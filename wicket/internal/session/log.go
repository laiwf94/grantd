package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Log record operations.
const (
	opCreate = "create"
	opTouch  = "touch"
	opRevoke = "revoke"
)

// maxRecordBytes bounds one log line, so a damaged file can't make replay
// allocate without limit.
const maxRecordBytes = 64 << 10

type record struct {
	Op      string    `json:"op"`
	Session *Session  `json:"session,omitempty"`
	ID      string    `json:"id,omitempty"`
	Time    time.Time `json:"t,omitzero"`
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// logFile is the append-only session log. Each line is
//
//	<crc32c of the JSON, 8 hex digits> <JSON record>\n
//
// the same framing grantd-style write-ahead logs use: a torn last line is a
// write that was never acknowledged and is dropped; a bad line anywhere else
// is damage, and loading stops rather than guessing.
type logFile struct {
	path    string
	f       *os.File
	records int
	broken  error
}

func openLog(path string) (*logFile, []*Session, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("session log: %w", err)
	}
	sessions, good, err := replay(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("session log %s: %w", path, err)
	}
	if err := f.Truncate(good); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("session log: %w", err)
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &logFile{path: path, f: f}, sessions, nil
}

// replay applies every record and returns the sessions, plus the offset of
// the end of the last good record.
func replay(r io.Reader) ([]*Session, int64, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	byID := map[string]*Session{}
	var order []string
	var offset int64
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, 0, fmt.Errorf("record at offset %d longer than %d bytes", offset, maxRecordBytes)
		}
		if errors.Is(err, io.EOF) {
			// No newline: a torn final write. Drop it.
			break
		}
		if err != nil {
			return nil, 0, err
		}
		rec, perr := parseLine(line)
		if perr != nil {
			// A bad final line is a torn write; anything after it means
			// the damage is in the middle of the file.
			if _, peekErr := br.Peek(1); errors.Is(peekErr, io.EOF) {
				break
			}
			return nil, 0, fmt.Errorf("damaged record at offset %d: %v", offset, perr)
		}
		switch rec.Op {
		case opCreate:
			if _, dup := byID[rec.Session.ID]; !dup {
				order = append(order, rec.Session.ID)
			}
			rec.Session.persistedSeen = rec.Session.LastSeen
			byID[rec.Session.ID] = rec.Session
		case opTouch:
			if s := byID[rec.ID]; s != nil && rec.Time.After(s.LastSeen) {
				s.LastSeen, s.persistedSeen = rec.Time, rec.Time
			}
		case opRevoke:
			delete(byID, rec.ID)
		}
		offset += int64(len(line))
	}
	out := make([]*Session, 0, len(byID))
	for _, id := range order {
		if s, ok := byID[id]; ok {
			out = append(out, s)
			delete(byID, id) // a re-created id appears once
		}
	}
	return out, offset, nil
}

func parseLine(line []byte) (record, error) {
	var rec record
	line = bytes.TrimSuffix(line, []byte("\n"))
	if len(line) < 10 || line[8] != ' ' {
		return rec, errors.New("bad framing")
	}
	want, err := strconv.ParseUint(string(line[:8]), 16, 32)
	if err != nil {
		return rec, errors.New("bad checksum field")
	}
	body := line[9:]
	if crc32.Checksum(body, castagnoli) != uint32(want) {
		return rec, errors.New("checksum mismatch")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, err
	}
	switch rec.Op {
	case opCreate:
		if rec.Session == nil || len(rec.Session.ID) != 32 {
			return rec, errors.New("create without a session")
		}
	case opTouch, opRevoke:
		if len(rec.ID) != 32 {
			return rec, errors.New("record without an id")
		}
	default:
		return rec, fmt.Errorf("unknown op %q", rec.Op)
	}
	return rec, nil
}

func encode(recs []record) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range recs {
		body, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "%08x %s\n", crc32.Checksum(body, castagnoli), body)
	}
	return buf.Bytes(), nil
}

// append writes records as one write; with sync it fsyncs before returning.
// A failed write is truncated away. If that fails too the log refuses all
// further writes rather than appending after garbage.
func (l *logFile) append(sync bool, recs []record) error {
	if l.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, l.broken)
	}
	b, err := encode(recs)
	if err != nil {
		return err
	}
	off, err := l.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err = l.f.Write(b); err == nil && sync {
		err = l.f.Sync()
	}
	if err != nil {
		if terr := l.f.Truncate(off); terr != nil {
			l.broken = terr
		} else if _, serr := l.f.Seek(off, io.SeekStart); serr != nil {
			l.broken = serr
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	l.records += len(recs)
	return nil
}

// compact replaces the log with one create record per live session: write a
// temporary file, fsync it, rename it over the log, fsync the directory.
func (l *logFile) compact(live []*Session) error {
	if l.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, l.broken)
	}
	recs := make([]record, len(live))
	for i, s := range live {
		recs[i] = record{Op: opCreate, Session: s}
	}
	b, err := encode(recs)
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = os.Rename(tmp, l.path)
	}
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if d, derr := os.Open(filepath.Dir(l.path)); derr == nil {
		_ = d.Sync()
		d.Close()
	}
	l.f.Close()
	l.f = f
	l.records = len(recs)
	return nil
}

func (l *logFile) close() error { return l.f.Close() }
