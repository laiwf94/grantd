// Command wicket runs the single sign-on gateway.
//
// Identity providers and apps are described in a JSON file (see
// docs/DESIGN.md and examples/wicket.json). Everything else comes from the
// environment:
//
//	WICKET_CONFIG           path of the JSON configuration file (required)
//	WICKET_COOKIE_KEYS      comma-separated 64-hex-character keys; the first seals cookies,
//	                        all open them, so a new key goes first during rotation (required)
//	WICKET_ADDR             public listen address for forward-auth, login and logout (default ":4180")
//	WICKET_ADMIN_ADDR       admin API and metrics listen address (default "127.0.0.1:4181");
//	                        must be a loopback address unless WICKET_ADMIN_TOKEN is set
//	WICKET_ADMIN_TOKEN      bearer token for the admin API, at least 16 characters
//	WICKET_SESSION_FILE     append-only session log; empty keeps sessions in memory only
//	WICKET_SIGNING_KEYS     comma-separated PEM files with P-256 keys for upstream tokens; the
//	                        first signs, all are published; empty generates a key per process
//	WICKET_TRUSTED_PROXIES  CIDRs whose X-Forwarded-For is believed (default loopback)
//	WICKET_LOGIN_RATE       login requests per minute per client address (default 30)
//	WICKET_LOG_LEVEL        debug, info, warn or error (default info)
//
// The configuration is reloaded on SIGHUP or POST /admin/reload.
//
// "wicket genkey" prints a new cookie key; "wicket gensigningkey" prints a
// new P-256 signing key in PEM.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/wicket/internal/config"
	"github.com/laiwf94/wicket/internal/jose"
	"github.com/laiwf94/wicket/internal/metrics"
	"github.com/laiwf94/wicket/internal/seal"
	"github.com/laiwf94/wicket/internal/server"
	"github.com/laiwf94/wicket/internal/session"
)

func main() {
	if len(os.Args) > 1 {
		if err := subcommand(os.Args[1], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "wicket:", err)
			os.Exit(2)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	if err := run(ctx, os.Getenv, os.Stdout, hup, nil); err != nil {
		fmt.Fprintln(os.Stderr, "wicket:", err)
		os.Exit(1)
	}
}

func subcommand(name string, out io.Writer) error {
	switch name {
	case "genkey":
		_, err := fmt.Fprintln(out, hex.EncodeToString(seal.RandomKey()))
		return err
	case "gensigningkey":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return fmt.Errorf("unknown command %q (commands: genkey, gensigningkey)", name)
}

type settings struct {
	configPath  string
	addr        string
	adminAddr   string
	adminToken  string
	cookieKeys  [][]byte
	sessionFile string
	signingKeys []string
	trusted     []netip.Prefix
	loginRate   int
	logLevel    slog.Level
}

func loadSettings(getenv func(string) string) (settings, error) {
	s := settings{addr: ":4180", adminAddr: "127.0.0.1:4181"}
	if s.configPath = getenv("WICKET_CONFIG"); s.configPath == "" {
		return s, errors.New("WICKET_CONFIG is required")
	}
	if v := getenv("WICKET_ADDR"); v != "" {
		s.addr = v
	}
	if v := getenv("WICKET_ADMIN_ADDR"); v != "" {
		s.adminAddr = v
	}
	s.adminToken = getenv("WICKET_ADMIN_TOKEN")
	if s.adminToken != "" && len(s.adminToken) < 16 {
		return s, errors.New("WICKET_ADMIN_TOKEN must be at least 16 characters")
	}
	if s.adminToken == "" && !isLoopback(s.adminAddr) {
		return s, fmt.Errorf("WICKET_ADMIN_ADDR %q is not a loopback address; set WICKET_ADMIN_TOKEN to expose the admin API", s.adminAddr)
	}
	for _, k := range strings.Split(getenv("WICKET_COOKIE_KEYS"), ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != seal.KeySize {
			return s, errors.New("WICKET_COOKIE_KEYS entries must be 64 hex characters (run: wicket genkey)")
		}
		s.cookieKeys = append(s.cookieKeys, b)
	}
	if len(s.cookieKeys) == 0 {
		return s, errors.New("WICKET_COOKIE_KEYS is required (run: wicket genkey)")
	}
	s.sessionFile = getenv("WICKET_SESSION_FILE")
	for _, f := range strings.Split(getenv("WICKET_SIGNING_KEYS"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			s.signingKeys = append(s.signingKeys, f)
		}
	}
	proxies := getenv("WICKET_TRUSTED_PROXIES")
	if proxies == "" {
		proxies = "127.0.0.0/8,::1/128"
	}
	for _, p := range strings.Split(proxies, ",") {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			return s, fmt.Errorf("WICKET_TRUSTED_PROXIES: %q is not a CIDR", p)
		}
		s.trusted = append(s.trusted, pfx)
	}
	if v := getenv("WICKET_LOGIN_RATE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100_000 {
			return s, errors.New("WICKET_LOGIN_RATE must be 1-100000")
		}
		s.loginRate = n
	}
	if v := getenv("WICKET_LOG_LEVEL"); v != "" {
		if err := s.logLevel.UnmarshalText([]byte(v)); err != nil {
			return s, fmt.Errorf("WICKET_LOG_LEVEL: %v", err)
		}
	}
	return s, nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func loadSigners(files []string) ([]*jose.Signer, error) {
	var out []*jose.Signer
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("signing key %s: no PEM block", f)
		}
		var key *ecdsa.PrivateKey
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			key, _ = k.(*ecdsa.PrivateKey)
		} else if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			key = k
		}
		if key == nil {
			return nil, fmt.Errorf("signing key %s: not an ECDSA private key", f)
		}
		sg, err := jose.NewSigner(key)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", f, err)
		}
		out = append(out, sg)
	}
	return out, nil
}

// run serves until ctx ends. ready, when set, receives the public and admin
// addresses once both listeners are bound.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, hup <-chan os.Signal, ready func(public, admin string)) error {
	st, err := loadSettings(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: st.logLevel}))
	signers, err := loadSigners(st.signingKeys)
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		log.Warn("WICKET_SIGNING_KEYS not set; using a key generated for this process, so upstream tokens can't be verified across replicas or restarts")
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sg, _ := jose.NewSigner(k)
		signers = []*jose.Signer{sg}
	}
	keys, err := seal.New(st.cookieKeys)
	if err != nil {
		return err
	}
	cfg, err := config.Load(st.configPath, getenv)
	if err != nil {
		return err
	}
	sessions, err := session.Open(session.Options{Path: st.sessionFile, IdleTimeout: time.Duration(cfg.Session.IdleTimeout),
		AbsoluteTimeout: time.Duration(cfg.Session.AbsoluteTimeout)})
	if err != nil {
		return err
	}
	defer sessions.Close()

	first := true
	srv, err := server.New(server.Options{
		Load: func() (*config.Config, error) {
			if first {
				first = false
				return cfg, nil
			}
			return config.Load(st.configPath, getenv)
		},
		Sessions: sessions, Keys: keys, Signers: signers, Logger: log, Metrics: metrics.New(),
		AdminToken: st.adminToken, TrustedProxies: st.trusted, LoginRate: st.loginRate,
	})
	if err != nil {
		return err
	}

	pub := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	adm := &http.Server{Handler: srv.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	pln, err := net.Listen("tcp", st.addr)
	if err != nil {
		return err
	}
	aln, err := net.Listen("tcp", st.adminAddr)
	if err != nil {
		pln.Close()
		return err
	}
	log.Info("listening", "addr", pln.Addr().String(), "admin_addr", aln.Addr().String(),
		"persistent_sessions", st.sessionFile != "", "sessions", sessions.Len())
	if ready != nil {
		ready(pln.Addr().String(), aln.Addr().String())
	}
	errc := make(chan error, 2)
	go func() { errc <- pub.Serve(pln) }()
	go func() { errc <- adm.Serve(aln) }()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	for {
		select {
		case err := <-errc:
			pub.Close()
			adm.Close()
			return err
		case <-hup:
			if err := srv.Reload(ctx); err != nil {
				log.Error("reload failed; keeping the running configuration", "error", err.Error())
			}
		case <-sweep.C:
			srv.Sweep()
		case <-ctx.Done():
			log.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err1 := pub.Shutdown(shutdownCtx)
			err2 := adm.Shutdown(shutdownCtx)
			return errors.Join(err1, err2)
		}
	}
}
