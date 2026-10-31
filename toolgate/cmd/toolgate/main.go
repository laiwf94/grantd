// Command toolgate runs the tool gateway, verifies audit logs and issues
// agent credentials.
//
//	toolgate                                  run the gateway (configured from the environment)
//	toolgate audit verify [-head HASH] FILE   check an audit log's hash chain
//	toolgate policy test [-v] POLICY CASES    check a policy against a file of expected decisions
//	toolgate token new                        print a new static agent key and its SHA-256 for the config
//	toolgate token hash < key                 print the SHA-256 of a static key read from stdin
//	toolgate token mint -sub ID [-owner NAME] [-scope "a b"] [-ttl 15m]
//	                                          print a signed token (needs TOOLGATE_CONFIG and TOOLGATE_SIGNING_KEYS)
//
// The gateway reads its configuration from the environment:
//
//	TOOLGATE_ADDR             agent listener (default "127.0.0.1:8080")
//	TOOLGATE_ADMIN_ADDR       admin listener (default "127.0.0.1:8081")
//	TOOLGATE_ADMIN_TOKEN      bearer token for the admin API, at least 32 characters (required)
//	TOOLGATE_CONFIG           path of the JSON config: agents, upstreams, limits (required)
//	TOOLGATE_POLICY           path of the JSON policy, reloaded when it changes (required)
//	TOOLGATE_AUDIT_LOG        path of the append-only audit log (required)
//	TOOLGATE_AUDIT_KEY        64 hex characters; keys the argument digests in the audit log (required)
//	TOOLGATE_STATE_DIR        directory for trusted tool definitions; empty keeps them in memory only
//	TOOLGATE_SIGNING_KEYS     kid=<64 hex>[,kid=<64 hex>...] for signed agent tokens; the first signs new tokens
//	TOOLGATE_ALLOWED_ORIGINS  comma-separated browser origins allowed to call /mcp (default none)
//	TOOLGATE_POLICY_POLL      how often to check the policy file (default "2s"; "0" disables; SIGHUP always reloads)
//	TOOLGATE_LOG_LEVEL        debug, info, warn or error (default info)
//
// Upstream credentials are read from the environment variables the config
// names in credential_env.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/grantd/internal/agents/audit"
	"github.com/laiwf94/grantd/internal/agents/gateway"
	"github.com/laiwf94/grantd/internal/agents/identity"
	"github.com/laiwf94/grantd/internal/agents/metrics"
	"github.com/laiwf94/grantd/internal/agents/pins"
	"github.com/laiwf94/grantd/internal/agents/policy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := cli(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// cli dispatches subcommands and returns the process exit code.
func cli(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, ready func(gw, admin string)) int {
	var err error
	switch {
	case len(args) == 0 || args[0] == "serve":
		err = run(ctx, getenv, stdout, ready)
	case args[0] == "audit" && len(args) > 1 && args[1] == "verify":
		return auditVerify(args[2:], stdout, stderr)
	case args[0] == "policy" && len(args) > 1 && args[1] == "test":
		return policyTest(args[2:], stdout, stderr)
	case args[0] == "token" && len(args) > 1:
		err = token(args[1], args[2:], getenv, stdin, stdout)
	default:
		err = errors.New("usage: toolgate [serve] | audit verify [-head HASH] FILE | policy test [-v] POLICY CASES | token new|hash|mint")
	}
	if err != nil {
		fmt.Fprintln(stderr, "toolgate:", err)
		return 1
	}
	return 0
}

type config struct {
	addr, adminAddr string
	adminToken      string
	configPath      string
	policyPath      string
	auditPath       string
	auditKey        []byte
	stateDir        string
	keys            map[string][]byte
	activeKey       string
	origins         []string
	poll            time.Duration
	logLevel        slog.Level
}

func required(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

func parseKeys(v string) (map[string][]byte, string, error) {
	keys := map[string][]byte{}
	active := ""
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, hexKey, ok := strings.Cut(part, "=")
		k, err := hex.DecodeString(hexKey)
		if !ok || err != nil || len(k) != 32 {
			return nil, "", errors.New("TOOLGATE_SIGNING_KEYS must be kid=<64 hex characters>, comma-separated")
		}
		if _, dup := keys[kid]; dup {
			return nil, "", fmt.Errorf("TOOLGATE_SIGNING_KEYS repeats key id %q", kid)
		}
		keys[kid] = k
		if active == "" {
			active = kid
		}
	}
	return keys, active, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{addr: "127.0.0.1:8080", adminAddr: "127.0.0.1:8081", poll: 2 * time.Second}
	if v := getenv("TOOLGATE_ADDR"); v != "" {
		c.addr = v
	}
	if v := getenv("TOOLGATE_ADMIN_ADDR"); v != "" {
		c.adminAddr = v
	}
	var err error
	if c.adminToken, err = required(getenv, "TOOLGATE_ADMIN_TOKEN"); err != nil {
		return c, err
	}
	if len(c.adminToken) < 32 {
		return c, errors.New("TOOLGATE_ADMIN_TOKEN must be at least 32 characters")
	}
	if c.configPath, err = required(getenv, "TOOLGATE_CONFIG"); err != nil {
		return c, err
	}
	if c.policyPath, err = required(getenv, "TOOLGATE_POLICY"); err != nil {
		return c, err
	}
	if c.auditPath, err = required(getenv, "TOOLGATE_AUDIT_LOG"); err != nil {
		return c, err
	}
	ak, err := required(getenv, "TOOLGATE_AUDIT_KEY")
	if err != nil {
		return c, err
	}
	if c.auditKey, err = hex.DecodeString(ak); err != nil || len(c.auditKey) != 32 {
		return c, errors.New("TOOLGATE_AUDIT_KEY must be 64 hex characters")
	}
	c.stateDir = getenv("TOOLGATE_STATE_DIR")
	if c.keys, c.activeKey, err = parseKeys(getenv("TOOLGATE_SIGNING_KEYS")); err != nil {
		return c, err
	}
	for _, o := range strings.Split(getenv("TOOLGATE_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.origins = append(c.origins, o)
		}
	}
	if v := getenv("TOOLGATE_POLICY_POLL"); v != "" {
		d, err := time.ParseDuration(v)
		if v == "0" {
			d, err = 0, nil
		}
		if err != nil || d < 0 {
			return c, errors.New("TOOLGATE_POLICY_POLL must be a duration such as 2s, or 0")
		}
		c.poll = d
	}
	if v := getenv("TOOLGATE_LOG_LEVEL"); v != "" {
		if err := c.logLevel.UnmarshalText([]byte(v)); err != nil {
			return c, fmt.Errorf("TOOLGATE_LOG_LEVEL: %v", err)
		}
	}
	return c, nil
}

func readGatewayConfig(path string, getenv func(string) string) (*gateway.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, gateway.MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return gateway.ParseConfig(src, getenv)
}

// run serves until ctx ends. ready, when set, receives the bound addresses.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(gw, admin string)) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.logLevel}))
	gc, err := readGatewayConfig(cfg.configPath, getenv)
	if err != nil {
		return err
	}
	auth, err := gc.NewAuthenticator(cfg.keys, cfg.activeKey)
	if err != nil {
		return err
	}
	pol, err := policy.OpenStore(cfg.policyPath, nil)
	if err != nil {
		return err
	}
	auditLog, err := audit.Open(cfg.auditPath, nil)
	if err != nil {
		return err
	}
	defer auditLog.Close()
	pinPath := ""
	if cfg.stateDir != "" {
		pinPath = filepath.Join(cfg.stateDir, "pins.json")
	} else {
		log.Warn("TOOLGATE_STATE_DIR not set; trusted tool definitions are kept in memory and reset on restart")
	}
	pinStore, err := pins.Open(pinPath, nil)
	if err != nil {
		return err
	}
	gw, err := gateway.New(gateway.Options{Config: gc, Auth: auth, Policy: pol, Audit: auditLog, Pins: pinStore,
		AuditKey: cfg.auditKey, AllowedOrigins: cfg.origins, Log: log, Metrics: metrics.New()})
	if err != nil {
		return err
	}

	servers := []*http.Server{newServer(gw.Handler()), newServer(gw.AdminHandler(cfg.adminToken))}
	listeners := make([]net.Listener, 0, 2)
	for _, addr := range []string{cfg.addr, cfg.adminAddr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	n, head := auditLog.Head()
	log.Info("listening", "addr", listeners[0].Addr().String(), "admin_addr", listeners[1].Addr().String(),
		"policy", pol.Current().Hash, "audit_records", n, "audit_head", head, "upstreams", len(gc.Upstreams))
	if ready != nil {
		ready(listeners[0].Addr().String(), listeners[1].Addr().String())
	}

	bg, cancelBG := context.WithCancel(ctx)
	defer cancelBG()
	if cfg.poll > 0 {
		go pol.Watch(bg, cfg.poll)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-bg.Done():
				return
			case <-hup:
				pol.Reload()
			}
		}
	}()
	go func() {
		// Notice tool definition changes even when no agent is asking.
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		gw.Refresh(bg)
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				gw.Refresh(bg)
			}
		}
	}()

	errc := make(chan error, len(servers))
	for i, s := range servers {
		go func() { errc <- s.Serve(listeners[i]) }()
	}
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		if serr := s.Shutdown(shutdownCtx); serr != nil && err == nil {
			err = serr
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Longer than the worst case for one call: a tool-list refresh (120 s)
		// plus an approval wait (60 s), a slot wait (1 s) and the call itself
		// (120 s), at the configuration maximums.
		WriteTimeout:   6 * time.Minute,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
}

func auditVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	head := fs.String("head", "", "expected hash of the last record (from GET /admin/audit/head)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: toolgate audit verify [-head HASH] FILE")
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "toolgate:", err)
		return 2
	}
	defer f.Close()
	res, err := audit.Verify(f)
	if err != nil {
		fmt.Fprintf(stdout, "FAIL %s: %v\n", fs.Arg(0), err)
		return 1
	}
	if *head != "" && *head != res.Head {
		fmt.Fprintf(stdout, "FAIL %s: chain is intact but ends at %s, not the expected head %s (records were removed from the end or the last one was changed)\n",
			fs.Arg(0), res.Head, *head)
		return 1
	}
	fmt.Fprintf(stdout, "OK %s: %d records, head %s\n", fs.Arg(0), res.Records, res.Head)
	return 0
}

// policyTest runs a case file against a policy. It exits 0 when every case
// passes, 1 when any fails and 2 when either file cannot be read or parsed.
func policyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("v", false, "also list the cases that pass")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: toolgate policy test [-v] POLICY CASES")
		return 2
	}
	src, err := readLimited(fs.Arg(0), policy.MaxBytes)
	if err != nil {
		fmt.Fprintln(stderr, "toolgate:", err)
		return 2
	}
	p, err := policy.Parse(src)
	if err != nil {
		fmt.Fprintf(stderr, "toolgate: %s: %v\n", fs.Arg(0), err)
		return 2
	}
	if src, err = readLimited(fs.Arg(1), policy.MaxCaseBytes); err != nil {
		fmt.Fprintln(stderr, "toolgate:", err)
		return 2
	}
	cs, err := policy.ParseCases(src)
	if err != nil {
		fmt.Fprintf(stderr, "toolgate: %s: %v\n", fs.Arg(1), err)
		return 2
	}
	rep := policy.RunCases(p, cs)
	rep.WriteText(stdout, *verbose)
	if rep.Failed > 0 {
		return 1
	}
	return 0
}

// readLimited reads a file, refusing one larger than limit bytes.
func readLimited(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(src) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return src, nil
}

func token(sub string, args []string, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	switch sub {
	case "new":
		t := identity.NewStaticToken()
		h := identity.HashToken(t)
		fmt.Fprintf(stdout, "key:          %s\ntoken_sha256: %s\n", t, hex.EncodeToString(h[:]))
		return nil
	case "hash":
		line, err := bufio.NewReader(io.LimitReader(stdin, identity.MaxTokenBytes+2)).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		t := strings.TrimSpace(line)
		if len(t) < identity.MinStaticBytes {
			return fmt.Errorf("a static key must be at least %d characters", identity.MinStaticBytes)
		}
		h := identity.HashToken(t)
		fmt.Fprintln(stdout, hex.EncodeToString(h[:]))
		return nil
	case "mint":
		fs := flag.NewFlagSet("token mint", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		subject := fs.String("sub", "", "agent id")
		owner := fs.String("owner", "", "owner of the agent")
		scope := fs.String("scope", "", "space-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		path, err := required(getenv, "TOOLGATE_CONFIG")
		if err != nil {
			return err
		}
		keys, active, err := parseKeys(getenv("TOOLGATE_SIGNING_KEYS"))
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return errors.New("TOOLGATE_SIGNING_KEYS is required to mint tokens")
		}
		gc, err := readGatewayConfig(path, nil) // upstream credentials are not needed to mint
		if err != nil {
			return err
		}
		auth, err := gc.NewAuthenticator(keys, active)
		if err != nil {
			return err
		}
		tok, err := auth.Mint(*subject, *owner, strings.Fields(*scope), *ttl)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tok)
		return nil
	default:
		return errors.New("usage: toolgate token new | hash | mint -sub ID [-owner NAME] [-scope \"a b\"] [-ttl 15m]")
	}
}
