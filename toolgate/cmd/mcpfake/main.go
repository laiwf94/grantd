// Command mcpfake runs a small MCP server over Streamable HTTP, as an
// upstream for trying toolgate. See internal/fakeserver for its tools.
//
// Configuration comes from the environment:
//
//	MCPFAKE_ADDR         listen address (default "127.0.0.1:9000")
//	MCPFAKE_SANDBOX      directory read_file may read (required)
//	MCPFAKE_HTTP_ALLOW   comma-separated hosts http_get may fetch (default none)
//	MCPFAKE_TOKEN        bearer token required on /mcp (default none)
//	MCPFAKE_ADMIN_TOKEN  bearer token for POST /admin/rugpull and /admin/restore (default: routes off)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/grantd/internal/agents/fakeserver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv, os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "mcpfake:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	addr := getenv("MCPFAKE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}
	sandbox := getenv("MCPFAKE_SANDBOX")
	if sandbox == "" {
		return errors.New("MCPFAKE_SANDBOX is required")
	}
	var allow []string
	for _, h := range strings.Split(getenv("MCPFAKE_HTTP_ALLOW"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			allow = append(allow, h)
		}
	}
	log := slog.New(slog.NewJSONHandler(logOut, nil))
	srv, err := fakeserver.New(fakeserver.Config{Sandbox: sandbox, HTTPAllow: allow,
		Token: getenv("MCPFAKE_TOKEN"), AdminToken: getenv("MCPFAKE_ADMIN_TOKEN"), Log: log})
	if err != nil {
		return err
	}
	defer srv.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Info("listening", "addr", ln.Addr().String(), "sandbox", sandbox)
	if ready != nil {
		ready(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}
