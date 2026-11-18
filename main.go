// external-dns-fortigate-webhook は、ExternalDNS のレコードを FortiGate の DNS データベース
// (config system dns-database) に書く webhook provider。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/provider"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/webhook"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func envBool(name string) (bool, error) {
	v := env(name, "false")
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %q は真偽値ではない", name, v)
	}
	return b, nil
}

func envList(name string) []string {
	var out []string
	for _, s := range strings.Split(env(name, ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func run() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		return fmt.Errorf("LOG_LEVEL: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	token := env("FORTIGATE_TOKEN", "")
	if f := env("FORTIGATE_TOKEN_FILE", ""); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("FORTIGATE_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	tokenInQuery, err := envBool("FORTIGATE_TOKEN_IN_QUERY")
	if err != nil {
		return err
	}
	insecure, err := envBool("FORTIGATE_INSECURE_SKIP_VERIFY")
	if err != nil {
		return err
	}
	dryRun, err := envBool("DRY_RUN")
	if err != nil {
		return err
	}
	resync, err := time.ParseDuration(env("REVERSE_RESYNC_INTERVAL", "5m"))
	if err != nil {
		return fmt.Errorf("REVERSE_RESYNC_INTERVAL: %w", err)
	}
	zone := env("FORTIGATE_ZONE", "")
	if zone == "" {
		return errors.New("FORTIGATE_ZONE がない")
	}

	client, err := fortigate.New(fortigate.Config{
		BaseURL:            env("FORTIGATE_URL", ""),
		Token:              token,
		VDOM:               env("FORTIGATE_VDOM", "root"),
		TokenInQuery:       tokenInQuery,
		CAFile:             env("FORTIGATE_CA_FILE", ""),
		InsecureSkipVerify: insecure,
	})
	if err != nil {
		return err
	}
	if insecure {
		log.Warn("FortiGate の証明書を検証しない (FORTIGATE_INSECURE_SKIP_VERIFY)")
	}

	p := provider.New(client, provider.Config{
		ForwardZone:  zone,
		ReverseZones: envList("FORTIGATE_REVERSE_ZONES"),
		DryRun:       dryRun,
	}, log)
	srv := webhook.New(p, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := &http.Server{Addr: env("WEBHOOK_ADDR", "127.0.0.1:8888"), Handler: srv.APIHandler(), ReadHeaderTimeout: 5 * time.Second}
	health := &http.Server{Addr: env("HEALTH_ADDR", ":8080"), Handler: srv.HealthHandler(), ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 2)
	for _, s := range []*http.Server{api, health} {
		go func() {
			log.Info("待ち受ける", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	// FortiGate に届くまで待つ。届くまでは /readyz と Negotiate が 503 を返す。
	for backoff := time.Second; ; backoff = min(backoff*2, 30*time.Second) {
		if err := p.Init(ctx); err == nil {
			break
		} else {
			log.Error("FortiGate のゾーンを読めない。やり直す", "err", err, "after", backoff.String())
		}
		select {
		case <-ctx.Done():
			return shutdown(api, health)
		case err := <-errc:
			return err
		case <-time.After(backoff):
		}
	}
	srv.SetReady(true)

	tick := time.NewTicker(resync)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return shutdown(api, health)
		case err := <-errc:
			return err
		case <-tick.C:
			if err := p.SyncReverse(ctx); err != nil {
				log.Error("逆引きのゾーンを直せない", "err", err)
			}
		}
	}
}

func shutdown(servers ...*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	return nil
}
