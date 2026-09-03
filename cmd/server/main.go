package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/endr-i/ecosystem-accounts/internal/account"
	"github.com/endr-i/ecosystem-accounts/internal/authn"
	"github.com/endr-i/ecosystem-accounts/internal/config"
	"github.com/endr-i/ecosystem-accounts/internal/db"
	"github.com/endr-i/ecosystem-accounts/internal/httpapi"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}

	accounts := account.NewService(account.NewRepository(pool))

	keyCache := authn.NewKeyCache(cfg.Auth.JWKSURL,
		authn.WithHTTPClient(&http.Client{Timeout: cfg.Auth.JWKSTimeout}),
		authn.WithLogger(log))
	if err := keyCache.RefreshWithRetry(ctx, cfg.Auth.StartupTimeout); err != nil {
		log.Error("load auth signing keys", "err", err)
		os.Exit(1)
	}
	keyCache.StartBackgroundRefresh(ctx, cfg.Auth.JWKSRefreshInterval)

	verifier := authn.NewVerifier(keyCache, cfg.Auth.Issuer)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpapi.NewServer(accounts, verifier, log).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info("http listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
