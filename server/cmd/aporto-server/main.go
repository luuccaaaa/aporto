package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"

	"github.com/luuccaaaa/aporto/server/internal/api"
	"github.com/luuccaaaa/aporto/server/internal/authkeys"
	"github.com/luuccaaaa/aporto/server/internal/broker"
	apconfig "github.com/luuccaaaa/aporto/server/internal/config"
	"github.com/luuccaaaa/aporto/server/internal/proxy"
	"github.com/luuccaaaa/aporto/server/internal/store"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "aporto-server",
	Short: "Self-hosted reverse proxy control plane",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "server/config.yaml", "Path to server config file")
}

func main() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("aporto-server failed")
	}
}

func run(ctx context.Context) error {
	cfg, err := apconfig.Load(configPath)
	if err != nil {
		return err
	}

	keyStore, err := authkeys.Load(cfg.AuthorizedKeysPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.With().Str("component", "server").Logger()

	store, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	b := broker.New(logger)
	apiSrv := api.New(store, b, cfg.AdminToken, cfg.Domain, keyStore, logger)

	controlServer := &http.Server{
		Addr:         cfg.ControlAddr,
		Handler:      apiSrv.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	proxyHandler := proxy.New(cfg.Domain, b, logger)

	tlsEnabled := cfg.TLS.EnableAutocert || (cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "")
	redirectOrProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tlsEnabled {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		proxyHandler.ServeHTTP(w, r)
	})

	publicHTTP := &http.Server{
		Addr:         cfg.HTTPAddr,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	var httpsServer *http.Server
	if tlsEnabled {
		httpsServer = &http.Server{
			Addr:         cfg.HTTPSAddr,
			Handler:      securityHeaders(proxyHandler),
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
		}

		if cfg.TLS.EnableAutocert {
			manager := &autocert.Manager{
				Cache:      autocert.DirCache(cfg.TLS.CacheDir),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(cfg.Domain, "*."+cfg.Domain),
				Email:      cfg.TLS.Email,
			}
			httpsServer.TLSConfig = &tls.Config{
				GetCertificate: manager.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			}
			publicHTTP.Handler = manager.HTTPHandler(securityHeaders(redirectOrProxy))
		} else {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("load tls cert: %w", err)
			}
			httpsServer.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
			publicHTTP.Handler = securityHeaders(redirectOrProxy)
		}
	} else {
		publicHTTP.Handler = securityHeaders(redirectOrProxy)
	}

	errCh := make(chan error, 3)
	go func() {
		logger.Info().Str("addr", controlServer.Addr).Msg("control plane listening")
		if err := controlServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("control plane: %w", err)
		}
	}()

	go func() {
		logger.Info().Str("addr", publicHTTP.Addr).Msg("public HTTP listening")
		if err := publicHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http listener: %w", err)
		}
	}()

	if httpsServer != nil {
		go func() {
			logger.Info().Str("addr", httpsServer.Addr).Msg("public HTTPS listening")
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("https listener: %w", err)
			}
		}()
	}

	// Broker sweep loop keeps sessions healthy.
	go func() {
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info().Msg("shutting down...")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = controlServer.Shutdown(shutdownCtx)
	_ = publicHTTP.Shutdown(shutdownCtx)
	if httpsServer != nil {
		_ = httpsServer.Shutdown(shutdownCtx)
	}
	return nil
}

// securityHeaders adds basic hardening middleware.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}
