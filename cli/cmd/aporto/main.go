package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/luuccaaaa/aporto/cli/internal/config"
	"github.com/luuccaaaa/aporto/cli/internal/keys"
	"github.com/luuccaaaa/aporto/cli/internal/tunnel"
	"github.com/luuccaaaa/aporto/cli/internal/ui"
)

var (
	configPath     string
	localAddrFlag  string
	tunnelNameFlag string
)

const (
	defaultLocalService = "http://127.0.0.1:3000"
	headerPublicKey     = "X-Aporto-Public-Key"
	headerSignature     = "X-Aporto-Signature"
	devLoginPath        = "/v1/dev/login"
	devPingPath         = "/v1/dev/ping"
	devLoginTimeout     = 15 * time.Second
)

func main() {
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().Local()
	}
	zerolog.TimeFieldFormat = "15:04:05"
	console := zerolog.ConsoleWriter{
		Out:          os.Stderr,
		TimeFormat:   "15:04:05",
		TimeLocation: time.Local,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			zerolog.MessageFieldName,
		},
	}
	log.Logger = log.Output(console)

	root := &cobra.Command{
		Use:   "aporto [local-port|local-url]",
		Short: "Developer CLI for aporto tunnels",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var override string
			if len(args) == 1 {
				var err error
				override, err = normalizeLocalArg(args[0])
				if err != nil {
					return err
				}
			}
			return runTunnelWithOverride(cmd, override)
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true

	defaultPath, err := config.DefaultPath()
	if err != nil {
		log.Fatal().Err(err).Msg("resolve default config path")
	}
	root.PersistentFlags().StringVar(&configPath, "config", defaultPath, "path to CLI config file")
	registerTunnelFlags(root)

	root.AddCommand(newInitCmd(), newLoginCmd(), newTunnelStartCmd(), newStatusCmd())

	if err := root.Execute(); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Fatal().Err(err).Msg("command failed")
		}
	}
}

func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a developer keypair for this machine",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			pair, err := keys.Generate()
			if err != nil {
				return err
			}
			if err := keys.Save(cfg.KeyPath, pair, force); err != nil {
				return err
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			pub := pair.PublicBase64()
			fmt.Fprintf(cmd.OutOrStdout(), "Generated keypair.\nPrivate key: %s\nPublic key: %s\n", cfg.KeyPath, pub)
			fmt.Fprintf(cmd.OutOrStdout(), "Add the public key to the server's authorized_keys file, then run 'aporto login'.\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite the existing key at the configured path")
	return cmd
}

func newLoginCmd() *cobra.Command {
	var (
		apiURL   string
		insecure bool
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store the control-plane URL and verify your developer key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			pair, err := keys.Load(cfg.KeyPath)
			if err != nil {
				return fmt.Errorf("load developer key (%s): %w (run 'aporto init')", cfg.KeyPath, err)
			}

			reader := bufio.NewReader(cmd.InOrStdin())
			if apiURL == "" {
				apiURL, err = promptString(cmd, reader, "Control plane URL", cfg.APIURL, true)
				if err != nil {
					return err
				}
			}

			if !cmd.Flags().Changed("insecure") {
				insecure = cfg.InsecureTLS
			}

			baseURL, err := normalizeAPIURL(apiURL)
			if err != nil {
				return err
			}

			if _, err := developerPing(cmd.Context(), baseURL, pair, insecure); err != nil {
				return err
			}

			cfg.APIURL = baseURL
			cfg.InsecureTLS = insecure
			if cfg.LocalAddr == "" {
				cfg.LocalAddr = defaultLocalService
			}

			if err := cfg.Save(); err != nil {
				return err
			}
			cmd.Printf("Verified developer key with %s\n", baseURL)
			cmd.Printf("Saved config to %s\n", cfg.Path())
			return nil
		},
	}

	cmd.Flags().StringVar(&apiURL, "api-url", "", "Control plane URL (e.g. https://control.example.com)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS verification when contacting the server (dev only)")

	return cmd
}

func newTunnelStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel start",
		Short: "Open the aporto tunnel and proxy HTTP requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			override := ""
			if localAddrFlag != "" {
				var err error
				override, err = normalizeLocalArg(localAddrFlag)
				if err != nil {
					return err
				}
			}
			return runTunnelWithOverride(cmd, override)
		},
	}

	cmd.Flags().StringVar(&localAddrFlag, "local-addr", "", "Override local address for this session")
	registerTunnelFlags(cmd)
	return cmd
}

func runTunnelWithOverride(cmd *cobra.Command, override string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if override != "" {
		cfg.LocalAddr = override
	}
	if cfg.LocalAddr == "" {
		cfg.LocalAddr = defaultLocalService
	}
	if err := ensureTunnel(cmd.Context(), cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	uiView, err := ui.New(cfg.Hostname, cfg.LocalAddr, cfg.DarkMode)
	if err != nil {
		return err
	}
	defer uiView.Close()
	logger := buildLogger(cfg.LogLevel, uiView.LogWriter()).Hook(statusHook{ui: uiView})
	runner, err := tunnel.NewRunner(cfg, logger, uiView.LogRequest)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	uiView.SetStatus("CONNECTING")
	uiView.UpdatePublic(cfg.Hostname)
	uiView.UpdateLocal(cfg.LocalAddr)
	logger.Info().Str("tunnel_id", cfg.TunnelID).Msg("starting aporto tunnel")
	err = runner.Run(ctx)
	if err != nil && err != context.Canceled {
		uiView.SetStatus("ERROR")
	} else {
		uiView.SetStatus("STOPPED")
	}
	return err
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the currently configured tunnel settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Config: %s\n", cfg.Path())
			fmt.Fprintf(cmd.OutOrStdout(), "API URL: %s\nTunnel ID: %s\nSubdomain: %s\nLocal Addr: %s\n", cfg.APIURL, cfg.TunnelID, cfg.Subdomain, cfg.LocalAddr)
			return nil
		},
	}
}

func buildLogger(level string, out io.Writer) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	if out == nil {
		out = os.Stderr
	}
	writer := zerolog.ConsoleWriter{
		Out:          out,
		TimeFormat:   "15:04:05",
		TimeLocation: time.Local,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			zerolog.MessageFieldName,
		},
	}
	return zerolog.New(writer).Level(lvl).With().Timestamp().Logger()
}

type devLoginResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Subdomain   string `json:"subdomain"`
	Hostname    string `json:"hostname"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

func developerLogin(ctx context.Context, baseURL string, payload []byte, pair *keys.Pair, insecure bool) (*devLoginResponse, error) {
	endpoint, err := joinAPIPath(baseURL, devLoginPath)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   devLoginTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerPublicKey, pair.PublicBase64())
	req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(pair.Sign(payload)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("server rejected login: %s (is your public key added to the authorized_keys file?)", msg)
		}
		return nil, fmt.Errorf("server rejected login: %s", msg)
	}

	var out devLoginResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

type devPingTunnel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Subdomain string `json:"subdomain"`
	Hostname  string `json:"hostname"`
	Active    bool   `json:"active"`
}

type devPingResponse struct {
	Fingerprint string         `json:"fingerprint"`
	Tunnel      *devPingTunnel `json:"tunnel"`
}

func developerPing(ctx context.Context, baseURL string, pair *keys.Pair, insecure bool) (*devPingResponse, error) {
	endpoint, err := joinAPIPath(baseURL, devPingPath)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   devLoginTimeout,
	}
	body := []byte(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerPublicKey, pair.PublicBase64())
	req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(pair.Sign(body)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("server rejected key: %s (add your public key to authorized_keys)", msg)
		}
		return nil, fmt.Errorf("server rejected key: %s", msg)
	}
	var out devPingResponse
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

func promptString(cmd *cobra.Command, reader *bufio.Reader, label, current string, required bool) (string, error) {
	for {
		var prompt string
		if current != "" {
			prompt = fmt.Sprintf("%s [%s]: ", label, current)
		} else {
			prompt = fmt.Sprintf("%s: ", label)
		}
		fmt.Fprint(cmd.OutOrStdout(), prompt)
		value, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value, nil
		}
		if current != "" {
			return current, nil
		}
		if !required {
			return "", nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Value is required.")
	}
}

func normalizeAPIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("api url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid api url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("api url must include scheme and host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	result := parsed.String()
	if strings.HasSuffix(result, "/") {
		result = strings.TrimRight(result, "/")
	}
	return result, nil
}

func joinAPIPath(baseURL, suffix string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, suffix)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func normalizeLocalArg(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", fmt.Errorf("local address cannot be empty")
	}
	if strings.Contains(arg, "://") {
		return arg, nil
	}
	if _, err := strconv.Atoi(arg); err == nil {
		return fmt.Sprintf("http://127.0.0.1:%s", arg), nil
	}
	if strings.HasPrefix(arg, "localhost:") || strings.Contains(arg, ":") {
		return "http://" + arg, nil
	}
	return "http://" + arg, nil
}

func registerTunnelFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&tunnelNameFlag, "name", "", "Preferred tunnel name/subdomain (optional)")
}

type statusHook struct {
	ui *ui.UI
}

func (h statusHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "tunnel connected"):
		h.ui.SetStatus("CONNECTED")
	case strings.Contains(lower, "disconnected"):
		h.ui.SetStatus("RECONNECTING")
	}
}

func ensureTunnel(ctx context.Context, cfg *config.Config) error {
	if cfg.APIURL == "" {
		return fmt.Errorf("run 'aporto login' first to set the control plane URL")
	}
	pair, err := keys.Load(cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("load developer key (%s): %w (run 'aporto init')", cfg.KeyPath, err)
	}
	ping, err := developerPing(ctx, cfg.APIURL, pair, cfg.InsecureTLS)
	if err != nil {
		return err
	}
	updated := false
	if ping != nil && ping.Tunnel != nil {
		if cfg.TunnelID != ping.Tunnel.ID || cfg.Subdomain != ping.Tunnel.Subdomain || cfg.Hostname != ping.Tunnel.Hostname {
			cfg.TunnelID = ping.Tunnel.ID
			cfg.Subdomain = ping.Tunnel.Subdomain
			cfg.Hostname = ping.Tunnel.Hostname
			updated = true
		}
	} else if cfg.TunnelID != "" || cfg.Subdomain != "" || cfg.Hostname != "" {
		cfg.TunnelID = ""
		cfg.Subdomain = ""
		cfg.Hostname = ""
		updated = true
	}
	if updated {
		_ = cfg.Save()
	}

	requestedName := strings.TrimSpace(tunnelNameFlag)
	randomized := false
	if requestedName == "" {
		requestedName = randomSlug(10)
		randomized = true
	}

	needsProvision := randomized ||
		cfg.TunnelID == "" ||
		cfg.TunnelSecret == "" ||
		!strings.EqualFold(cfg.Subdomain, requestedName)
	if !needsProvision {
		return nil
	}
	payload, err := json.Marshal(map[string]string{
		"name":      requestedName,
		"subdomain": requestedName,
	})
	if err != nil {
		return err
	}
	resp, err := developerLogin(ctx, cfg.APIURL, payload, pair, cfg.InsecureTLS)
	if err != nil {
		return err
	}
	cfg.TunnelID = resp.ID
	cfg.TunnelSecret = resp.Secret
	cfg.Subdomain = resp.Subdomain
	cfg.Hostname = resp.Hostname
	if err := cfg.Save(); err != nil {
		return err
	}
	return nil
}

func randomSlug(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "xxxxxx"
	}
	for i := 0; i < n; i++ {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}
