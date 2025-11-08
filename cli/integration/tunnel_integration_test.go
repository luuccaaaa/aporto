package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/luuccaaaa/aporto/cli/internal/config"
	"github.com/luuccaaaa/aporto/cli/internal/tunnel"
)

func TestTunnelEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	controlPort := freePort(t)
	publicPort := freePort(t)

	domain := "apps.test.aporto"
	adminToken := "integration-admin-token"

	cfgPath := filepath.Join(tempDir, "server.yaml")
	dataDir := filepath.Join(tempDir, "data")
	cacheDir := filepath.Join(dataDir, "autocert-cache")
	writeServerConfig(t, cfgPath, domain, controlPort, publicPort, adminToken, dataDir, cacheDir)

	repoRoot := repoRootDir(t)
	serverCmd := exec.CommandContext(ctx, "go", "run", "github.com/luuccaaaa/aporto/server/cmd/aporto-server", "--config", cfgPath)
	serverCmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	serverCmd.Stdout = &stdout
	serverCmd.Stderr = &stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serverCmd.Wait()
	}()
	defer func() {
		cancel()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			_ = serverCmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("server stdout:\n%s", stdout.String())
			t.Logf("server stderr:\n%s", stderr.String())
		}
	}()

	controlURL := fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	if err := waitForControl(ctx, controlURL, adminToken); err != nil {
		t.Fatalf("control plane not ready: %v", err)
	}

	tunnelInfo := createTunnel(t, ctx, controlURL, adminToken, "integration")

	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from local %s", r.URL.Path)
	}))
	defer localSrv.Close()

	cfg := &config.Config{
		APIURL:       controlURL,
		TunnelID:     tunnelInfo.ID,
		TunnelSecret: tunnelInfo.Secret,
		LocalAddr:    localSrv.URL,
		LogLevel:     "error",
	}

	logger := zerolog.New(io.Discard)
	runner, err := tunnel.NewRunner(cfg, logger, nil)
	if err != nil {
		t.Fatalf("create runner: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runnerErr := make(chan error, 1)
	go func() {
		runnerErr <- runner.Run(runCtx)
	}()

	hostHeader := fmt.Sprintf("%s.%s", tunnelInfo.Subdomain, domain)
	expectedBody := "hello from local /ok"
	if err := awaitProxiedResponse(ctx, publicPort, hostHeader, "/ok", expectedBody); err != nil {
		t.Fatalf("proxy response: %v", err)
	}

	runCancel()
	select {
	case err := <-runnerErr:
		if err != nil && err != context.Canceled {
			t.Fatalf("runner exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not exit")
	}
}

type tunnelResponse struct {
	ID        string `json:"id"`
	Subdomain string `json:"subdomain"`
	Secret    string `json:"secret"`
}

func createTunnel(t *testing.T, ctx context.Context, controlURL, adminToken, name string) tunnelResponse {
	t.Helper()
	body := bytes.NewBufferString(fmt.Sprintf(`{"name":"%s","subdomain":"%s"}`, name, name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, controlURL+"/v1/tunnels", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(b))
	}
	var tr tunnelResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return tr
}

func waitForControl(ctx context.Context, controlURL, adminToken string) error {
	client := http.Client{Timeout: 500 * time.Millisecond}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, controlURL+"/v1/tunnels", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func awaitProxiedResponse(ctx context.Context, publicPort int, host, path, expectedBody string) error {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", publicPort, path)
	client := http.Client{Timeout: 1 * time.Second}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Host = host
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == expectedBody {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done before success: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func writeServerConfig(t *testing.T, path, domain string, controlPort, publicPort int, adminToken, dataDir, cacheDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfg := fmt.Sprintf(`domain: "%s"
http_addr: "127.0.0.1:%d"
https_addr: "127.0.0.1:0"
control_addr: "127.0.0.1:%d"
data_dir: "%s"
db_path: "%s/aporto.db"
admin_token: "%s"
tls:
  enable_autocert: false
  email: ""
  cache_dir: "%s"
  cert_file: ""
  key_file: ""
`, domain, publicPort, controlPort, dataDir, dataDir, adminToken, cacheDir)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func repoRootDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(cwd, "..", ".."))
}
