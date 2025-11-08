package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config stores CLI runtime settings.
type Config struct {
	APIURL       string `yaml:"api_url"`
	TunnelID     string `yaml:"tunnel_id"`
	TunnelSecret string `yaml:"tunnel_secret"`
	Subdomain    string `yaml:"subdomain"`
	Hostname     string `yaml:"hostname"`
	LocalAddr    string `yaml:"local_addr"`
	InsecureTLS  bool   `yaml:"insecure_tls"`
	LogLevel     string `yaml:"log_level"`
	KeyPath      string `yaml:"key_path"`
	DarkMode     bool   `yaml:"dark_mode"`
	configFile   string
}

// DefaultPath resolves ~/.config/aporto/config.yaml (or its platform equivalent).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "aporto", "config.yaml"), nil
}

// Load reads the config from disk (if present).
func Load(path string) (*Config, error) {
	cfg := &Config{
		LogLevel: "info",
		DarkMode: true,
	}
	cfg.configFile = path
	cfg.KeyPath = defaultKeyPath(path)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = defaultKeyPath(path)
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return cfg, nil
}

// Save writes the config atomically.
func (c *Config) Save() error {
	if c.configFile == "" {
		return fmt.Errorf("config path not set")
	}
	if err := os.MkdirAll(filepath.Dir(c.configFile), 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := c.configFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	return os.Rename(tmp, c.configFile)
}

// Path returns the underlying file path.
func (c *Config) Path() string {
	return c.configFile
}

// Validate ensures required fields exist before starting a tunnel.
func (c *Config) Validate() error {
	if c.APIURL == "" {
		return fmt.Errorf("api_url is required")
	}
	if c.TunnelID == "" {
		return fmt.Errorf("tunnel_id is required")
	}
	if c.TunnelSecret == "" {
		return fmt.Errorf("tunnel_secret is required")
	}
	if c.LocalAddr == "" {
		return fmt.Errorf("local_addr is required")
	}
	return nil
}

func defaultKeyPath(configPath string) string {
	dir := filepath.Dir(configPath)
	return filepath.Join(dir, "developer.key")
}
