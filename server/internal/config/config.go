package config

import (
	"fmt"
	"path/filepath"
	"strings"

	apconfig "github.com/luuccaaaa/aporto/pkg/config"
)

// TLSConfig controls how the public listener obtains TLS certificates.
type TLSConfig struct {
	EnableAutocert bool   `mapstructure:"enable_autocert"`
	Email          string `mapstructure:"email"`
	CacheDir       string `mapstructure:"cache_dir"`
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
}

// Config describes all runtime knobs for the server process.
type Config struct {
	Domain             string    `mapstructure:"domain"`
	HTTPAddr           string    `mapstructure:"http_addr"`
	HTTPSAddr          string    `mapstructure:"https_addr"`
	ControlAddr        string    `mapstructure:"control_addr"`
	DataDir            string    `mapstructure:"data_dir"`
	DBPath             string    `mapstructure:"db_path"`
	AdminToken         string    `mapstructure:"admin_token"`
	AuthorizedKeysPath string    `mapstructure:"authorized_keys"`
	TLS                TLSConfig `mapstructure:"tls"`
}

// Load reads a YAML/TOML/JSON config file and fills defaults.
func Load(path string) (*Config, error) {
	loader, err := apconfig.New(path, "APORTO_SERVER")
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := loader.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.HTTPAddr == "" {
		c.HTTPAddr = ":80"
	}
	if c.HTTPSAddr == "" {
		c.HTTPSAddr = ":443"
	}
	if c.ControlAddr == "" {
		c.ControlAddr = "127.0.0.1:9090"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "aporto.db")
	}
	if c.TLS.CacheDir == "" {
		c.TLS.CacheDir = filepath.Join(c.DataDir, "autocert-cache")
	}
}

// Validate ensures the config has the mandatory values.
func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if !strings.Contains(c.Domain, ".") {
		return fmt.Errorf("domain must be FQDN")
	}
	// Admin token optional in key-based flow.
	// Authorized keys required for developer self-service.
	if c.AuthorizedKeysPath == "" {
		return fmt.Errorf("authorized_keys path is required")
	}
	return nil
}
