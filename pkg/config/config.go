package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Loader wraps a viper instance to read YAML/TOML/JSON configs with env overrides.
type Loader struct {
	v *viper.Viper
}

// New returns a Loader prepared to read the provided config path.
// If path is empty, only environment variables will be used.
func New(path string, envPrefix string) (*Loader, error) {
	v := viper.New()
	if path != "" {
		v.SetConfigFile(path)
	}

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if path != "" {
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	return &Loader{v: v}, nil
}

// Unmarshal binds the config into the provided target struct pointer.
func (l *Loader) Unmarshal(target any) error {
	if err := l.v.Unmarshal(target); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return nil
}
