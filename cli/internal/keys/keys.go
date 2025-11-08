package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Pair holds an ed25519 keypair.
type Pair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generate creates a new keypair.
func Generate() (*Pair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Pair{Private: priv, Public: pub}, nil
}

// Save writes the private/public files in base64 format.
func Save(path string, p *Pair, force bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("key already exists at %s (use --force to overwrite)", path)
		}
	}
	privB64 := base64.StdEncoding.EncodeToString(p.Private)
	if err := os.WriteFile(path, []byte(privB64), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(p.Public)
	if err := os.WriteFile(path+".pub", []byte(pubB64+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// Load reads the keypair from disk.
func Load(path string) (*Pair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privBytes, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return &Pair{Private: priv, Public: pub}, nil
}

// EncodePublic returns the base64 form of the public key.
func EncodePublic(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// Fingerprint returns the hex sha256 fingerprint of the public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Sign signs the provided payload using the private key.
func (p *Pair) Sign(payload []byte) []byte {
	return ed25519.Sign(p.Private, payload)
}

// PublicBase64 returns the base64-encoded public key for this pair.
func (p *Pair) PublicBase64() string {
	return EncodePublic(p.Public)
}
