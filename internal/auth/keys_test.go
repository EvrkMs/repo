package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKeys_CreatesKeysIfMissing(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	priv, pub, err := LoadOrGenerateKeys(privPath, pubPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("expected non-nil keys")
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key file not written: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key file not written: %v", err)
	}
}

func TestLoadOrGenerateKeys_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	priv1, _, err := LoadOrGenerateKeys(privPath, pubPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	priv2, _, err := LoadOrGenerateKeys(privPath, pubPath)
	if err != nil {
		t.Fatalf("unexpected error on second load: %v", err)
	}

	if priv1.D.Cmp(priv2.D) != 0 {
		t.Error("expected same key to be loaded, got a different key")
	}
}
