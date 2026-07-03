package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrGenerateKeys загружает RSA-ключи с диска. Если файлов нет — генерирует
// новую пару (2048 бит) и сохраняет на диск для последующих запусков.
func LoadOrGenerateKeys(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if fileExists(privPath) && fileExists(pubPath) {
		return loadKeys(privPath, pubPath)
	}
	return generateAndSaveKeys(privPath, pubPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadKeys(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("чтение приватного ключа: %w", err)
	}
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, nil, fmt.Errorf("невалидный PEM в %s", privPath)
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("парсинг приватного ключа: %w", err)
	}
	return priv, &priv.PublicKey, nil
}

func generateAndSaveKeys(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("генерация RSA-ключа: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return nil, nil, fmt.Errorf("создание директории для ключей: %w", err)
	}

	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err := os.WriteFile(privPath, privBytes, 0o600); err != nil {
		return nil, nil, fmt.Errorf("запись приватного ключа: %w", err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey),
	})
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return nil, nil, fmt.Errorf("запись публичного ключа: %w", err)
	}

	return priv, &priv.PublicKey, nil
}
