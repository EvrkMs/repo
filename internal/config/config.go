package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Port              string
	DBPath            string
	DemoStoragePath   string
	SteamAPIKey       string
	RootSteamID       string
	AdminSteamIDs     map[string]struct{}
	TLSCertPath       string
	TLSKeyPath        string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	SessionSecret     string
	CallbackBaseURL   string // напр. http://localhost:8080, используется в Steam OpenID return_to
}

func Load() (*Config, error) {
	root := os.Getenv("ROOT_STEAM_ID")
	if root == "" {
		return nil, fmt.Errorf("ROOT_STEAM_ID не задан в .env")
	}

	admins := make(map[string]struct{})
	for _, id := range strings.Split(os.Getenv("STEAM_ADMIN_IDS"), ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			admins[id] = struct{}{}
		}
	}

	cfg := &Config{
		Port:              getEnvDefault("PORT", "8080"),
		DBPath:            getEnvDefault("DB_PATH", "./data/intact.db"),
		DemoStoragePath:   getEnvDefault("DEMO_STORAGE_PATH", "./data/demos"),
		SteamAPIKey:       os.Getenv("STEAM_API_KEY"),
		RootSteamID:       root,
		AdminSteamIDs:     admins,
		TLSCertPath:       os.Getenv("TLS_CERT_PATH"),
		TLSKeyPath:        os.Getenv("TLS_KEY_PATH"),
		JWTPrivateKeyPath: getEnvDefault("JWT_PRIVATE_KEY_PATH", "./data/keys/jwt_private.pem"),
		JWTPublicKeyPath:  getEnvDefault("JWT_PUBLIC_KEY_PATH", "./data/keys/jwt_public.pem"),
		SessionSecret:     os.Getenv("SESSION_SECRET"),
		CallbackBaseURL:   getEnvDefault("CALLBACK_BASE_URL", "http://localhost:8080"),
	}
	if cfg.SteamAPIKey == "" {
		return nil, fmt.Errorf("STEAM_API_KEY не задан в .env")
	}
	return cfg, nil
}

func (c *Config) IsAdmin(steamID string) bool {
	if steamID == c.RootSteamID {
		return true
	}
	_, ok := c.AdminSteamIDs[steamID]
	return ok
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
