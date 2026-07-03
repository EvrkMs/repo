package main

import (
	"log"
	"net/http"
	"time"

	"github.com/joho/godotenv"

	"intact-cs-map/internal/auth"
	"intact-cs-map/internal/config"
	"intact-cs-map/internal/db"
)

func main() {
	// Загружаем .env, если он есть. Отсутствие файла не ошибка — переменные
	// могли быть заданы напрямую в окружении (например, в Docker).
	if err := godotenv.Load(); err != nil {
		log.Printf(".env не найден, используются переменные окружения процесса: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("конфигурация: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("база данных: %v", err)
	}
	defer database.Close()

	priv, pub, err := auth.LoadOrGenerateKeys(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath)
	if err != nil {
		log.Fatalf("JWT-ключи: %v", err)
	}

	jwtIssuer := auth.NewJWTIssuer(priv, pub, 15*time.Minute)
	refreshStore := auth.NewRefreshStore(database, 24*time.Hour)
	steamVerifier := auth.NewSteamOpenIDVerifier()

	// allowedProxyIPs пока nil — читается из server_config, когда появится
	// панель настроек (вне скоупа текущего плана).
	handlers := auth.NewHandlers(cfg, jwtIssuer, refreshStore, steamVerifier, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", handlers.HandleLogin)
	mux.HandleFunc("GET /auth/callback", handlers.HandleCallback)
	mux.HandleFunc("POST /auth/refresh", handlers.HandleRefresh)
	mux.HandleFunc("POST /auth/logout", handlers.HandleLogout)
	mux.Handle("GET /auth/me", auth.RequireAuth(jwtIssuer)(http.HandlerFunc(handlers.HandleMe)))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./ui/login.html")
	})

	// Пример защищённого маршрута — реальные маршруты добавятся вместе
	// с остальными подсистемами (парсер, WebSocket и т.д.).
	protected := auth.RequireAuth(jwtIssuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		steamID, _ := auth.SteamIDFromContext(r.Context())
		w.Write([]byte("OK, привет, " + steamID))
	}))
	mux.Handle("GET /api/ping", protected)

	log.Printf("сервер запущен на порту %s", cfg.Port)
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		log.Fatal(http.ListenAndServeTLS(":"+cfg.Port, cfg.TLSCertPath, cfg.TLSKeyPath, mux))
	} else {
		log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
	}
}
