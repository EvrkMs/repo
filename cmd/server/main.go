package main

import (
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/joho/godotenv"

	"intact-cs-map/internal/auth"
	"intact-cs-map/internal/config"
	"intact-cs-map/internal/db"
	"intact-cs-map/ui"
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
	proxyIPStore, err := auth.NewProxyIPStore(database)
	if err != nil {
		log.Fatalf("proxy IP store: %v", err)
	}

	handlers := auth.NewHandlers(cfg, jwtIssuer, refreshStore, steamVerifier, proxyIPStore)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", handlers.HandleLogin)
	mux.HandleFunc("GET /auth/callback", handlers.HandleCallback)
	mux.HandleFunc("POST /auth/refresh", handlers.HandleRefresh)
	mux.HandleFunc("POST /auth/logout", handlers.HandleLogout)
	mux.Handle("GET /auth/me", auth.RequireAuth(jwtIssuer, cfg)(http.HandlerFunc(handlers.HandleMe)))
	mux.Handle("GET /admin/config", auth.RequireRoot(jwtIssuer, cfg)(http.HandlerFunc(handlers.HandleGetAdminConfig)))
	mux.Handle("POST /admin/config", auth.RequireRoot(jwtIssuer, cfg)(http.HandlerFunc(handlers.HandleSetAdminConfig)))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		data, err := ui.FS.ReadFile("login.html")
		if err != nil {
			http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// /demo-map/* — статика React-каркаса, встроенная в бинарник (см. ui/embed.go).
	// Раздаётся публично (как и login.html): обычная навигация браузера не может
	// нести Authorization-заголовок, поэтому авторизацию сама SPA делает на клиенте
	// (тот же bootstrap: /auth/refresh по cookie -> /auth/me), редиректя на / при
	// отсутствии сессии. Реальные данные — когда появится API парсера — будут
	// закрыты RequireAuth отдельно.
	demoMapFS, err := fs.Sub(ui.FS, "demo-map/dist")
	if err != nil {
		log.Fatalf("встроенные файлы demo-map: %v", err)
	}
	mux.Handle("GET /demo-map/", http.StripPrefix("/demo-map/", http.FileServer(http.FS(demoMapFS))))

	// Пример защищённого маршрута — реальные маршруты добавятся вместе
	// с остальными подсистемами (парсер, WebSocket и т.д.).
	protected := auth.RequireAuth(jwtIssuer, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
