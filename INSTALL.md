# Первый запуск

## 1. Установить зависимости

`go.sum` намеренно не включён в архив: он собирался в изолированной песочнице, у которой нет доступа к `modernc.org` (домен, с которого раздаётся `modernc.org/sqlite`), поэтому сгенерированный там `go.sum` был бы неполным/некорректным. На твоей машине с обычным доступом в интернет выполни:

```bash
go mod tidy
```

Это скачает три зависимости (`golang-jwt/jwt/v5`, `joho/godotenv`, `modernc.org/sqlite`) и сгенерирует корректный `go.sum`.

## 2. Настроить конфиг

```bash
cp .env.example .env
```

Открой `.env` и заполни:
- `STEAM_API_KEY` — получить на https://steamcommunity.com/dev/apikey
- `ROOT_STEAM_ID` — твой SteamID64
- `STEAM_ADMIN_IDS` — SteamID64 остальных тренеров через запятую (можно оставить пустым на старте)

RSA-ключи для JWT (`JWT_PRIVATE_KEY_PATH`/`JWT_PUBLIC_KEY_PATH`) генерируются автоматически при первом запуске — трогать не нужно.

## 3. Прогнать тесты

```bash
go test ./... -v
```

Ожидается 19 тестов, все PASS (уже проверено локально в песочнице на идентичном коде, только с временно подменённым SQLite-драйвером — см. `docs/specs/adr/2026-07-02-auth-tech-stack.md`, почему в проекте именно `modernc.org/sqlite`).

## 4. Запустить

```bash
go run ./cmd/server
```

Проверить:
```bash
curl -i http://localhost:8080/api/ping
# ожидается 401 + заголовок X-Token-Refresh-Required: true

curl -i http://localhost:8080/auth/login
# ожидается 302 редирект на steamcommunity.com/openid/login
```

Открой `http://localhost:8080/` в браузере — страница логина, кнопка "Войти через Steam".

## Что дальше

Список открытых задач вне скоупа auth-подсистемы — в конце `docs/specs/2026-07-02-auth-design.md` (раздел «Вне скоупа») и в implementation plan (раздел Self-Review): панель управления `allowed_proxy_ip`, логирование security-событий в постоянное хранилище, остальные бизнес-эндпоинты (parser, WebSocket, demo storage).
