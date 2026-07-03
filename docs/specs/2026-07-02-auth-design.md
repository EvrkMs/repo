# Auth Design — Intact-CS-Map

Дата: 2026-07-02
Статус: Approved (design), реализовано в implementation plan.

## 1. Проблема

Приложение — веб-инструмент для тактического разбора демок CS2, разворачивается как один бинарник в локальной сети (буткемп/тренировочная база). Доступ должен быть строго ограничен доверенным кругом людей (тренерский штаб), без внешней инфраструктуры (нет отдельного identity-провайдера, кроме Steam).

## 2. Модель доступа

Список допущенных SteamID — закрытое множество, полностью определяемое `.env`. SQLite не хранит и не может расширить этот список.

```
is_admin(steam_id) := steam_id == ROOT_STEAM_ID
                    OR steam_id ∈ STEAM_ADMIN_IDS
```

- `ROOT_STEAM_ID` — break-glass root, всегда доступен, не зависит от состояния БД.
- `STEAM_ADMIN_IDS` — список через запятую в `.env`.
- Панель управления не может добавлять/удалять людей из этого списка.

**Проверка на каждый request**, не только при логине — доступ обрубается немедленно при удалении ID из `.env` + рестарте, без отдельной revocation-логики.

## 3. Аутентификация

- **Провайдер:** Steam OpenID 2.0.
- **Access token:** JWT, RS256 (RSA-2048), TTL 10–15 мин.
- **Refresh token:** SQLite, хэш SHA-256, TTL 1 день, rotation + reuse detection.
- Просроченные/инвалидированные токены — периодическая очистка по `expires_at`.

## 4. Cookie и транспорт

- `httpOnly`, `SameSite=Strict` если `Secure=true`, иначе `Lax`.
- `Secure` — автоматически: `r.TLS != nil`, либо доверенный `allowed_proxy_ip` + `X-Forwarded-Proto`.

## 5. CSRF

Не реализуется отдельно — один домен, `SameSite` достаточен при условии, что все state-changing операции идут не через `GET`.

## 6. Реализация

Полный implementation plan — `docs/specs/plans/2026-07-02-auth-implementation-plan.md`.
Обоснование выбора библиотек — `docs/specs/adr/2026-07-02-auth-tech-stack.md`.
