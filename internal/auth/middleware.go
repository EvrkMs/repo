package auth

import (
	"context"
	"net/http"
	"strings"

	"intact-cs-map/internal/config"
)

type contextKey string

const steamIDContextKey contextKey = "steam_id"

// RequireAuth возвращает middleware, проверяющий access token (Authorization: Bearer ...)
// на каждом защищённом маршруте, а также проверяющий SteamID против текущего allow-list
// (cfg.IsAdmin) — не только валидность подписи/срока токена. Это то, что закрывает пробел
// из design doc: "is_admin проверяется на каждый request" — если SteamID убрали из .env
// и перезапустили сервер, ещё не истёкший access token всё равно должен терять доступ.
//
// Различает два разных случая отказа:
//   - 401 + X-Token-Refresh-Required: true — токена нет/истёк/подпись неверна.
//     Клиент должен попробовать POST /auth/refresh.
//   - 403 — токен валиден, но SteamID больше не в allow-list. Refresh не поможет
//     (HandleRefresh тоже проверяет is_admin и откажет), это финальный отказ.
func RequireAuth(issuer *JWTIssuer, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				respondUnauthorizedWithRefreshHint(w)
				return
			}
			token := strings.TrimPrefix(authHeader, prefix)

			steamID, err := issuer.VerifyAccessToken(token)
			if err != nil {
				respondUnauthorizedWithRefreshHint(w)
				return
			}

			if !cfg.IsAdmin(steamID) {
				http.Error(w, "доступ запрещён: SteamID не в списке допуска", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), steamIDContextKey, steamID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func respondUnauthorizedWithRefreshHint(w http.ResponseWriter) {
	w.Header().Set("X-Token-Refresh-Required", "true")
	http.Error(w, "требуется аутентификация", http.StatusUnauthorized)
}

func SteamIDFromContext(ctx context.Context) (string, bool) {
	steamID, ok := ctx.Value(steamIDContextKey).(string)
	return steamID, ok
}

// RequireRoot оборачивает RequireAuth дополнительной проверкой: только ROOT_STEAM_ID
// проходит. Используется для эндпоинтов панели управления (/admin/config), которые
// не должны быть доступны обычным допущенным SteamID — только break-glass root'у.
func RequireRoot(issuer *JWTIssuer, cfg *config.Config) func(http.Handler) http.Handler {
	requireAuth := RequireAuth(issuer, cfg)
	return func(next http.Handler) http.Handler {
		return requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			steamID, _ := SteamIDFromContext(r.Context())
			if steamID != cfg.RootSteamID {
				http.Error(w, "доступ только для root", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}
