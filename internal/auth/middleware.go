package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const steamIDContextKey contextKey = "steam_id"

// RequireAuth возвращает middleware, проверяющий access token (Authorization: Bearer ...)
// на каждом защищённом маршруте. При отсутствии или истечении токена отвечает 401
// с заголовком X-Token-Refresh-Required: true — сигнал клиенту вызвать POST /auth/refresh
// и повторить запрос с новым токеном. Сам middleware refresh не делает — это ответственность
// клиента (см. ui/login.html).
func RequireAuth(issuer *JWTIssuer) func(http.Handler) http.Handler {
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
