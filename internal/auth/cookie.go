package auth

import (
	"net"
	"net/http"
	"time"
)

const refreshCookieName = "refresh_token"

// SetRefreshCookie ставит httpOnly refresh-cookie. Secure определяется:
//   - true, если сам сервер видит реальный TLS-хендшейк (r.TLS != nil);
//   - true, если запрос пришёл с IP из allowedProxyIPs И этот запрос
//     сообщает X-Forwarded-Proto: https (доверяем заголовку только с этого IP);
//   - false в остальных случаях.
func SetRefreshCookie(w http.ResponseWriter, r *http.Request, rawToken string, allowedProxyIPs map[string]struct{}) {
	secure := isSecureRequest(r, allowedProxyIPs)

	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func isSecureRequest(r *http.Request, allowedProxyIPs map[string]struct{}) bool {
	if r.TLS != nil {
		return true
	}
	if len(allowedProxyIPs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if _, trusted := allowedProxyIPs[host]; !trusted {
		return false
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

func ClearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func ReadRefreshCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}
