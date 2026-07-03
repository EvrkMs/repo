package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"intact-cs-map/internal/config"
)

type Handlers struct {
	cfg             *config.Config
	jwtIssuer       *JWTIssuer
	refreshStore    *RefreshStore
	steamVerifier   *SteamOpenIDVerifier
	allowedProxyIPs map[string]struct{} // читается из server_config, может быть nil
}

func NewHandlers(cfg *config.Config, jwtIssuer *JWTIssuer, refreshStore *RefreshStore, steamVerifier *SteamOpenIDVerifier, allowedProxyIPs map[string]struct{}) *Handlers {
	return &Handlers{
		cfg:             cfg,
		jwtIssuer:       jwtIssuer,
		refreshStore:    refreshStore,
		steamVerifier:   steamVerifier,
		allowedProxyIPs: allowedProxyIPs,
	}
}

// HandleLogin редиректит на страницу логина Steam.
func (h *Handlers) HandleLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := BuildSteamLoginURL(h.cfg.CallbackBaseURL + "/auth/callback")
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// HandleCallback обрабатывает возврат от Steam, проверяет допуск,
// выдаёт access token (в JSON-ответе тела) и refresh token (в cookie).
func (h *Handlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "невалидный запрос", http.StatusBadRequest)
		return
	}

	steamID, err := h.steamVerifier.Verify(r.Form)
	if err != nil {
		log.Printf("steam openid verify failed: %v", err)
		http.Error(w, "не удалось подтвердить вход через Steam", http.StatusUnauthorized)
		return
	}

	if !h.cfg.IsAdmin(steamID) {
		http.Error(w, "доступ запрещён: SteamID не в списке допуска", http.StatusForbidden)
		return
	}

	rawRefresh, err := h.refreshStore.Issue(steamID, "")
	if err != nil {
		log.Printf("issue refresh token failed: %v", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}

	SetRefreshCookie(w, r, rawRefresh, h.allowedProxyIPs)

	accessToken, err := h.jwtIssuer.IssueAccessToken(steamID)
	if err != nil {
		log.Printf("issue access token failed: %v", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}

	// Редирект на UI с access token во фрагменте URL (не в query — не попадёт в логи/Referer).
	// UI подхватывает его на JS-стороне и держит в памяти (не localStorage).
	http.Redirect(w, r, "/#access_token="+accessToken, http.StatusFound)
}

// HandleRefresh ротирует refresh token из cookie и выдаёт новый access token.
func (h *Handlers) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	rawRefresh, err := ReadRefreshCookie(r)
	if err != nil {
		http.Error(w, "refresh cookie отсутствует", http.StatusUnauthorized)
		return
	}

	steamID, newRawRefresh, err := h.refreshStore.Rotate(rawRefresh)
	if err != nil {
		if errors.Is(err, ErrTokenReused) {
			log.Printf("SECURITY: refresh token reuse detected for a session; family invalidated")
		}
		ClearRefreshCookie(w)
		http.Error(w, "невалидная сессия, требуется повторный вход", http.StatusUnauthorized)
		return
	}

	if !h.cfg.IsAdmin(steamID) {
		ClearRefreshCookie(w)
		http.Error(w, "доступ запрещён: SteamID не в списке допуска", http.StatusForbidden)
		return
	}

	SetRefreshCookie(w, r, newRawRefresh, h.allowedProxyIPs)

	accessToken, err := h.jwtIssuer.IssueAccessToken(steamID)
	if err != nil {
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

func (h *Handlers) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ClearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// HandleMe — защищённый эндпоинт (монтируется через RequireAuth в main.go),
// подтверждает клиенту, что access token валиден, и возвращает SteamID.
// Существует отдельно от отладочного /api/ping из main.go: /api/ping — временный
// пример защищённого маршрута, /auth/me — часть auth-контракта для фронта.
func (h *Handlers) HandleMe(w http.ResponseWriter, r *http.Request) {
	steamID, ok := SteamIDFromContext(r.Context())
	if !ok {
		// Не должно происходить за RequireAuth-мидлварью, но не молчим на всякий случай.
		http.Error(w, "steamID отсутствует в контексте", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"steam_id": steamID})
}
