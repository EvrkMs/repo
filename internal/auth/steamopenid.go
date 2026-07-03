package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const defaultSteamOpenIDEndpoint = "https://steamcommunity.com/openid/login"

var claimedIDPattern = regexp.MustCompile(`^https?://steamcommunity\.com/openid/id/(\d+)$`)

// BuildSteamLoginURL формирует URL редиректа на Steam OpenID login page.
func BuildSteamLoginURL(returnTo string) string {
	params := url.Values{
		"openid.ns":         {"http://specs.openid.net/auth/2.0"},
		"openid.mode":       {"checkid_setup"},
		"openid.return_to":  {returnTo},
		"openid.realm":      {returnTo},
		"openid.identity":   {"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.claimed_id": {"http://specs.openid.net/auth/2.0/identifier_select"},
	}
	return defaultSteamOpenIDEndpoint + "?" + params.Encode()
}

func extractSteamID(claimedID string) (string, error) {
	m := claimedIDPattern.FindStringSubmatch(claimedID)
	if m == nil {
		return "", fmt.Errorf("не удалось извлечь SteamID из claimed_id: %s", claimedID)
	}
	return m[1], nil
}

type SteamOpenIDVerifier struct {
	steamEndpoint string // переопределяется в тестах, по умолчанию defaultSteamOpenIDEndpoint
}

func NewSteamOpenIDVerifier() *SteamOpenIDVerifier {
	return &SteamOpenIDVerifier{steamEndpoint: defaultSteamOpenIDEndpoint}
}

// Verify принимает query-параметры callback-запроса от Steam, отправляет их
// обратно в Steam с mode=check_authentication (защита от подделки ответа),
// и при успехе возвращает SteamID64.
func (v *SteamOpenIDVerifier) Verify(callbackValues map[string][]string) (string, error) {
	claimedIDs, ok := callbackValues["openid.claimed_id"]
	if !ok || len(claimedIDs) == 0 {
		return "", errors.New("отсутствует openid.claimed_id в ответе Steam")
	}
	steamID, err := extractSteamID(claimedIDs[0])
	if err != nil {
		return "", err
	}

	verifyParams := url.Values{}
	for k, vals := range callbackValues {
		verifyParams[k] = vals
	}
	verifyParams.Set("openid.mode", "check_authentication")

	resp, err := http.PostForm(v.steamEndpoint, verifyParams)
	if err != nil {
		return "", fmt.Errorf("запрос check_authentication к Steam: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("чтение ответа Steam: %w", err)
	}

	if !strings.Contains(string(body), "is_valid:true") {
		return "", errors.New("Steam отклонил подтверждение подлинности (is_valid:false)")
	}

	return steamID, nil
}
