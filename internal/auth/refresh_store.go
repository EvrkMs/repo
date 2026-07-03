package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type RefreshStore struct {
	db  *sql.DB
	ttl time.Duration
}

func NewRefreshStore(db *sql.DB, ttl time.Duration) *RefreshStore {
	return &RefreshStore{db: db, ttl: ttl}
}

var ErrTokenReused = errors.New("refresh token уже использован — цепочка сессии инвалидирована")

// Issue создаёт новый refresh token. Если familyID пустой — начинает новую
// цепочку (первый логин), иначе продолжает существующую.
func (s *RefreshStore) Issue(steamID, familyID string) (rawToken string, err error) {
	rawToken, err = randomToken()
	if err != nil {
		return "", err
	}
	if familyID == "" {
		familyID, err = randomToken()
		if err != nil {
			return "", err
		}
	}

	hash := hashToken(rawToken)
	_, err = s.db.Exec(
		`INSERT INTO refresh_tokens (token_hash, family_id, steam_id, expires_at)
		 VALUES (?, ?, ?, ?)`,
		hash, familyID, steamID, time.Now().Add(s.ttl),
	)
	if err != nil {
		return "", fmt.Errorf("сохранение refresh token: %w", err)
	}
	return rawToken, nil
}

// Rotate проверяет rawToken, при успехе инвалидирует его и выдаёт новый в той же family.
// Если токен уже был инвалидирован ранее (reuse) — инвалидирует всю family и возвращает ErrTokenReused.
func (s *RefreshStore) Rotate(rawToken string) (steamID, newRawToken string, err error) {
	hash := hashToken(rawToken)

	var (
		familyID  string
		dbSteamID string
		expiresAt time.Time
		revokedAt sql.NullTime
	)
	row := s.db.QueryRow(
		`SELECT family_id, steam_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?`,
		hash,
	)
	if err := row.Scan(&familyID, &dbSteamID, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", errors.New("refresh token не найден")
		}
		return "", "", fmt.Errorf("чтение refresh token: %w", err)
	}

	if revokedAt.Valid {
		// Токен уже был инвалидирован ранее — это reuse. Инвалидируем всю family.
		if _, err := s.db.Exec(
			`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP
			 WHERE family_id = ? AND revoked_at IS NULL`,
			familyID,
		); err != nil {
			return "", "", fmt.Errorf("инвалидация family после reuse: %w", err)
		}
		return "", "", ErrTokenReused
	}

	if time.Now().After(expiresAt) {
		return "", "", errors.New("refresh token истёк")
	}

	// Инвалидируем текущий токен
	if _, err := s.db.Exec(
		`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
		hash,
	); err != nil {
		return "", "", fmt.Errorf("инвалидация текущего токена: %w", err)
	}

	newRawToken, err = s.Issue(dbSteamID, familyID)
	if err != nil {
		return "", "", err
	}
	return dbSteamID, newRawToken, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("генерация токена: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
