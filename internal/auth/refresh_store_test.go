package auth

import (
	"testing"
	"time"

	"intact-cs-map/internal/db"
)

func TestRefreshStore_IssueAndRotate(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer database.Close()

	store := NewRefreshStore(database, 24*time.Hour)

	// Первая выдача — новая family
	rawToken1, err := store.Issue("76561198000000001", "")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if rawToken1 == "" {
		t.Fatal("expected non-empty token")
	}

	// Rotate: валидный refresh -> новый токен, старый инвалидирован
	steamID, rawToken2, err := store.Rotate(rawToken1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if steamID != "76561198000000001" {
		t.Errorf("got steamID %s", steamID)
	}
	if rawToken2 == rawToken1 {
		t.Error("expected a new token after rotation")
	}

	// Повторное использование старого (уже инвалидированного) токена -> reuse detected,
	// вся family должна быть инвалидирована, включая rawToken2
	if _, _, err := store.Rotate(rawToken1); err == nil {
		t.Error("expected reuse detection error, got nil")
	}
	if _, _, err := store.Rotate(rawToken2); err == nil {
		t.Error("expected rawToken2 to be invalidated after reuse detection on family")
	}
}
