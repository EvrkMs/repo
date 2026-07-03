package auth

import (
	"testing"

	"intact-cs-map/internal/db"
)

func TestProxyIPStore_SetAndGet(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer database.Close()

	store, err := NewProxyIPStore(database)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Изначально пусто
	if got := store.GetList(); len(got) != 0 {
		t.Errorf("expected empty list initially, got %v", got)
	}

	if err := store.Set([]string{"10.0.0.5", "10.0.0.6", " 10.0.0.6 "}); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := store.Get()
	if _, ok := got["10.0.0.5"]; !ok {
		t.Error("expected 10.0.0.5 in allowlist")
	}
	if _, ok := got["10.0.0.6"]; !ok {
		t.Error("expected 10.0.0.6 in allowlist")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 unique IPs (dedup whitespace variant), got %d: %v", len(got), got)
	}
}

func TestProxyIPStore_PersistsAcrossReload(t *testing.T) {
	path := t.TempDir() + "/test.db"
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("db: %v", err)
	}

	store1, err := NewProxyIPStore(database)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store1.Set([]string{"192.168.1.1"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	database.Close()

	database2, err := db.Open(path)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer database2.Close()

	store2, err := NewProxyIPStore(database2)
	if err != nil {
		t.Fatalf("new store on reload: %v", err)
	}

	got := store2.Get()
	if _, ok := got["192.168.1.1"]; !ok {
		t.Errorf("expected persisted IP to survive reload, got %v", got)
	}
}
