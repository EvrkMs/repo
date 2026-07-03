package db

import "testing"

func TestOpen_CreatesTables(t *testing.T) {
	dir := t.TempDir()
	database, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer database.Close()

	tables := []string{"refresh_tokens", "server_config"}
	for _, table := range tables {
		var name string
		err := database.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("таблица %s не создана: %v", table, err)
		}
	}
}
