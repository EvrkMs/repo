package config

import "testing"

func TestIsAdmin(t *testing.T) {
	cfg := &Config{
		RootSteamID:   "76561198000000001",
		AdminSteamIDs: map[string]struct{}{"76561198000000002": {}},
	}

	cases := []struct {
		id   string
		want bool
	}{
		{"76561198000000001", true},  // root
		{"76561198000000002", true},  // admin list
		{"76561198000000099", false}, // не в списке
	}

	for _, c := range cases {
		if got := cfg.IsAdmin(c.id); got != c.want {
			t.Errorf("IsAdmin(%s) = %v, want %v", c.id, got, c.want)
		}
	}
}
