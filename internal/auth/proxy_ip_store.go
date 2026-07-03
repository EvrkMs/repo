package auth

import (
	"database/sql"
	"strings"
	"sync"
)

const proxyIPConfigKey = "allowed_proxy_ip"

// ProxyIPStore держит текущий allowlist доверенных IP reverse-proxy в памяти,
// синхронизированный с SQLite (server_config), чтобы изменения через панель
// применялись без рестарта сервера (см. design doc, раздел "Панель управления").
type ProxyIPStore struct {
	db  *sql.DB
	mu  sync.RWMutex
	ips map[string]struct{}
}

func NewProxyIPStore(db *sql.DB) (*ProxyIPStore, error) {
	s := &ProxyIPStore{db: db, ips: map[string]struct{}{}}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ProxyIPStore) reload() error {
	var value string
	err := s.db.QueryRow(`SELECT value FROM server_config WHERE key = ?`, proxyIPConfigKey).Scan(&value)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ips = parseIPList(value)
	return nil
}

// Get возвращает копию текущего allowlist для использования в SetRefreshCookie/isSecureRequest.
func (s *ProxyIPStore) Get() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]struct{}, len(s.ips))
	for ip := range s.ips {
		out[ip] = struct{}{}
	}
	return out
}

// GetList возвращает allowlist в виде отсортированного для стабильности вывода списка строк.
func (s *ProxyIPStore) GetList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.ips))
	for ip := range s.ips {
		out = append(out, ip)
	}
	return out
}

// Set сохраняет новый allowlist в SQLite и сразу применяет его в памяти —
// без рестарта сервера.
func (s *ProxyIPStore) Set(ips []string) error {
	clean := map[string]struct{}{}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			clean[ip] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(clean))
	for ip := range clean {
		ordered = append(ordered, ip)
	}
	value := strings.Join(ordered, ",")

	_, err := s.db.Exec(
		`INSERT INTO server_config (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		proxyIPConfigKey, value,
	)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.ips = clean
	s.mu.Unlock()
	return nil
}

func parseIPList(value string) map[string]struct{} {
	out := map[string]struct{}{}
	if value == "" {
		return out
	}
	for _, ip := range strings.Split(value, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			out[ip] = struct{}{}
		}
	}
	return out
}
