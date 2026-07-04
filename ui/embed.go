// Package ui встраивает статические файлы фронтенда (login.html и собранный
// React-каркас demo-map/dist) прямо в бинарник через go:embed — соответствует
// заявленной в README архитектуре "один бинарный файл без внешней инфраструктуры".
// Раньше cmd/server/main.go читал эти файлы с диска (http.Dir/http.ServeFile),
// что требовало держать папку ui/ рядом с бинарником при развёртывании — исправлено.
package ui

import "embed"

//go:embed login.html demo-map/dist
var FS embed.FS
