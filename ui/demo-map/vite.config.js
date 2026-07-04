import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base: '/demo-map/' — Go-сервер отдаёт собранные ассеты именно с этого префикса
// (см. cmd/server/main.go, маршрут GET /demo-map/*), иначе относительные пути
// в index.html после сборки будут указывать на корень сайта, а не на /demo-map/.
export default defineConfig({
  plugins: [react()],
  base: '/demo-map/',
})
