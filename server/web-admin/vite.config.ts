import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  // 相对路径构建：产物交给 admin_server 在任意路径下托管
  base: './',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:9090',
    },
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 2000,
  },
})
