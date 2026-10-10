/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Built into the API's public dir, which the API serves at /ui/.
export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: { outDir: '../api/public', emptyOutDir: true },
  server: { proxy: { '/api': 'http://localhost:3000' } },
  test: { environment: 'jsdom', globals: true, setupFiles: ['./src/setup.ts'] },
});
