import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));

// dist/ is the unpacked extension: manifest.json + background.js + icons come
// verbatim from public/, the two HTML entries are built by Rollup.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    target: 'chrome120',
    rollupOptions: {
      input: {
        sidepanel: resolve(root, 'sidepanel.html'),
        dashboard: resolve(root, 'dashboard.html'),
      },
    },
  },
});
