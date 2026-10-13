import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const backend = 'http://localhost:8080';

// Same policy as contentSecurityPolicy in internal/webui/handler/handler.go, so
// the browser tests fail on any inline script or style.
const contentSecurityPolicy =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

export default defineConfig({
  plugins: [react()],
  build: {
    // dist/ is ignored repository-wide; build/app is embedded into the Go binary.
    outDir: 'build/app',
    emptyOutDir: true,
    // Keep every asset a separate file so the CSP never needs data: scripts.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL('./index.html', import.meta.url)),
        loggedOut: fileURLToPath(new URL('./logged-out.html', import.meta.url)),
      },
    },
  },
  server: {
    // `npm run dev` proxies the BFF started with `make run-webui`. The BFF
    // only accepts unsafe requests from its own origin, so the proxy presents
    // that origin. This is a development-only convenience.
    proxy: {
      '/api': {
        target: backend,
        configure: (proxy) => proxy.on('proxyReq', (req) => req.setHeader('origin', backend)),
      },
      '/auth': {
        target: backend,
        configure: (proxy) => proxy.on('proxyReq', (req) => req.setHeader('origin', backend)),
      },
    },
  },
  preview: {
    headers: { 'Content-Security-Policy': contentSecurityPolicy },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
