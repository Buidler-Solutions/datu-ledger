import { defineConfig } from 'vite';

// The lab frontend talks to the sandbox backend on 127.0.0.1:5175 in dev
// and same-origin in production (the backend serves dist/). Keep the same
// esbuild JSX settings as the registrar so both apps share one toolchain.
export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:5175', changeOrigin: false },
    },
  },
  build: { outDir: 'dist' },
  esbuild: { jsx: 'automatic' },
  test: { environment: 'jsdom' },
});
