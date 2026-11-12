import { defineConfig } from 'vite';

export default defineConfig({
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: { outDir: 'dist' },
  // React 19 automatic runtime for .jsx everywhere (build, dev, tests).
  esbuild: { jsx: 'automatic' },
  test: { environment: 'jsdom' },
});
