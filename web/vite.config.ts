import { tanstackRouter } from '@tanstack/router-plugin/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Dev-server API target. The Go server listens on :8080 by default (PORTAL_HTTP_ADDR).
const apiTarget = process.env.PORTAL_API_URL ?? 'http://localhost:8080';

export default defineConfig({
  plugins: [
    // Must come before the React plugin. Generates src/routeTree.gen.ts from src/routes.
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
      routesDirectory: './src/routes',
      generatedRouteTree: './src/routeTree.gen.ts',
    }),
    react(),
  ],
  build: {
    // The Go server embeds this directory (internal/webui/embed.go, `all:dist`),
    // serves /assets/* with immutable caching and falls back to index.html.
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
  server: {
    port: 5173,
    proxy: {
      '/healthz': { target: apiTarget },
      '/v1': { target: apiTarget },
    },
  },
});
