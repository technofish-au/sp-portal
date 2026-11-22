import { defineConfig } from 'astro/config';

// Static-only build. `site` is the canonical public origin; it is also used
// for the sitemap/canonical URLs Astro generates.
export default defineConfig({
  site: 'https://serverperch.com',
  output: 'static',
  trailingSlash: 'never',
  build: {
    format: 'directory',
  },
});
