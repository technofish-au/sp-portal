#!/usr/bin/env bash
# Ensure internal/webui/dist/index.html exists so that `//go:embed all:dist`
# compiles without a web build. Writes a minimal placeholder page only when
# index.html is missing; a real Vite build (web/, outDir ../internal/webui/dist)
# is never touched. Called first by every Go build/test/lint target.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="${root}/internal/webui/dist"

if [ -f "${dist}/index.html" ]; then
  exit 0
fi

mkdir -p "${dist}"
cat > "${dist}/index.html" <<'EOF'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="sp-placeholder" content="true" />
    <title>ServerPerch Portal</title>
  </head>
  <body>
    <h1>ServerPerch Portal</h1>
    <p>web UI not built. Run <code>make web-build</code> (or <code>make build</code>) and rebuild sp-portal.</p>
  </body>
</html>
EOF
echo "ensure-web-dist: wrote placeholder ${dist}/index.html"
