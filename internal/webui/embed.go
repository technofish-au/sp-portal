// Package webui embeds the built portal web UI (Vite output in ./dist) and
// serves it as a single-page application.
//
// dist/ is produced by `npm run build` in web/ (build.outDir
// '../internal/webui/dist') and is gitignored. scripts/ensure-web-dist.sh
// writes a placeholder dist/index.html when it is missing, so Go builds
// and tests work without a web build.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded dist directory as the root of a file system.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil { // only possible if the embed pattern changes
		panic(err)
	}
	return sub
}

// Handler serves the embedded web UI; see NewHandler.
func Handler() http.Handler {
	return NewHandler(FS())
}
