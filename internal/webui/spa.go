package webui

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Cache-Control values.
const (
	// CacheImmutable is used for content-hashed files under /assets/.
	CacheImmutable = "public, max-age=31536000, immutable"
	// CacheNoCache is used for index.html and other unhashed files.
	CacheNoCache = "no-cache"
)

const (
	indexFile    = "index.html"
	assetsPrefix = "assets/"
)

// NewHandler returns an SPA handler for fsys:
//
//   - GET/HEAD of an existing file serves it; files under assets/ get
//     CacheImmutable, everything else CacheNoCache.
//   - A missing file under assets/ is a 404 (never index.html, so a stale
//     hashed URL can't be cached as HTML).
//   - Any other GET/HEAD (client-side route, directory) serves index.html
//     with CacheNoCache.
//   - Other methods get 405.
func NewHandler(fsys fs.FS) http.Handler {
	return &spa{fsys: fsys}
}

type spa struct {
	fsys fs.FS
}

func (s *spa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = indexFile
	}

	if s.isFile(name) {
		cache := CacheNoCache
		if strings.HasPrefix(name, assetsPrefix) {
			cache = CacheImmutable
		}
		s.serve(w, r, name, cache)
		return
	}

	if strings.HasPrefix(name, assetsPrefix) {
		http.NotFound(w, r)
		return
	}
	if !s.isFile(indexFile) {
		http.Error(w, "web UI not built", http.StatusNotFound)
		return
	}
	s.serve(w, r, indexFile, CacheNoCache)
}

func (s *spa) isFile(name string) bool {
	st, err := fs.Stat(s.fsys, name)
	return err == nil && st.Mode().IsRegular()
}

func (s *spa) serve(w http.ResponseWriter, r *http.Request, name, cache string) {
	f, err := s.fsys.Open(name)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()

	var modTime time.Time
	if st, err := f.Stat(); err == nil {
		modTime = st.ModTime()
	}
	content, ok := f.(io.ReadSeeker)
	if !ok {
		b, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		content = bytes.NewReader(b)
	}
	w.Header().Set("Cache-Control", cache)
	http.ServeContent(w, r, name, modTime, content)
}
