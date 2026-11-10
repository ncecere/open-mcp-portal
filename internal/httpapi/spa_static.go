package httpapi

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gzipMinBytes is the size below which compressing a file is not worth a
// second representation.
const gzipMinBytes = 1024

// compressible are the text formats of the built app. Fonts and images are
// already compressed.
var compressible = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".svg": true, ".html": true,
	".json": true, ".map": true, ".txt": true, ".xml": true,
}

// staticFiles serves the embedded app's files with an ETag and, for text
// formats, a gzip representation. The app is about 1 MB of JavaScript and
// CSS that compresses to under a third, and nothing in front of the portal
// is required to compress it. Each file is hashed and compressed once, on
// its first request.
type staticFiles struct {
	assets fs.FS
	raw    http.Handler

	mu    sync.Mutex
	files map[string]*staticFile
}

type staticFile struct {
	once sync.Once
	etag string // quoted; "" when the file could not be read
	gz   []byte // nil: served as stored
}

func newStaticFiles(assets fs.FS) *staticFiles {
	return &staticFiles{assets: assets, raw: http.FileServer(http.FS(assets)), files: map[string]*staticFile{}}
}

func (s *staticFiles) file(name string) *staticFile {
	s.mu.Lock()
	f := s.files[name]
	if f == nil {
		f = &staticFile{}
		s.files[name] = f
	}
	s.mu.Unlock()
	f.once.Do(func() {
		data, err := fs.ReadFile(s.assets, name)
		if err != nil {
			return
		}
		sum := sha256.Sum256(data)
		f.etag = `"` + hex.EncodeToString(sum[:12]) + `"`
		if !compressible[path.Ext(name)] || len(data) < gzipMinBytes {
			return
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = zw.Write(data)
		if zw.Close() == nil && buf.Len() < len(data) {
			f.gz = buf.Bytes()
		}
	})
	return f
}

// serve writes the file name, which the caller has checked exists.
func (s *staticFiles) serve(w http.ResponseWriter, r *http.Request, name string) {
	f := s.file(name)
	h := w.Header()
	h.Add("Vary", "Accept-Encoding")
	ctype := mime.TypeByExtension(path.Ext(name))
	if f.gz == nil || ctype == "" || !acceptsGzip(r) {
		if f.etag != "" {
			h.Set("ETag", f.etag)
		}
		s.raw.ServeHTTP(w, r)
		return
	}
	// A different representation needs its own validator.
	h.Set("ETag", strings.TrimSuffix(f.etag, `"`)+`-gz"`)
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", ctype)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.gz))
}

// acceptsGzip reports whether the request accepts a gzip response
// (Accept-Encoding lists gzip or *, not with q=0).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if coding = strings.TrimSpace(coding); !strings.EqualFold(coding, "gzip") && coding != "*" {
			continue
		}
		if q, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if v, err := strconv.ParseFloat(q, 64); err == nil && v == 0 {
				return false
			}
		}
		return true
	}
	return false
}
