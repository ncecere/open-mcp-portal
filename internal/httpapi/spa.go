package httpapi

import (
	"bytes"
	"html"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

// contentSecurityPolicy applies to the web app. Styles allow 'unsafe-inline'
// because the dialog and menu primitives position themselves with inline
// style attributes; scripts are same-origin only. %IMG% is replaced with the
// image sources (the logo's origin is added when UI_LOGO_URL is absolute).
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src %IMG%; font-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// apiPrefixes never fall back to the app: unknown API paths are JSON 404s.
// /mcp/ and /.well-known/ are reserved for the MCP endpoints and their
// metadata (later phases).
var apiPrefixes = []string{"/v1/", "/auth/", "/healthz", "/readyz", "/mcp/", "/.well-known/"}

// spaOptions personalise index.html for this instance (ADR-0018).
type spaOptions struct {
	Title      string // INSTANCE_NAME, the <title>
	Theme      string // UI_THEME, <html data-brand>
	LogoOrigin string // https origin of UI_LOGO_URL, allowed in img-src
}

var (
	titleRE       = regexp.MustCompile(`(?is)<title>.*?</title>`)
	htmlTagRE     = regexp.MustCompile(`(?i)<html\b[^>]*>`)
	dataBrandRE   = regexp.MustCompile(`(?i)\sdata-brand\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)`)
	httpsOriginRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$`)
)

// renderIndex sets the page title and the theme on <html> server-side, so
// the first paint already has the right brand (no flash). Values are
// HTML-escaped.
func renderIndex(page []byte, o spaOptions) []byte {
	out := page
	if loc := titleRE.FindIndex(out); o.Title != "" && loc != nil {
		out = splice(out, loc, []byte("<title>"+html.EscapeString(o.Title)+"</title>"))
	}
	if loc := htmlTagRE.FindIndex(out); o.Theme != "" && loc != nil {
		// Drop any data-brand the build left, then add ours right after <html.
		rest := dataBrandRE.ReplaceAllLiteral(out[loc[0]+len("<html"):loc[1]], nil)
		tag := append([]byte(`<html data-brand="`+html.EscapeString(o.Theme)+`"`), rest...)
		out = splice(out, loc, tag)
	}
	return out
}

// splice returns b with b[loc[0]:loc[1]] replaced by with (b is not modified).
func splice(b []byte, loc []int, with []byte) []byte {
	out := make([]byte, 0, len(b)-(loc[1]-loc[0])+len(with))
	out = append(out, b[:loc[0]]...)
	out = append(out, with...)
	return append(out, b[loc[1]:]...)
}

// cspFor is the app's policy for this instance.
func cspFor(o spaOptions) string {
	img := "'self' data:"
	if httpsOriginRE.MatchString(o.LogoOrigin) {
		img += " " + o.LogoOrigin
	}
	return strings.Replace(contentSecurityPolicy, "%IMG%", img, 1)
}

// loadIndex reads and personalises index.html (nil when the UI is not built).
func loadIndex(assets fs.FS, built bool, opts spaOptions) []byte {
	if !built || assets == nil {
		return nil
	}
	page, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil
	}
	return renderIndex(page, opts)
}

// spaHandler serves the embedded single-page app. Existing files are served
// directly, gzipped when the client accepts it: hashed assets are cached for
// a year, the other files are revalidated by ETag. A missing file (a path
// whose last segment has an extension, such as /favicon.ico) is a plain
// 404; any other GET path returns index.html, personalised by opts, so
// client-side routes work on reload. App routes never end in an extension.
func spaHandler(assets fs.FS, built bool, opts spaOptions) http.Handler {
	files := newStaticFiles(assets)
	csp := cspFor(opts)
	index := loadIndex(assets, built, opts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range apiPrefixes {
			if strings.HasPrefix(r.URL.Path, p) || r.URL.Path == strings.TrimSuffix(p, "/") {
				httpx.Error(w, http.StatusNotFound, "not_found", "Not found")
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpx.Error(w, http.StatusNotFound, "not_found", "Not found")
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		if !built || index == nil {
			h.Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The web UI has not been built. Run `make web`, then rebuild Open MCP Portal.\n"))
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(assets, name); err == nil && !st.IsDir() {
				// Only assets/ names carry a content hash; the rest (the
				// color-mode script the page blocks on, icons) revalidate.
				h.Set("Cache-Control", "no-cache")
				if strings.HasPrefix(name, "assets/") {
					h.Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.serve(w, r, name)
				return
			}
		}
		if name != "index.html" && path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	})
}
