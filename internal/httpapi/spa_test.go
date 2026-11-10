package httpapi

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAHandler(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":         {Data: []byte("<html>app</html>")},
		"assets/app-123.js":  {Data: []byte("console.log(1)")},
		"assets/app-123.css": {Data: []byte("body{}")},
	}
	h := spaHandler(assets, true, spaOptions{})
	cases := []struct {
		method, path string
		status       int
		body, cache  string
	}{
		{"GET", "/", 200, "<html>app</html>", "no-cache"},
		{"GET", "/admin/users", 200, "<html>app</html>", "no-cache"},
		{"GET", "/teams/registrar", 200, "<html>app</html>", "no-cache"},
		{"GET", "/assets/app-123.js", 200, "console.log(1)", "public, max-age=31536000, immutable"},
		// A missing file isn't the app (the browser's /favicon.ico probe).
		{"GET", "/favicon.ico", 404, "404 page not found", ""},
		{"GET", "/assets/gone-1.js", 404, "404 page not found", ""},
		{"GET", "/v1/unknown", 404, `"not_found"`, "no-store"},
		{"GET", "/auth/nope", 404, `"not_found"`, "no-store"},
		{"GET", "/mcp/tools", 404, `"not_found"`, "no-store"},
		{"GET", "/.well-known/jwks.json", 404, `"not_found"`, "no-store"},
		{"POST", "/admin/users", 404, `"not_found"`, "no-store"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) || w.Header().Get("Cache-Control") != tc.cache {
			t.Errorf("%s %s = %d %q cache=%q", tc.method, tc.path, w.Code, w.Body.String(), w.Header().Get("Cache-Control"))
		}
		if tc.status == 200 && !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s: missing CSP", tc.path)
		}
	}

	w := httptest.NewRecorder()
	spaHandler(fstest.MapFS{}, false, spaOptions{}).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "make web") {
		t.Errorf("unbuilt UI = %d %q", w.Code, w.Body.String())
	}
}

// Text files are served gzipped to clients that accept it, each
// representation with its own validator; small files and other formats are
// served as stored.
func TestSPAStaticCompression(t *testing.T) {
	script := strings.Repeat("console.log('open mcp portal');\n", 200)
	font := strings.Repeat("\x00binary", 400)
	h := spaHandler(fstest.MapFS{
		"index.html":           {Data: []byte("<html>app</html>")},
		"color-mode.js":        {Data: []byte(script)},
		"assets/app-123.js":    {Data: []byte(script)},
		"assets/tiny-1.js":     {Data: []byte("1")},
		"assets/inter-1.woff2": {Data: []byte(font)},
	}, true, spaOptions{})
	get := func(path string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	gunzip := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		zr, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(zr)
		return string(out)
	}

	plain := get("/assets/app-123.js", nil)
	zipped := get("/assets/app-123.js", map[string]string{"Accept-Encoding": "br, gzip;q=0.8"})
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != script {
		t.Errorf("identity response = %q encoding %q", plain.Body.String()[:20], plain.Header().Get("Content-Encoding"))
	}
	if zipped.Header().Get("Content-Encoding") != "gzip" || zipped.Body.Len() >= len(script)/4 ||
		!strings.HasPrefix(zipped.Header().Get("Content-Type"), "text/javascript") ||
		zipped.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("gzip response: %d bytes, headers %v", zipped.Body.Len(), zipped.Header())
	}
	if got := gunzip(zipped); got != script {
		t.Errorf("gzip body decodes to %d bytes, want %d", len(got), len(script))
	}
	for _, w := range []*httptest.ResponseRecorder{plain, zipped} {
		if w.Header().Get("Vary") != "Accept-Encoding" || w.Header().Get("ETag") == "" {
			t.Errorf("headers = %v", w.Header())
		}
	}
	if plain.Header().Get("ETag") == zipped.Header().Get("ETag") {
		t.Error("the two representations share an ETag")
	}

	// Refused, too small to gain, or already compressed: served as stored.
	for path, header := range map[string]map[string]string{
		"/assets/app-123.js":    {"Accept-Encoding": "gzip;q=0, identity"},
		"/assets/tiny-1.js":     {"Accept-Encoding": "gzip"},
		"/assets/inter-1.woff2": {"Accept-Encoding": "gzip"},
	} {
		if w := get(path, header); w.Code != 200 || w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s with %v = %d, encoding %q", path, header, w.Code, w.Header().Get("Content-Encoding"))
		}
	}

	// An unhashed file is revalidated, and a current copy costs no body.
	first := get("/color-mode.js", map[string]string{"Accept-Encoding": "gzip"})
	if first.Header().Get("Cache-Control") != "no-cache" || first.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("unhashed file headers = %v", first.Header())
	}
	again := get("/color-mode.js", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": first.Header().Get("ETag")})
	if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("revalidation = %d with %d bytes", again.Code, again.Body.Len())
	}
	// The gzip validator does not vouch for the stored representation.
	if w := get("/color-mode.js", map[string]string{"If-None-Match": first.Header().Get("ETag")}); w.Code != 200 {
		t.Errorf("the gzip validator matched the identity response: %d", w.Code)
	}
}

// index.html gets the instance's theme and title server-side (no flash of
// the wrong theme); both are escaped.
func TestSPAIndexPersonalised(t *testing.T) {
	page := `<!doctype html>
<html lang="en" data-brand="neutral">
  <head><title>Open MCP Portal</title><script type="module" src="/assets/app-1.js"></script></head>
  <body><div id="root"></div></body>
</html>`
	assets := fstest.MapFS{"index.html": {Data: []byte(page)}, "assets/app-1.js": {Data: []byte("x")}}
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}

	h := spaHandler(assets, true, spaOptions{Title: `Campus </title><script>alert("x")</script> & Co`, Theme: "custom"})
	for _, p := range []string{"/", "/index.html", "/teams/registrar"} {
		w := get(h, p)
		body := w.Body.String()
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s = %d %v", p, w.Code, w.Header())
		}
		if !strings.Contains(body, `<html data-brand="custom" lang="en">`) || strings.Count(body, "data-brand") != 1 {
			t.Errorf("%s: theme not applied once:\n%s", p, body)
		}
		want := `<title>Campus &lt;/title&gt;&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; Co</title>`
		if !strings.Contains(body, want) || strings.Count(body, "<title>") != 1 || strings.Contains(body, "<script>alert") {
			t.Errorf("%s: title not replaced and escaped:\n%s", p, body)
		}
		if !strings.Contains(body, `<script type="module" src="/assets/app-1.js">`) {
			t.Errorf("%s: rest of the page changed:\n%s", p, body)
		}
	}
	if w := get(h, "/assets/app-1.js"); w.Body.String() != "x" {
		t.Errorf("asset = %q", w.Body.String())
	}

	// A page without data-brand gets one; HEAD has no body.
	h = spaHandler(fstest.MapFS{"index.html": {Data: []byte("<html><head><title>x</title></head></html>")}}, true,
		spaOptions{Title: "Campus AI", Theme: "neutral"})
	if body := get(h, "/").Body.String(); body != `<html data-brand="neutral"><head><title>Campus AI</title></head></html>` {
		t.Errorf("body = %q", body)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("HEAD", "/", nil))
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD = %d %q", w.Code, w.Body.String())
	}

	// An absolute logo's origin is allowed as an image source; nothing else is.
	csp := get(spaHandler(assets, true, spaOptions{LogoOrigin: "https://cdn.example.edu"}), "/").Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data: https://cdn.example.edu;") {
		t.Errorf("csp = %q", csp)
	}
	csp = get(spaHandler(assets, true, spaOptions{LogoOrigin: "https://x; script-src *"}), "/").Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data:;") || strings.Contains(csp, "script-src *") {
		t.Errorf("csp = %q", csp)
	}
	// No page may be framed.
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("csp = %q", csp)
	}
}
