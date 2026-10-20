package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// stateLogin is a sign-in that stopped at the callback: the cookies the
// portal set at /auth/login and the callback URL the provider sent the
// browser to.
type stateLogin struct {
	cookies  []*http.Cookie
	callback string // path and query
}

// startSignIn drives /auth/login and the provider's authorize endpoint
// without following the redirect to APP_URL (an https name that is not
// served here).
func startSignIn(t *testing.T, app *testApp, p *testutil.OIDCProvider) stateLogin {
	t.Helper()
	p.SetClaims(map[string]any{"sub": "state-sub", "email": "state@example.com", "email_verified": true})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", res.StatusCode)
	}
	out := stateLogin{cookies: res.Cookies()}
	res, err = client.Get(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	target, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d %v", res.StatusCode, err)
	}
	out.callback = target.RequestURI()
	return out
}

// callbackWith sends the callback with the given cookies only (as a browser
// that held exactly those would) and returns the response.
func callbackWith(t *testing.T, app *testApp, l stateLogin, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", app.URL+l.callback, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func cookieNamed(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func httpsApp(t *testing.T) (*testApp, *testutil.OIDCProvider) {
	return oidcApp(t, func(c *config.Config) { c.AppURL = "https://omp.example.com" })
}

// Over https the sign-in state cookie is __Host- prefixed: host-only, Secure,
// Path=/, HttpOnly, SameSite=Lax, with a lifetime; the plain name is not
// set. Sign-in completes with it, and the cookie is cleared afterwards.
func TestOIDCStateCookieIsHostPrefixedOnHTTPS(t *testing.T) {
	app, p := httpsApp(t)
	l := startSignIn(t, app, p)
	c := cookieNamed(l.cookies, "__Host-omp_oidc_state")
	if c == nil {
		t.Fatalf("no __Host-omp_oidc_state cookie in %v", l.cookies)
	}
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 || len(c.Value) < 32 {
		t.Errorf("attributes = %+v", c)
	}
	if cookieNamed(l.cookies, "omp_oidc_state") != nil {
		t.Error("the plain name was set as well")
	}
	res := callbackWith(t, app, l, c)
	if res.StatusCode != http.StatusSeeOther || cookieNamed(res.Cookies(), "__Host-omp_session") == nil {
		t.Fatalf("callback = %d, cookies %v", res.StatusCode, res.Cookies())
	}
	cleared := cookieNamed(res.Cookies(), "__Host-omp_oidc_state")
	if cleared == nil || cleared.MaxAge >= 0 || !cleared.Secure || cleared.Path != "/" {
		t.Errorf("state cookie not cleared: %+v", cleared)
	}
}

// A person who started signing in before the upgrade holds the plain name on
// an https origin: the callback still works for one release.
func TestOIDCStateCookieUpgradeMidSignIn(t *testing.T) {
	app, p := httpsApp(t)
	l := startSignIn(t, app, p)
	issued := cookieNamed(l.cookies, "__Host-omp_oidc_state")
	legacy := &http.Cookie{Name: "omp_oidc_state", Value: issued.Value, Path: "/", Secure: true, HttpOnly: true}
	res := callbackWith(t, app, l, legacy)
	if res.StatusCode != http.StatusSeeOther || cookieNamed(res.Cookies(), "__Host-omp_session") == nil {
		t.Fatalf("callback with the old cookie name = %d", res.StatusCode)
	}
	// The old name is cleared too, so it doesn't linger.
	if c := cookieNamed(res.Cookies(), "omp_oidc_state"); c == nil || c.MaxAge >= 0 {
		t.Errorf("old cookie not cleared: %+v", c)
	}

	// The current name wins: a wrong value under it is not rescued by a right
	// value under the old name, and the state is single-use.
	l2 := startSignIn(t, app, p)
	right := cookieNamed(l2.cookies, "__Host-omp_oidc_state").Value
	wrong := &http.Cookie{Name: "__Host-omp_oidc_state", Value: strings.Repeat("x", len(right))}
	old := &http.Cookie{Name: "omp_oidc_state", Value: right}
	if res := callbackWith(t, app, l2, wrong, old); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a wrong current cookie with a right old one = %d, want 400", res.StatusCode)
	}
	if res := callbackWith(t, app, l2); res.StatusCode != http.StatusBadRequest {
		t.Errorf("no state cookie = %d, want 400", res.StatusCode)
	}
}

// Over plain http (the development origin) the plain name is kept, and
// the __Host- name (which a browser would not accept there) is still read.
func TestOIDCStateCookieOnPlainHTTP(t *testing.T) {
	app, p := oidcApp(t, nil)
	l := startSignIn(t, app, p)
	c := cookieNamed(l.cookies, "omp_oidc_state")
	if c == nil || c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie = %+v in %v", c, l.cookies)
	}
	if cookieNamed(l.cookies, "__Host-omp_oidc_state") != nil {
		t.Error("the __Host- name was set over http")
	}
	if res := callbackWith(t, app, l, c); res.StatusCode != http.StatusSeeOther || cookieNamed(res.Cookies(), "omp_session") == nil {
		t.Fatalf("callback = %d", res.StatusCode)
	}
	l = startSignIn(t, app, p)
	other := &http.Cookie{Name: "__Host-omp_oidc_state", Value: cookieNamed(l.cookies, "omp_oidc_state").Value}
	if res := callbackWith(t, app, l, other); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback with the other name = %d", res.StatusCode)
	}
}
