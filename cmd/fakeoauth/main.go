// Command fakeoauth runs a fake third-party OAuth 2.0 provider for local
// development of delegated credentials (docs/phase5-delegated-credentials.md):
//
//	go run ./cmd/fakeoauth                  # http://127.0.0.1:8092
//	go run ./cmd/fakeoauth -ttl 2m          # short-lived access tokens, to watch refreshes
//	go run ./cmd/fakeoauth -ttl 2m -honour-refresh-scope   # a refresh's scope narrows the token (narrowOnRefresh)
//
// It serves GET /authorize (a page with Approve and Deny; -auto approves at
// once), POST /token (authorization_code with optional PKCE S256, and
// refresh_token with rotation), POST /revoke (RFC 7009) and GET /userinfo
// ({"login": ...}), with the logic of testutil.FakeOAuth. Register it in
// Admin › Auth providers with DEV_AUTH on a loopback APP_URL (which allows
// plain http to loopback addresses):
//
//	Authorization URL  http://127.0.0.1:8092/authorize
//	Token URL          http://127.0.0.1:8092/token
//	Revocation URL     http://127.0.0.1:8092/revoke
//	Userinfo URL       http://127.0.0.1:8092/userinfo
//	Client ID / secret fake-client / fake-secret-0123456789 (-client-id, -client-secret)
//
// As the authorization server of an OAuth-protected MCP server (Phase 7,
// docs/phase7-upstream-oauth.md) it also serves RFC 8414 metadata, POST
// /introspect (for `fakemcp -protect`), records the resource parameter and
// binds tokens to it:
//
//	go run ./cmd/fakeoauth -dcr                          # metadata at /.well-known/oauth-authorization-server, /register
//	go run ./cmd/fakeoauth -issuer-path /login/oauth -no-dcr   # like GitHub: path-insertion metadata only, iss, no DCR
//	go run ./cmd/fakeoauth -cimd -reject-resource
//
// Tokens are logged only as a digest prefix.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8092", "listen address")
	clientID := flag.String("client-id", "fake-client", "the registered client ID")
	clientSecret := flag.String("client-secret", "fake-secret-0123456789", "the client secret (empty: a public client)")
	ttl := flag.Duration("ttl", time.Hour, "access token lifetime (0: tokens don't expire)")
	auto := flag.Bool("auto", false, "approve every authorization without showing a page")
	rotate := flag.Bool("rotate", true, "rotate refresh tokens on every use")
	login := flag.String("login", "octocat", "the account name /userinfo reports")
	issuerPath := flag.String("issuer-path", "", "the issuer's path, for example /login/oauth (metadata only at the RFC 8414 path-insertion URL)")
	dcr := flag.Bool("dcr", false, "offer dynamic client registration (POST /register)")
	noDCR := flag.Bool("no-dcr", false, "no dynamic client registration (the GitHub case; overrides -dcr)")
	cimd := flag.Bool("cimd", false, "say client ID metadata documents are supported")
	rejectResource := flag.Bool("reject-resource", false, "refuse requests with a resource parameter (invalid_target)")
	iss := flag.Bool("iss", true, "send iss in authorization responses (RFC 9207) and say so in the metadata")
	scopes := flag.String("scopes", "repo read:user write", "scopes_supported in the metadata (space-separated)")
	honourRefreshScope := flag.Bool("honour-refresh-scope", false, "let a refresh request's scope narrow the new access token (RFC 6749 section 6, like Microsoft)")
	flag.Parse()

	f, h := testutil.NewFakeOAuthHandler(*clientID, *clientSecret)
	f.Set(func(f *testutil.FakeOAuth) {
		f.AccessTTL, f.AutoApprove, f.RotateRefresh, f.Login = *ttl, *auto, *rotate, *login
		f.IssuerPath, f.DCR, f.CIMD, f.RejectResource, f.IssParam = *issuerPath, *dcr && !*noDCR, *cimd, *rejectResource, *iss
		f.ScopesSupported = strings.Fields(*scopes)
		f.HonourRefreshScope = *honourRefreshScope
	})
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
	log.Printf("fake OAuth provider on http://%s (client %s, issuer http://%s%s)", *addr, *clientID, *addr, *issuerPath)
	srv := &http.Server{Addr: *addr, Handler: logged, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
