package testutil

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// clientOK authenticates the client of a token or revocation request and
// returns its ID.
func (f *FakeOAuth) clientOK(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if want, ok := f.clients[id]; ok {
		return id, want == "" || secret == want
	}
	if f.CIMD && id != f.ClientID && (strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://")) {
		return id, true // a public client identified by its metadata document
	}
	return id, id == f.ClientID && (f.ClientSecret == "" || secret == f.ClientSecret)
}

func (f *FakeOAuth) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "fake provider says no"})
}

func (f *FakeOAuth) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	f.mu.Lock()
	f.tokens++
	f.resources = append(f.resources, r.PostForm.Get("resource"))
	rejectResource, beforeToken := f.RejectResource, f.BeforeToken
	f.mu.Unlock()
	if beforeToken != nil {
		beforeToken(r.PostForm.Get("grant_type"))
	}
	clientID, ok := f.clientOK(r)
	if r.PostForm.Get("grant_type") == "client_credentials" {
		f.recordClientCredentials(r, clientID, ok)
	}
	if !ok {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if rejectResource && r.PostForm.Get("resource") != "" {
		f.fail(w, http.StatusBadRequest, "invalid_target")
		return
	}
	var scopes []string
	resource := r.PostForm.Get("resource")
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.mu.Lock()
		hook := f.BeforeCodeExchange
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		f.mu.Lock()
		c, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		if !ok || c.redirectURI != r.PostForm.Get("redirect_uri") || c.clientID != clientID ||
			(c.resource != "" && resource != "" && c.resource != resource) {
			f.fail(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		if resource == "" {
			resource = c.resource
		}
		if c.challenge != "" {
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
				f.fail(w, http.StatusBadRequest, "invalid_grant")
				return
			}
		}
		scopes = c.scopes
	case "refresh_token":
		f.mu.Lock()
		f.refreshs++
		f.refreshScopes = append(f.refreshScopes, r.PostForm.Get("scope"))
		delay, failMode := f.RefreshDelay, f.FailRefresh
		f.mu.Unlock()
		time.Sleep(delay)
		switch failMode {
		case "invalid_grant", "invalid_scope":
			f.fail(w, http.StatusBadRequest, failMode)
			return
		case "unavailable":
			http.Error(w, "upstream down", http.StatusServiceUnavailable)
			return
		}
		f.mu.Lock()
		rt := r.PostForm.Get("refresh_token")
		g, ok := f.refresh[rt]
		if ok && f.RotateRefresh {
			delete(f.refresh, rt)
		}
		f.mu.Unlock()
		if !ok || g.clientID != clientID {
			f.fail(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		scopes = g.scopes
		if resource == "" {
			resource = g.resource
		}
		f.mu.Lock()
		honour := f.HonourRefreshScope
		if f.RefreshGrantedScopes != nil {
			scopes = slices.Clone(f.RefreshGrantedScopes)
		}
		f.mu.Unlock()
		if want := strings.FieldsFunc(r.PostForm.Get("scope"), func(r rune) bool { return r == ' ' || r == ',' }); honour && len(want) > 0 {
			for _, sc := range want {
				if !slices.Contains(g.scopes, sc) {
					f.fail(w, http.StatusBadRequest, "invalid_scope")
					return
				}
			}
			f.issue(w, r, fakeGrant{scopes: want, resource: resource, clientID: clientID}, g)
			return
		}
	case "client_credentials":
		f.clientCredentials(w, r, clientID, resource)
		return
	default:
		f.fail(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	g := fakeGrant{scopes: scopes, resource: resource, clientID: clientID}
	f.issue(w, r, g, g)
}

// issue answers with a new access token for g (and a refresh token for rg,
// which differs from g when a refresh narrowed the access token).
func (f *FakeOAuth) issue(w http.ResponseWriter, r *http.Request, g, rg fakeGrant) {
	scopes := g.scopes
	f.mu.Lock()
	access := fakeToken("fat_")
	f.access[access] = g
	if f.AccessTTL > 0 {
		f.expires[access] = time.Now().Add(f.AccessTTL)
	}
	f.issued = append(f.issued, access)
	out := map[string]any{"access_token": access, "token_type": "bearer"}
	if f.AccessTTL > 0 {
		out["expires_in"] = int64(f.AccessTTL / time.Second)
	}
	refresh := ""
	if f.IssueRefresh {
		refresh = r.PostForm.Get("refresh_token")
		if refresh == "" || f.RotateRefresh {
			refresh = fakeToken("frt_")
		}
		f.refresh[refresh] = rg
		f.issuedRT = append(f.issuedRT, refresh)
		out["refresh_token"] = refresh
	}
	if !f.OmitScope {
		out["scope"] = strings.Join(scopes, " ")
	}
	form, slack := f.FormEncoded, f.Slack
	f.mu.Unlock()
	switch {
	case slack:
		if s, ok := out["scope"].(string); ok {
			out["scope"] = strings.ReplaceAll(s, " ", ",")
		}
		out["token_type"] = "user"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "access_token": "xoxb-bot-not-for-people", "token_type": "bot",
			"authed_user": out})
	case form:
		v := url.Values{}
		for k, val := range out {
			v.Set(k, fmt.Sprint(val))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte(v.Encode()))
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *FakeOAuth) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if _, ok := f.clientOK(r); !ok {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	f.mu.Lock()
	before, fail := f.BeforeRevoke, f.FailRevoke
	f.mu.Unlock()
	if before != nil {
		before()
	}
	if fail {
		f.fail(w, http.StatusServiceUnavailable, "revocation_unavailable")
		return
	}
	token := r.PostForm.Get("token")
	f.mu.Lock()
	f.revoked = append(f.revoked, token)
	delete(f.access, token)
	if _, ok := f.refresh[token]; ok {
		delete(f.refresh, token)
		// Revoking a refresh token ends its access tokens too (as Google does).
		for k := range f.access {
			delete(f.access, k)
		}
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *FakeOAuth) userinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	failing, login := f.FailUserinfo, f.Login
	_, ok := f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	switch {
	case failing:
		http.Error(w, "userinfo down", http.StatusInternalServerError)
	case !ok:
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": login, "sub": "fake-" + login})
	}
}

// TokenDigest is the hex SHA-256 prefix of a token that the fake MCP
// server's provider_token tool reports (never the token itself).
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

// recordClientCredentials notes a client credentials request.
func (f *FakeOAuth) recordClientCredentials(r *http.Request, clientID string, ok bool) {
	method := "none"
	secret := r.PostForm.Get("client_secret")
	if _, sec, basic := r.BasicAuth(); basic {
		method = "basic"
		secret, _ = url.QueryUnescape(sec)
	} else if secret != "" {
		method = "post"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.machine = append(f.machine, ClientCredentialsRequest{ClientAuth: method, ClientID: clientID, ClientSecret: secret,
		Scope: r.PostForm.Get("scope"), Audience: r.PostForm.Get("audience"), Resource: r.PostForm.Get("resource"), Authorized: ok})
}

// ClientCredentialsRequests are the client credentials grant requests so
// far, in order.
func (f *FakeOAuth) ClientCredentialsRequests() []ClientCredentialsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ClientCredentialsRequest(nil), f.machine...)
}

// clientCredentials answers the client credentials grant for an authenticated
// client: an access token (no refresh token) for the scopes asked for.
func (f *FakeOAuth) clientCredentials(w http.ResponseWriter, r *http.Request, clientID, resource string) {
	f.mu.Lock()
	off, fail, allowed, delay := f.NoClientCredentials, f.FailClientCredentials, append([]string(nil), f.MachineScopes...), f.TokenDelay
	f.mu.Unlock()
	time.Sleep(delay)
	switch {
	case off:
		f.fail(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	case fail == "invalid_client":
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	case fail == "unavailable":
		http.Error(w, "authorization server down", http.StatusServiceUnavailable)
		return
	case fail == "invalid_response":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
		return
	}
	want := strings.Fields(r.PostForm.Get("scope"))
	for _, sc := range want {
		if len(allowed) > 0 && !slices.Contains(allowed, sc) {
			f.fail(w, http.StatusBadRequest, "invalid_scope")
			return
		}
	}
	if len(want) == 0 {
		want = allowed
	}
	if want == nil {
		want = []string{}
	}
	f.mu.Lock()
	access := fakeToken("fmt_")
	f.access[access] = fakeGrant{scopes: want, resource: resource, clientID: clientID}
	if f.AccessTTL > 0 {
		f.expires[access] = time.Now().Add(f.AccessTTL)
	}
	f.issued = append(f.issued, access)
	out := map[string]any{"access_token": access, "token_type": "bearer"}
	if fail == "wrong_type" {
		out["token_type"] = "DPoP"
	}
	if f.AccessTTL > 0 {
		out["expires_in"] = int64(f.AccessTTL / time.Second)
	}
	if !f.OmitScope {
		out["scope"] = strings.Join(want, " ")
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
