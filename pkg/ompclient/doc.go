// Package ompclient is a Go client for the operations of the Open MCP Portal
// management API (/v1) that accept automation tokens (docs/automation-tokens.md):
// the platform-admin tokens (ompadm_) and team publisher tokens (omppub_).
//
// The code is generated from api/openapi.yaml; nothing in ompclient.gen.go is
// edited by hand. Only operations annotated with x-omp-token-scopes are
// included, because they are the only ones a token may call; the browser-session
// operations are not part of this package.
//
// Stability: this package is versioned v0. It follows the API contract, which
// can still change before 1.0 (see CHANGELOG.md), so pin a release and expect to
// regenerate and adapt on upgrades. The CLI in cmd/omp is built on it.
//
//	c, _ := ompclient.NewClientWithResponses("https://portal.example.com",
//		ompclient.WithBearerToken(os.Getenv("OMP_TOKEN")))
//	res, err := c.GetTokenWithResponse(ctx)
package ompclient

import (
	"context"
	"net/http"
)

// WithBearerToken sends "Authorization: Bearer <token>" with every request.
// Pass an automation token (ompadm_ or omppub_). The token is only ever sent
// to the server URL the client was created with.
func WithBearerToken(token string) ClientOption {
	return WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	})
}
