package mcpgw

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// captureCall starts capturing a call about to be forwarded when its
// gateway or its server captures payloads (docs/phase6-operations.md
// "Payload capture"). args are the call's arguments (or {"uri": ...} for a
// read). The values the gateway handles for the call (the identity token,
// the provider token, the server's credential parts and the client's own
// credential) are redacted wherever they appear; they are never stored.
func (rc *request) captureCall(o gateways.Offer, args []byte, target upstream.Target, token string, cred *providers.Credential) {
	rc.forwarded = true
	if rc.h.Capture == nil || !(rc.gateway.CapturePayloads || o.Server.CapturePayloads) {
		return
	}
	args = bytes.TrimSpace(args)
	if len(args) == 0 || bytes.Equal(args, []byte("null")) {
		args = []byte("{}")
	}
	// Every part of the server's own credential, the base64 form of Basic and
	// the identity token (target.Secrets), and the token as signed.
	secrets := append([]string{token}, target.Secrets()...)
	if _, bearer, ok := strings.Cut(rc.r.Header.Get("Authorization"), " "); ok {
		secrets = append(secrets, strings.TrimSpace(bearer))
	}
	if cred != nil {
		secrets = append(secrets, cred.AccessToken, cred.Provider.Slug+" "+cred.AccessToken, "Bearer "+cred.AccessToken)
	}
	rc.capture = &capture.Input{
		ByGateway: rc.gateway.CapturePayloads, ByServer: o.Server.CapturePayloads,
		GatewayTeamID: rc.gateway.TeamID, ServerTeamID: uuid.NullUUID{UUID: o.Server.TeamID, Valid: o.Server.TeamID != uuid.Nil},
		Arguments: append([]byte(nil), args...), Secrets: secrets,
	}
}

// captureResult is what the client received: the result, or the server's
// JSON-RPC error.
func (rc *request) captureResult(b []byte) {
	if rc.capture != nil {
		rc.capture.Result = b
	}
}

// captureError keeps a server's JSON-RPC error as the result.
func (rc *request) captureError(code int64, message string) {
	if rc.capture != nil {
		b, err := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": message}})
		if err == nil {
			rc.capture.Result = b
		}
	}
}

func readArguments(uri string) []byte {
	b, _ := json.Marshal(map[string]string{"uri": uri})
	return b
}
