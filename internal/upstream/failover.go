package upstream

import (
	"context"
	"errors"
	"strings"
)

const MaxExtraEndpoints = 2

// ExpectedCapability is trusted stored metadata, never an upstream annotation
// or a caller-supplied MCP field. A fallback must advertise this exact offer.
type ExpectedCapability struct{ Kind, Name, Fingerprint string }

func failoverConfiguration(message string) error {
	return &Error{Class: ClassConfig, Reason: "failover_not_supported", Message: message, BeforeDispatch: true}
}

func validateFailoverTarget(t Target) error {
	if len(t.Endpoints) == 0 {
		return nil
	}
	if len(t.Endpoints) > MaxExtraEndpoints || t.TLS != nil || t.Provider != "" || t.ProviderToken != "" || t.BearerToken != "" || t.PersonSecret != "" {
		return failoverConfiguration("Additional endpoints cannot carry provider, personal, OAuth, machine or TLS credentials.")
	}
	ids := map[string]bool{}
	urls := map[string]bool{t.URL: true}
	for _, e := range t.Endpoints {
		if e.ID == "" || e.URL == "" || ids[e.ID] || urls[e.URL] {
			return failoverConfiguration("The additional endpoint configuration is invalid.")
		}
		ids[e.ID], urls[e.URL] = true, true
		if t.IdentityValue != "" && (e.IdentityValue == "" || e.IdentityValue == t.IdentityValue) {
			return failoverConfiguration("Each endpoint needs its own destination-bound identity.")
		}
	}
	return nil
}

// endpointTarget changes only the independently configured network identity.
// Keep all guards, budgets, quota/controller facts and parameter headers, but
// explicitly clear credential families that are never allowed on extras.
func endpointTarget(base Target, e Endpoint) Target {
	t := base
	t.redactionSecrets = base.Secrets()
	t.URL, t.Credentials, t.IdentityHeader, t.IdentityValue = e.URL, e.Credentials, e.IdentityHeader, e.IdentityValue
	t.PersonSecret, t.Provider, t.ProviderToken, t.BearerToken = "", "", "", ""
	t.TLS = nil
	return t
}

func forwardCanRepeat(ctx context.Context, t Target, req ForwardRequest, progress bool, attempt int) bool {
	return ctx.Err() == nil && !t.NoReplay && !progress && attempt < MaxReadRetries &&
		len(strings.TrimSpace(string(req.InputResponses))) == 0 && req.RequestState == ""
}

func mayRetryOrFailover(ctx context.Context, t Target, req ForwardRequest, err error, progress bool, attempt, endpointIndex int) (*Error, bool, bool) {
	if !forwardCanRepeat(ctx, t, req, progress, attempt) {
		return nil, false, false
	}
	var e *Error
	if !errors.As(err, &e) {
		return nil, false, false
	}
	hasNext := endpointIndex+1 < len(t.Endpoints)
	readRetry := req.Retryable && e.retryable
	preRequestSwitch := hasNext && e.preRequest
	if !readRetry && !preRequestSwitch {
		return e, false, false
	}
	return e, true, hasNext
}

func (c *Client) validateFallbackOffer(ctx context.Context, t Target, req ForwardRequest) error {
	x := req.Expected
	if x == nil || x.Name == "" || len(x.Fingerprint) != 64 {
		return &Error{Class: ClassConfig, Reason: "endpoint_definition_unverified", Message: "No trusted capability definition is available for this fallback."}
	}
	validKind := req.Method == MethodToolsCall && x.Kind == KindTool || req.Method == MethodPromptsGet && x.Kind == KindPrompt || req.Method == MethodResourcesRead && (x.Kind == KindResource || x.Kind == KindResourceTemplate)
	if !validKind || (req.Method != MethodResourcesRead && x.Name != req.Name) {
		return &Error{Class: ClassConfig, Reason: "endpoint_definition_unverified", Message: "The fallback does not have a matching trusted offer."}
	}
	d, err := c.Discover(ctx, t)
	if err != nil {
		return err
	}
	for _, cap := range d.Capabilities {
		if cap.Kind == x.Kind && cap.Name == x.Name && cap.Fingerprint == x.Fingerprint {
			return nil
		}
	}
	return &Error{Class: ClassNotAllowed, Reason: "endpoint_definition_mismatch", Message: "The fallback's advertised capability does not match the trusted definition."}
}
