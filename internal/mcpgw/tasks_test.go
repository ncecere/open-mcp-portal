package mcpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

type stubApprovals struct{}

func (stubApprovals) Epoch(context.Context) (int64, error) { return 1, nil }
func (stubApprovals) Begin(context.Context, approvals.BeginInput) (approvals.Plan, error) {
	return approvals.Plan{}, nil
}
func (stubApprovals) CheckContext(context.Context, int64, time.Time) error                { return nil }
func (stubApprovals) CheckUngoverned(context.Context, approvals.Binding, time.Time) error { return nil }
func (stubApprovals) Consume(context.Context, approvals.Plan) error                       { return nil }
func (stubApprovals) CancelBound(context.Context, approvals.BeginInput, uuid.UUID, int64) error {
	return nil
}
func (stubApprovals) URL(uuid.UUID) string { return "" }

func taskCaps(extension string) map[string]json.RawMessage {
	return map[string]json.RawMessage{"extensions": json.RawMessage(`{"` + extension + `":{}}`)}
}

func TestTasksDeclaredRequiresAnObjectOnThisModernRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		modern bool
		caps   map[string]json.RawMessage
		want   bool
	}{
		"declared":              {true, taskCaps(upstream.TasksExtension), true},
		"with unknown settings": {true, map[string]json.RawMessage{"extensions": json.RawMessage(`{"io.modelcontextprotocol/tasks":{"x":1}}`)}, true},
		"legacy request":        {false, taskCaps(upstream.TasksExtension), false},
		"other extension":       {true, taskCaps("io.example/other"), false},
		"no extensions":         {true, map[string]json.RawMessage{}, false},
		"extensions not object": {true, map[string]json.RawMessage{"extensions": json.RawMessage(`["io.modelcontextprotocol/tasks"]`)}, false},
		"null":                  {true, map[string]json.RawMessage{"extensions": json.RawMessage(`{"io.modelcontextprotocol/tasks":null}`)}, false},
		"boolean":               {true, map[string]json.RawMessage{"extensions": json.RawMessage(`{"io.modelcontextprotocol/tasks":true}`)}, false},
	} {
		rc := &request{modern: tc.modern, clientCaps: tc.caps}
		if got := rc.tasksDeclared(); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// reachedReservation runs the negotiation decision and reports whether it got
// past every gate (the zero-value request has no HTTP request, so the first use
// of the context panics: the point where the reservation would begin).
func reachedReservation(rc *request, o gateways.Offer, again retry, target *upstream.Target, fwd *upstream.ForwardRequest, streaming bool) (reached bool, negotiated *taskInit, ok bool) {
	defer func() {
		if recover() != nil {
			reached = true
		}
	}()
	negotiated, ok = rc.negotiateTask(o, json.RawMessage(`{"a":1}`), again, target, fwd, nil, nil, "", streaming, &calls.Call{})
	return false, negotiated, ok
}

func TestNegotiationRequiresEveryConditionAndNeverTouchesGovernedCalls(t *testing.T) {
	good := func() (*request, gateways.Offer, retry, *upstream.Target, *upstream.ForwardRequest) {
		o := gateways.Offer{Selected: gateways.Selected{Capability: dbgen.McpCapability{Kind: upstream.KindTool}, Server: dbgen.McpServer{SupportsTasks: true}}}
		rc := &request{h: &Handler{Tasks: &mcptasks.Store{}, Approvals: stubApprovals{}}, modern: true, clientCaps: taskCaps(upstream.TasksExtension),
			approval: &approvalAttempt{}}
		return rc, o, retry{}, &upstream.Target{Endpoints: []upstream.Endpoint{{ID: "e", URL: "https://x.example"}}}, &upstream.ForwardRequest{}
	}
	if rc, o, again, target, fwd := good(); true {
		if reached, _, _ := reachedReservation(rc, o, again, target, fwd, false); !reached {
			t.Fatal("the baseline did not qualify: the table below would prove nothing")
		}
	}
	for name, mutate := range map[string]func(*request, *gateways.Offer, *retry, *upstream.Target, *upstream.ForwardRequest, *bool){
		"no store": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.h.Tasks = nil
		},
		"no approval runtime": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.h.Approvals = nil
		},
		"client did not declare": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.clientCaps = nil
		},
		"legacy era": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.modern = false
		},
		"server without support": func(_ *request, o *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			o.Server.SupportsTasks = false
		},
		"a prompt": func(_ *request, o *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			o.Capability.Kind = upstream.KindPrompt
		},
		"a resource": func(_ *request, o *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			o.Capability.Kind = upstream.KindResource
		},
		"streamed": func(_ *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, s *bool) {
			*s = true
		},
		"input continuation": func(_ *request, _ *gateways.Offer, a *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			a.relay = &relayState{}
		},
		"input responses": func(_ *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, f *upstream.ForwardRequest, _ *bool) {
			f.InputResponses = json.RawMessage(`{"k":{}}`)
		},
		"request state": func(_ *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, f *upstream.ForwardRequest, _ *bool) {
			f.RequestState = "s"
		},
		"no approval attempt": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.approval = nil
		},
		"governed by a rule": func(rc *request, _ *gateways.Offer, _ *retry, _ *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			rc.approval = &approvalAttempt{plan: approvals.Plan{Required: true}}
		},
		"already no-replay": func(_ *request, _ *gateways.Offer, _ *retry, t *upstream.Target, _ *upstream.ForwardRequest, _ *bool) {
			t.NoReplay = true
		},
	} {
		rc, o, again, target, fwd := good()
		streaming := false
		mutate(rc, &o, &again, target, fwd, &streaming)
		noReplay, endpoints := target.NoReplay, len(target.Endpoints)
		reached, ti, ok := reachedReservation(rc, o, again, target, fwd, streaming)
		if reached || ti != nil || !ok || fwd.Tasks || rc.noResend || target.NoReplay != noReplay || len(target.Endpoints) != endpoints {
			t.Errorf("%s: reached=%v negotiated=%v ok=%v declared=%v", name, reached, ti != nil, ok, fwd.Tasks)
		}
	}
}

func TestDependencyIdentityIgnoresTokensAndTracksConfiguration(t *testing.T) {
	rc := &request{h: &Handler{}}
	provider := registry.Provider{ID: uuid.New(), Slug: "gh", Kind: "platform"}
	connection := uuid.New()
	build := func() (gateways.Offer, *providers.Credential, *personsecrets.Secret, upstream.Target) {
		o := gateways.Offer{Selected: gateways.Selected{Server: dbgen.McpServer{SendIdentity: true, AuthMode: registry.AuthStaticHeader},
			Requires: &registry.Requirement{Provider: provider, Scopes: []string{"b", "a"}}}}
		cred := &providers.Credential{Provider: provider, AccessToken: "token-one", Resource: "https://r.example", ServiceConnectionID: connection, ServiceGeneration: 4}
		secret := &personsecrets.Secret{Value: "secret-one", Placement: "header", Name: "X-Key", Prefix: "Bearer ", ID: uuid.New(), Sealed: []byte("x")}
		target := upstream.Target{Credentials: []upstream.Credential{{Kind: upstream.CredHeader, Name: "X-Tenant", Value: "tenant-one"}}}
		return o, cred, secret, target
	}
	digest := func(mutate func(*gateways.Offer, *providers.Credential, *personsecrets.Secret, *upstream.Target)) string {
		o, c, s, tg := build()
		if mutate != nil {
			mutate(&o, c, s, &tg)
		}
		d, err := rc.dependencyDigest(o, c, s, tg)
		if err != nil || len(d) != 64 {
			t.Fatalf("digest = %q, %v", d, err)
		}
		return d
	}
	base := digest(nil)
	same := map[string]func(*gateways.Offer, *providers.Credential, *personsecrets.Secret, *upstream.Target){
		"a refreshed access token": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.AccessToken = "token-two"
		},
		"a narrowed token": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.Narrowed = true
		},
		"a new connection generation": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.ServiceGeneration++
		},
		"a rotated person secret": func(_ *gateways.Offer, _ *providers.Credential, s *personsecrets.Secret, _ *upstream.Target) {
			s.Value, s.ID, s.Sealed = "secret-two", uuid.New(), nil
		},
		"a rotated static value": func(_ *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, t *upstream.Target) {
			t.Credentials[0].Value = "tenant-two"
		},
		"scope order": func(o *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			o.Requires.Scopes = []string{"a", "b"}
		},
	}
	for name, m := range same {
		if got := digest(m); got != base {
			t.Errorf("%s changed the dependency identity", name)
		}
	}
	different := map[string]func(*gateways.Offer, *providers.Credential, *personsecrets.Secret, *upstream.Target){
		"another provider": func(o *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			o.Requires.Provider.ID, c.Provider.ID = uuid.New(), uuid.New()
		},
		"another scope": func(o *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			o.Requires.Scopes = []string{"a"}
		},
		"another resource": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.Resource = "https://other.example"
		},
		"another shared connection": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.ServiceConnectionID = uuid.New()
		},
		"a personal connection instead of a shared one": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.ServiceConnectionID = uuid.Nil
		},
		"a server-bound sign-in": func(_ *gateways.Offer, c *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			c.Provider.Kind = registry.KindMCPServer
		},
		"a person secret placement": func(_ *gateways.Offer, _ *providers.Credential, s *personsecrets.Secret, _ *upstream.Target) {
			s.Placement = "query"
		},
		"a person secret name": func(_ *gateways.Offer, _ *providers.Credential, s *personsecrets.Secret, _ *upstream.Target) {
			s.Name = "X-Other"
		},
		"a person secret prefix": func(_ *gateways.Offer, _ *providers.Credential, s *personsecrets.Secret, _ *upstream.Target) {
			s.Prefix = ""
		},
		"no person secret": func(_ *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {},
		"another static name": func(_ *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, t *upstream.Target) {
			t.Credentials[0].Name = "X-Other"
		},
		"another static kind": func(_ *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, t *upstream.Target) {
			t.Credentials[0].Kind = upstream.CredQuery
		},
		"another auth mode": func(o *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			o.Server.AuthMode = registry.AuthPersonSecret
		},
		"identity switched off": func(o *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, _ *upstream.Target) {
			o.Server.SendIdentity = false
		},
		"a TLS identity": func(_ *gateways.Offer, _ *providers.Credential, _ *personsecrets.Secret, t *upstream.Target) {
			t.TLS = &upstream.TLSIdentity{}
		},
	}
	seen := map[string]string{base: "base"}
	for name, m := range different {
		if name == "no person secret" {
			o, c, _, tg := build()
			d, _ := rc.dependencyDigest(o, c, nil, tg)
			if d == base || seen[d] != "" {
				t.Errorf("%s kept the identity (or collided with %s)", name, seen[d])
			}
			seen[d] = name
			continue
		}
		d := digest(m)
		if other := seen[d]; other != "" {
			t.Errorf("%s has the same dependency identity as %s", name, other)
		}
		seen[d] = name
	}
}

func TestRedactorScrubsDecodedStringsKeysAndNumbersNotJustBytes(t *testing.T) {
	const id = "task-id/with \"quotes\" & <html> \\ and ünïcode"
	red := newTaskRedactor(id, []string{"Bearer abc.def-123", "tok=a+b/c&d", "id", "ab"})
	// Short credential values are not secrets; the task ID always is.
	if hit := red.text("an id and ab"); hit != "an id and ab" {
		t.Fatalf("short values were treated as secrets: %q", hit)
	}
	raw := json.RawMessage(`{"statusMessage":"saw ` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(id) + ` and Bearer abc.def-123 plus tok%3Da%2Bb%2Fc%26d",` +
		`"` + `task-id/with \"quotes\" & <html> \\ and ünïcode` + `":"key leak",` +
		`"nested":[{"t":"tok=a+b/c&d"},{"n":12345678}],"escaped":"\u003chtml\u003e Bearer abc.def-123"}`)
	out, err := red.json(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"quotes", "abc.def-123", "tok=a+b", "tok%3Da", "ünïcode"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("%q survived: %s", leak, out)
		}
	}
	if !strings.Contains(string(out), "[REDACTED]") || !json.Valid(out) {
		t.Fatalf("bad output: %s", out)
	}
	if !red.clean(out) {
		t.Fatalf("the cleaned output still fails the final gate: %s", out)
	}
	// A number equal to the ID is replaced by a string, never kept.
	numeric := newTaskRedactor("98765432", nil)
	o2, err := numeric.json(json.RawMessage(`{"id":98765432,"other":1}`))
	if err != nil || strings.Contains(string(o2), "98765432") || !strings.Contains(string(o2), `"other":1`) {
		t.Fatalf("numeric ID: %s %v", o2, err)
	}
	// The final gate refuses an encoding that still holds a value, raw or
	// JSON-escaped.
	encodedID, _ := json.Marshal(id)
	if red.clean([]byte(`{"x":"Bearer abc.def-123"}`)) || red.clean([]byte(`{"x":`+string(encodedID)+`}`)) || red.clean([]byte(id)) {
		t.Fatal("the final gate accepted a leak")
	}
	if _, err := red.json(json.RawMessage(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := red.json(json.RawMessage(`{`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestRedactionValuesAreBoundedBeforeSealing(t *testing.T) {
	if got, ok := validRedactionValues([]string{"", "abc", "long-enough", "long-enough", "another-value"}); !ok || len(got) != 2 {
		t.Fatalf("dedupe/short filter: %v %v", got, ok)
	}
	if _, ok := validRedactionValues([]string{string([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb})}); ok {
		t.Fatal("invalid UTF-8 was accepted")
	}
	many := make([]string, mcptasks.MaxRedactionSecrets+1)
	for i := range many {
		many[i] = strings.Repeat("x", 8) + string(rune('a'+i%26)) + strings.Repeat("y", i)
	}
	if _, ok := validRedactionValues(many); ok {
		t.Fatal("too many values were accepted")
	}
	if _, ok := validRedactionValues([]string{strings.Repeat("z", mcptasks.MaxRedactionSecretBytes+1)}); ok {
		t.Fatal("an oversized value was accepted")
	}
}

func TestTaskNameHeaderMustEqualTheTaskID(t *testing.T) {
	ok := validateTaskName(http.Header{"Mcp-Name": {"omptask_a"}}, json.RawMessage(`{"taskId":"omptask_a"}`))
	if ok != nil {
		t.Fatalf("matching name refused: %v", ok)
	}
	for name, tc := range map[string]struct {
		h http.Header
		p string
	}{
		"missing":   {http.Header{}, `{"taskId":"omptask_a"}`},
		"different": {http.Header{"Mcp-Name": {"omptask_b"}}, `{"taskId":"omptask_a"}`},
		"encoded":   {http.Header{"Mcp-Name": {"=?base64?!!!?="}}, `{"taskId":"omptask_a"}`},
		"control":   {http.Header{"Mcp-Name": {"a\x01"}}, `{"taskId":"a"}`},
	} {
		err := validateTaskName(tc.h, json.RawMessage(tc.p))
		if err == nil || err.status != http.StatusBadRequest || err.code != codeHeaderMismatch || strings.Contains(err.message, "omptask_") {
			t.Errorf("%s: %+v", name, err)
		}
	}
	if b64 := validateTaskName(http.Header{"Mcp-Name": {"=?base64?" + "b21wdGFza19h" + "?="}}, json.RawMessage(`{"taskId":"omptask_a"}`)); b64 != nil {
		t.Fatalf("base64 form of the same handle refused: %v", b64)
	}
}
