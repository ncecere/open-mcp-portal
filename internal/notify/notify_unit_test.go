package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	key, err := secrets.ParseKey("94cwGQfaKGZdfF4A04/lGwT/LMSckeFIpgC3FO3lnm8=")
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// unitService is a service with no database: enough for URL checks and
// webhook delivery.
func unitService(t *testing.T, client *upstream.Client) *Service {
	t.Helper()
	return &Service{box: testBox(t), client: client, log: testutil.Logger(), now: time.Now,
		cfg: Config{AppURL: "https://portal.example.com", InstanceName: "Open MCP Portal", Version: "test"}}
}

func entries(t *testing.T, list string) []netpolicy.Entry {
	t.Helper()
	e, err := netpolicy.ParseList(list)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSignAndVerify(t *testing.T) {
	body := []byte(`{"id":"1","type":"server.unhealthy"}`)
	now := time.Unix(1_800_000_000, 0)
	h := SignatureHeader(now.Unix(), body, "ompwhs_new", "ompwhs_old")
	if strings.Count(h, "v1=") != 2 || !strings.HasPrefix(h, "v1=") {
		t.Fatalf("a rotation signs with both secrets: %q", h)
	}
	for _, secret := range []string{"ompwhs_new", "ompwhs_old"} {
		if !Verify(secret, h, now.Unix(), body, now, 5*time.Minute) {
			t.Errorf("%s should verify", secret)
		}
	}
	if Verify("ompwhs_other", h, now.Unix(), body, now, 5*time.Minute) {
		t.Error("another secret verified")
	}
	if Verify("ompwhs_new", h, now.Unix(), append(body, ' '), now, 5*time.Minute) {
		t.Error("a changed body verified")
	}
	if Verify("ompwhs_new", h, now.Unix()+1, body, now, 5*time.Minute) {
		t.Error("a changed timestamp verified")
	}
	if Verify("ompwhs_new", h, now.Unix(), body, now.Add(6*time.Minute), 5*time.Minute) {
		t.Error("a stale timestamp (a replay) verified")
	}
	// Only the first v1 is the new secret; one value is the normal case.
	if one := SignatureHeader(now.Unix(), body, "ompwhs_new"); strings.Contains(one, ",") || Sign("ompwhs_new", now.Unix(), body) != strings.TrimPrefix(one, "v1=") {
		t.Errorf("single signature: %q", one)
	}
	// The signed string is timestamp, a dot and the raw body.
	if Sign("k", 5, []byte("x")) == Sign("k", 5, []byte("y")) || Sign("k", 5, []byte("x")) == Sign("k", 6, []byte("x")) {
		t.Error("signature must cover the timestamp and the body")
	}
}

func TestRetrySchedule(t *testing.T) {
	want := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}
	if MaxAttempts != 6 || len(retryDelays) != len(want) {
		t.Fatalf("6 attempts, 5 waits: got %d attempts, %d waits", MaxAttempts, len(retryDelays))
	}
	for i, d := range want {
		if retryDelays[i] != d {
			t.Errorf("wait %d = %s, want %s", i+1, retryDelays[i], d)
		}
	}
	if StopAfter != 20 || EmailsPerHour != 30 || ExpireAfter != 24*time.Hour || MaxDestinations != 10 {
		t.Error("limits of the design changed")
	}
}

func TestCheckURL(t *testing.T) {
	s := unitService(t, NewWebhookClient(nil, nil))
	reason := func(err error) string {
		e, ok := apperr.As(err)
		if !ok || e.Code != "url_not_allowed" || e.Status != 422 {
			return "NOT url_not_allowed: " + strconv.Quote(errString(err))
		}
		return e.Details.(map[string]any)["reason"].(string)
	}
	ok := []string{
		"https://hooks.slack.com/services/T000/B000/XXXX",
		"https://example.com/hook?token=abc",
		"https://8.8.8.8/hook",
		"https://[2606:4700:4700::1111]/hook",
	}
	for _, u := range ok {
		if err := s.CheckURL(context.Background(), u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	refused := map[string]string{
		"http://example.com/hook":                          "scheme",
		"ftp://example.com/hook":                           "scheme",
		"https://user:pw@example.com/hook":                 "userinfo",
		"https://example.com/hook#frag":                    "fragment",
		"https://example.com/" + strings.Repeat("a", 1001): "too_long",
		"not a url":              "invalid",
		"https:///nohost":        "invalid",
		"https://127.0.0.1/hook": "blocked_address",
		"https://169.254.169.254/latest/meta-data": "blocked_address",
		"https://[::1]/hook":                       "blocked_address",
		"https://[fe80::1]/hook":                   "blocked_address",
		"https://[::ffff:127.0.0.1]/hook":          "blocked_address", // IPv4-mapped loopback
		"https://[::ffff:10.0.0.1]/hook":           "private_address", // IPv4-mapped private
		"https://[64:ff9b::7f00:1]/hook":           "blocked_address", // NAT64 of 127.0.0.1
		"https://[64:ff9b::a00:1]/hook":            "private_address", // NAT64 of 10.0.0.1
		"https://[::7f00:1]/hook":                  "blocked_address", // IPv4-compatible
		"https://10.0.0.5/hook":                    "private_address",
		"https://192.168.1.1/hook":                 "private_address",
		"https://100.64.0.1/hook":                  "private_address",
		"https://localhost/hook":                   "blocked_address",
		"https://app.localhost/hook":               "blocked_address",
		"https://0x7f.1/hook":                      "private_address", // alternative notation
		"https://2130706433/hook":                  "private_address", // decimal
		"https://168.63.129.16/hook":               "blocked_address", // Azure wire server
		"https://[fd00:ec2::254]/hook":             "blocked_address", // AWS IMDS over IPv6
	}
	for u, want := range refused {
		if got := reason(s.CheckURL(context.Background(), u)); got != want {
			t.Errorf("%.60s: reason %q, want %q", u, got, want)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// Webhook URLs never use the MCP servers' allowlist: only the operator's own
// NOTIFY_WEBHOOK_ALLOWED_NETWORKS opens an internal address, and loopback,
// link-local and metadata stay shut whatever it says.
func TestCheckURLOperatorAllowlist(t *testing.T) {
	// Loopback, link-local and metadata can't even be listed.
	for _, bad := range []string{"127.0.0.0/8", "169.254.0.0/16", "localhost"} {
		if _, err := netpolicy.ParseList(bad); err == nil {
			t.Errorf("%s was accepted as an allowlist entry", bad)
		}
	}
	s := unitService(t, NewWebhookClient(entries(t, "10.20.0.0/16,http:*.hooks.internal"), nil))
	for _, u := range []string{"https://10.20.1.2/hook", "http://a.hooks.internal/hook", "https://a.hooks.internal/hook"} {
		if err := s.CheckURL(context.Background(), u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://10.20.1.2/hook", "https://10.21.0.1/hook", "https://127.0.0.1/hook", "https://169.254.169.254/x"} {
		if s.CheckURL(context.Background(), u) == nil {
			t.Errorf("%s was accepted", u)
		}
	}
	if NewWebhookClient(nil, nil).AllowPrivate {
		t.Error("there is no development allowance for webhooks")
	}
}

func dest(t *testing.T, s *Service, format, rawURL string, previous ...string) dbgen.NotificationDestination {
	t.Helper()
	id := uuid.New()
	d := dbgen.NotificationDestination{ID: id, Format: format, Scope: "team", Events: []string{ServerUnhealthy}}
	var err error
	if d.UrlCipher, err = s.box.Seal([]byte(rawURL), URLAAD(id)); err != nil {
		t.Fatal(err)
	}
	if format == "json" {
		if d.SecretCipher, err = s.box.Seal([]byte("ompwhs_current"), SecretAAD(id)); err != nil {
			t.Fatal(err)
		}
		if len(previous) > 0 {
			until := time.Now().Add(time.Hour)
			d.SecretPreviousCipher, _ = s.box.Seal([]byte(previous[0]), PreviousSecretAAD(id))
			d.SecretPreviousUntil = &until
		}
	}
	return d
}

// reach points an allowlisted literal address at a local test server.
func reach(t *testing.T, srv *httptest.Server) (*upstream.Client, string) {
	t.Helper()
	c := NewWebhookClient(entries(t, "http:10.0.0.0/8"), nil)
	addr := srv.Listener.Addr().String()
	c.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return c, "http://10.9.9.9:8080/hook"
}

func TestSendWebhookSignsAndKeepsNothingOfTheAnswer(t *testing.T) {
	const sentinel = "RESPONSE-BODY-SENTINEL"
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(sentinel))
	}))
	defer srv.Close()
	client, raw := reach(t, srv)
	s := unitService(t, client)
	d := dest(t, s, "json", raw, "ompwhs_previous")
	eventID := uuid.New()
	res := s.sendWebhook(context.Background(), d, ServerUnhealthy, eventID, 77, 2, []byte(`{"hello":"world"}`))
	if res.OK || res.Class != ClassRejected || !res.Permanent || res.Status != 400 {
		t.Fatalf("a 400 is a permanent rejection: %+v", res)
	}
	if strings.Contains(res.Message, sentinel) || strings.Contains(explain(res), sentinel) {
		t.Error("the destination's response body reached the result")
	}
	if got.Get("Content-Type") != "application/json" || got.Get(HeaderEvent) != ServerUnhealthy || got.Get(HeaderEventID) != eventID.String() ||
		got.Get(HeaderDelivery) != "77" || got.Get(HeaderAttempt) != "2" || got.Get("User-Agent") != "open-mcp-portal/test" {
		t.Errorf("headers = %v", got)
	}
	ts, _ := strconv.ParseInt(got.Get(HeaderTimestamp), 10, 64)
	sig := got.Get(HeaderSignature)
	if strings.Count(sig, "v1=") != 2 {
		t.Fatalf("signature %q should carry the current and the previous secret", sig)
	}
	for _, secret := range []string{"ompwhs_current", "ompwhs_previous"} {
		if !Verify(secret, sig, ts, body, time.Now(), 5*time.Minute) {
			t.Errorf("receiver can't verify with %s", secret)
		}
	}
	// A slack destination is unsigned; the other headers still go.
	sd := dest(t, s, "slack", raw)
	got = nil
	if r := s.sendWebhook(context.Background(), sd, ServerUnhealthy, eventID, 1, 1, slackBody("hi")); r.Class != ClassRejected {
		t.Fatalf("%+v", r)
	}
	if got.Get(HeaderSignature) != "" || got.Get(HeaderTimestamp) != "" || got.Get(HeaderEvent) == "" {
		t.Errorf("slack headers = %v", got)
	}
}

func TestSendWebhookStatusClasses(t *testing.T) {
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer srv.Close()
	client, raw := reach(t, srv)
	s := unitService(t, client)
	d := dest(t, s, "slack", raw)
	for code, want := range map[int]result{
		200: {OK: true, Status: 200},
		204: {OK: true, Status: 204},
		400: {Class: ClassRejected, Permanent: true, Status: 400},
		404: {Class: ClassRejected, Permanent: true, Status: 404},
		408: {Class: ClassRejected, Status: 408}, // retried
		429: {Class: ClassRejected, Status: 429}, // retried
		500: {Class: ClassServerError, Status: 500},
		503: {Class: ClassServerError, Status: 503},
	} {
		status.Store(int32(code))
		got := s.sendWebhook(context.Background(), d, ServerUnhealthy, uuid.New(), 1, 1, slackBody("x"))
		if got.OK != want.OK || got.Class != want.Class || got.Permanent != want.Permanent || got.Status != want.Status {
			t.Errorf("%d: %+v, want %+v", code, got, want)
		}
	}
}

// Redirects are never followed (a 3xx is not_allowed), however harmless the
// target looks.
func TestSendWebhookNeverFollowsRedirects(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://10.9.9.9:8080/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	client, raw := reach(t, srv)
	s := unitService(t, client)
	res := s.sendWebhook(context.Background(), dest(t, s, "slack", raw), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x"))
	if res.OK || res.Class != ClassNotAllowed || hits.Load() != 1 {
		t.Errorf("redirect: %+v after %d request(s)", res, hits.Load())
	}
}

// A host that resolves to a blocked address (rebinding) is refused at dial
// time, and a URL that stopped being allowed since it was saved is refused at
// send time, without a request.
func TestSendWebhookRechecksAtEverySend(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	for name, resolved := range map[string]string{"loopback": "127.0.0.1", "metadata": "169.254.169.254", "private": "10.1.2.3", "mapped": "::ffff:127.0.0.1"} {
		c := NewWebhookClient(nil, nil)
		c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(resolved)}, nil
		}
		c.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		s := unitService(t, c)
		res := s.sendWebhook(context.Background(), dest(t, s, "slack", "https://rebind.example.com/hook"), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x"))
		if res.OK || res.Class != ClassNotAllowed {
			t.Errorf("%s rebinding: %+v", name, res)
		}
	}
	// A multi-address answer with one blocked address is refused as a whole.
	c := NewWebhookClient(nil, nil)
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	s := unitService(t, c)
	if res := s.sendWebhook(context.Background(), dest(t, s, "slack", "https://mixed.example.com/hook"), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x")); res.Class != ClassNotAllowed {
		t.Errorf("mixed answer: %+v", res)
	}
	// Plain http without an allowlist entry; an internal literal address; a
	// stored URL that is loopback.
	for _, u := range []string{"http://example.com/hook", "https://10.0.0.5/hook", "https://127.0.0.1:1/hook", "https://169.254.169.254/x"} {
		if res := s.sendWebhook(context.Background(), dest(t, s, "slack", u), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x")); res.Class != ClassNotAllowed {
			t.Errorf("%s: %+v", u, res)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d request(s) reached the target", hits.Load())
	}
}

// An unreachable destination is classified, never quoted: the result has the
// fixed class and message only.
func TestSendWebhookErrorsDontQuoteTheURL(t *testing.T) {
	c := NewWebhookClient(nil, nil)
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	c.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrUnexpectedEOF }
	s := unitService(t, c)
	secretPath := "/services/T0SENTINEL/B1SENTINEL/XSECRETSENTINEL"
	res := s.sendWebhook(context.Background(), dest(t, s, "slack", "https://hooks.example.com"+secretPath+"?key=QUERYSENTINEL"), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x"))
	if res.Class != ClassConnect || res.OK {
		t.Fatalf("%+v", res)
	}
	for _, text := range []string{res.Message, explain(res), res.Class} {
		if strings.Contains(text, "SENTINEL") || strings.Contains(text, "hooks.example.com") {
			t.Errorf("the URL leaked: %q", text)
		}
	}
	if d := display("https://hooks.example.com" + secretPath + "?key=x"); d != "https://hooks.example.com/..." {
		t.Errorf("display = %q", d)
	}
}

func TestComposeHostileText(t *testing.T) {
	s := unitService(t, nil)
	hostile := "Evil\r\n<!channel> <https://evil.example|click> @here &amp; \"quoted\" " + strings.Repeat("x", 400)
	data, _ := json.Marshal(apitypes.ServerUnhealthyData{Server: serverRef(uuid.New(), "evil", hostile), Since: time.Now(), ConsecutiveFailures: 3})
	ev := dbgen.NotificationEvent{ID: 1, PublicID: uuid.New(), Event: ServerUnhealthy, Payload: data, OccurredAt: time.Now()}
	team := &teamInfo{ID: uuid.New(), Slug: "ops", Name: "Ops"}
	msg := compose(ev, team)
	if strings.ContainsAny(msg.Title+msg.Body, "\r\n") || len([]rune(msg.Title)) > 200 || len([]rune(msg.Body)) > 500 {
		t.Errorf("title/body must be one line and bounded: %q", msg.Title)
	}
	if !strings.Contains(msg.Title, `Server "`) {
		t.Errorf("user text should be delimited: %q", msg.Title)
	}
	text := s.slackText(msg)
	for _, bad := range []string{"<!channel>", "<https://evil.example", "@here", "&amp; "} {
		if strings.Contains(text, bad) {
			t.Errorf("slack text contains %q: %q", bad, text)
		}
	}
	if strings.Count(text, "<") != 1 || !strings.HasSuffix(text, "|Open>") || !strings.Contains(text, "<https://portal.example.com/teams/ops/servers/") {
		t.Errorf("the only link is the portal's: %q", text)
	}
	if len([]rune(text)) > 3000 {
		t.Error("slack text too long")
	}
	body := slackBody(text)
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil || m["text"] != text || len(m) != 1 {
		t.Errorf("slack body: %s", body)
	}
}

func TestPayloadShapeAndBound(t *testing.T) {
	s := unitService(t, nil)
	team := &teamInfo{ID: uuid.New(), Slug: "ops", Name: "Ops"}
	d := apitypes.CapabilityChangedData{Server: serverRef(uuid.New(), "srv", "Server"), Held: true}
	for i := 0; i < 10; i++ {
		d.Capabilities = append(d.Capabilities, struct {
			Change apitypes.CapabilityChangedDataCapabilitiesChange `json:"change"`
			Kind   apitypes.CapabilityChangedDataCapabilitiesKind   `json:"kind"`
			Name   string                                           `json:"name"`
		}{Change: "changed", Kind: "tool", Name: clip(strings.Repeat("n", 300), 100)})
	}
	d.ChangedCount, d.MoreCount = 10, 5
	raw, _ := json.Marshal(d)
	ev := dbgen.NotificationEvent{ID: 9, PublicID: uuid.New(), Event: CapabilityChanged, Payload: raw, OccurredAt: time.Now()}
	body, err := s.payload(ev, team, compose(ev, team))
	if err != nil || len(body) > 8192 {
		t.Fatalf("payload %d bytes, err %v", len(body), err)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "type", "version", "occurredAt", "instance", "team", "url", "data"} {
		if _, ok := env[k]; !ok {
			t.Errorf("payload lacks %q", k)
		}
	}
	if len(env) != 8 {
		t.Errorf("payload has extra fields: %v", env)
	}
	// Names go to the team's own destinations; a platform destination gets counts.
	var own, platform apitypes.CapabilityChangedData
	_ = json.Unmarshal(forDestination(ev, dbgen.NotificationDestination{Scope: "team"}).Payload, &own)
	_ = json.Unmarshal(forDestination(ev, dbgen.NotificationDestination{Scope: "platform"}).Payload, &platform)
	if len(own.Capabilities) != 10 || len(platform.Capabilities) != 0 || platform.MoreCount != 15 || platform.ChangedCount != 10 {
		t.Errorf("own %d names, platform %d names, more %d", len(own.Capabilities), len(platform.Capabilities), platform.MoreCount)
	}
	if strings.Contains(string(forDestination(ev, dbgen.NotificationDestination{Scope: "platform"}).Payload), "nnnn") {
		t.Error("capability names reached a platform destination")
	}
}

func TestBuildMessageHeaderInjection(t *testing.T) {
	cfg := config.SMTP{Host: "smtp.example.com", From: "Open MCP Portal <portal@example.com>"}
	m := Mail{To: "person@example.com", ToName: "Eve\r\nBcc: spy@example.com", Subject: "[Portal] Server \"x\"\r\nBcc: spy@example.com\r\nX-Evil: 1 – ünïcode",
		Event: "server.unhealthy\r\nX-Evil2: 1", Text: "line one\r\n.dot line\r\nBcc: not-a-header", HTML: "<p>x</p>"}
	raw, rcpt, err := BuildMessage(cfg, m, time.Unix(1_800_000_000, 0))
	if err != nil || rcpt != "person@example.com" {
		t.Fatalf("%v %q", err, rcpt)
	}
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "bcc:") || strings.HasPrefix(l, "x-evil") {
			t.Errorf("an injected header: %q", line)
		}
	}
	for _, want := range []string{"From: ", "To: ", "Subject: =?utf-8?", "Auto-Submitted: auto-generated", "X-OMP-Event: ", "MIME-Version: 1.0", "multipart/alternative"} {
		if !strings.Contains(head, want) {
			t.Errorf("missing %q in\n%s", want, head)
		}
	}
	if strings.Contains(string(raw), "\n") && strings.Contains(strings.ReplaceAll(string(raw), "\r\n", ""), "\n") {
		t.Error("bare LF in the message")
	}
	for _, bad := range []string{"img ", "<img", "http://", "src="} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the message references remote content: %q", bad)
		}
	}
	if _, _, err := BuildMessage(cfg, Mail{To: "a@b.example\r\nBcc: x@y.example", Subject: "x"}, time.Now()); err == nil {
		t.Error("a recipient with CR/LF was accepted")
	}
}

func TestRenderEmailEscapesAndHasNoImages(t *testing.T) {
	s := unitService(t, nil)
	text, html, err := s.render(Message{Title: `<script>alert(1)</script> & "x"`, Body: `<b>bold</b>`, Link: &Link{Type: LinkReviewQueue}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<b>bold") || strings.Contains(html, "<img") || strings.Contains(html, "src=") {
		t.Errorf("html not escaped or has images:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(text, "https://portal.example.com/admin/publishing") ||
		!strings.Contains(text, "https://portal.example.com/settings/notifications") {
		t.Errorf("text:\n%s", text)
	}
}

func TestEmitValidation(t *testing.T) {
	// Without a database, Emit must still refuse bad input without panicking.
	var q *dbgen.Queries
	for _, ev := range []Event{{Type: "nope", DedupKey: "x"}, {Type: ServerUnhealthy}, {Type: ServerUnhealthy, DedupKey: strings.Repeat("k", 201)},
		{Type: ServerUnhealthy, DedupKey: "k", Data: strings.Repeat("x", MaxPayload+1)}} {
		if Emit(context.Background(), q, ev) {
			t.Errorf("%+v was emitted", ev.Type)
		}
	}
}

// There is no port or path oracle: whatever internal address a destination
// names, the outcome is the same fixed class and message.
func TestInternalTargetsAreIndistinguishable(t *testing.T) {
	s := unitService(t, NewWebhookClient(nil, nil))
	var first result
	for i, u := range []string{"https://127.0.0.1:1/a", "https://127.0.0.1:8080/admin", "https://10.0.0.5/x", "https://169.254.169.254/latest", "https://[::1]:9/", "http://example.com/hook"} {
		res := s.sendWebhook(context.Background(), dest(t, s, "slack", u), ServerUnhealthy, uuid.New(), 1, 1, slackBody("x"))
		if i == 0 {
			first = res
		}
		if res.OK || res.Class != ClassNotAllowed || res.Status != 0 || res.Message != first.Message {
			t.Errorf("%s: %+v differs from %+v", u, res, first)
		}
	}
}

func TestAuditSinkStatusLink(t *testing.T) {
	for _, typ := range []string{AuditSinkFailing, AuditSinkRecovered} {
		m := compose(dbgen.NotificationEvent{Event: typ}, nil)
		if m.Link == nil || m.Link.path() != "/admin/audit-stream" || m.Title == "" || m.Body == "" {
			t.Fatalf("missing sink status composition: %+v", m)
		}
	}
}
