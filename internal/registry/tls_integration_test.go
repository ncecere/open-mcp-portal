package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// The client key is sealed with an AAD bound to its server and to the field:
// it opens only as that server's client key, never as another server's, a
// header value, or any other field; Target opens it and presents the
// certificate; a key that no longer opens (ENCRYPTION_KEY lost) is a config
// error that names nothing secret.
func TestTLSKeyIsBoundToItsServerAndField(t *testing.T) {
	s, exec := testService(t)
	ctx := context.Background()
	ca := testutil.NewCA(t, "CA")
	client := ca.Issue(t, testutil.IssueOptions{CommonName: "c", Client: true})
	team := exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T') RETURNING id::text`)
	a := uuid.MustParse(exec(`INSERT INTO mcp_servers (team_id, slug, name, url) VALUES ($1, 'a', 'A', 'https://127.0.0.1:9/mcp') RETURNING id::text`, team))
	b := uuid.MustParse(exec(`INSERT INTO mcp_servers (team_id, slug, name, url) VALUES ($1, 'b', 'B', 'https://127.0.0.1:9/mcp') RETURNING id::text`, team))

	plan, err := s.planTLS(a, nil, &TLSInput{CAPEM: &ca.CertPEM, ClientCertPEM: &client.CertPEM, ClientKeyPEM: &client.KeyPEM}, false, time.Now())
	if err != nil || !plan.write || !plan.caChanged || !plan.clientChanged {
		t.Fatalf("plan = %+v %v", plan, err)
	}
	row, err := storeTLS(ctx, s.q, a, plan)
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row.ClientKeyCipher), "PRIVATE") || len(row.ClientKeyCipher) < 40 {
		t.Fatal("the key isn't sealed")
	}
	// Opens as server a's client key and nothing else.
	if plain, err := s.box.Open(row.ClientKeyCipher, TLSKeyAAD(a)); err != nil || string(plain) != client.KeyPEM {
		t.Fatalf("own AAD: %v", err)
	}
	for name, aad := range map[string][]byte{
		"another server's":  TLSKeyAAD(b),
		"a header value's":  ServerAAD(a),
		"the bare table":    []byte("mcp_server_tls:" + a.String()),
		"a credential part": CredentialAAD(a),
	} {
		if _, err := s.box.Open(row.ClientKeyCipher, aad); err == nil {
			t.Errorf("the key opens with %s AAD", name)
		}
	}
	// A ciphertext moved to another server's row doesn't open there: Target
	// fails with a config error, not with a key.
	exec(`INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after)
		SELECT $1, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after FROM mcp_server_tls WHERE server_id = $2 RETURNING server_id::text`, b, a)
	svB, _ := s.q.GetMCPServer(ctx, b)
	_, err = s.Target(ctx, svB)
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Class != upstream.ClassConfig || strings.Contains(ue.Message, "PRIVATE") {
		t.Fatalf("a moved ciphertext: %v", err)
	}
	// The real one: Target carries a ready identity, and nothing prints it.
	svA, _ := s.q.GetMCPServer(ctx, a)
	tgt, err := s.Target(ctx, svA)
	if err != nil || tgt.TLS == nil || !tgt.TLS.HasCA() || !tgt.TLS.HasClientCert() {
		t.Fatalf("target = %+v %v", tgt.TLS, err)
	}
	// The key opens for the transport only; the target's string forms hide it.
	if got := tgt.TLS.String(); strings.Contains(got, "PRIVATE") || strings.Contains(got, client.KeyPEM[40:80]) {
		t.Fatalf("the identity prints %q", got)
	}
	// A server without a row has no identity (the system roots).
	exec(`DELETE FROM mcp_server_tls WHERE server_id = $1 RETURNING server_id::text`, b)
	svB, _ = s.q.GetMCPServer(ctx, b)
	if tgt, err := s.Target(ctx, svB); err != nil || tgt.TLS != nil {
		t.Fatalf("a server without settings: %+v %v", tgt.TLS, err)
	}
	// Deleting the server removes the row.
	exec(`DELETE FROM mcp_servers WHERE id = $1 RETURNING id::text`, a)
	if exec(`SELECT count(*)::text FROM mcp_server_tls`) != "0" {
		t.Fatal("the TLS row outlived its server")
	}
}

// The plan's rules: what changes, what counts as a trust change, what the
// origin does.
func TestPlanTLS(t *testing.T) {
	s, exec := testService(t)
	ctx := context.Background()
	ca1, ca2 := testutil.NewCA(t, "CA one"), testutil.NewCA(t, "CA two")
	c1 := ca1.Issue(t, testutil.IssueOptions{CommonName: "c1", Client: true})
	c2 := ca1.Issue(t, testutil.IssueOptions{CommonName: "c2", Client: true})
	team := exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T') RETURNING id::text`)
	id := uuid.MustParse(exec(`INSERT INTO mcp_servers (team_id, slug, name, url) VALUES ($1, 'a', 'A', 'https://127.0.0.1:9/mcp') RETURNING id::text`, team))
	now := time.Now()
	in := func(ca, cert, key *string, clear bool) *TLSInput {
		return &TLSInput{CAPEM: ca, ClientCertPEM: cert, ClientKeyPEM: key, Clear: clear}
	}
	empty := ""
	apply := func(p tlsPlan) *dbgen.McpServerTl {
		t.Helper()
		row, err := storeTLS(ctx, s.q, id, p)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}

	p, err := s.planTLS(id, nil, in(&ca1.CertPEM, &c1.CertPEM, &c1.KeyPEM, false), false, now)
	if err != nil || !p.caChanged || !p.clientChanged {
		t.Fatalf("first = %+v %v", p, err)
	}
	row := apply(p)
	// Nothing sent, or the same thing again: no write.
	for name, input := range map[string]*TLSInput{"nil": nil, "empty": in(nil, nil, nil, false), "same CA": in(&ca1.CertPEM, nil, nil, false),
		"same pair": in(nil, &c1.CertPEM, &c1.KeyPEM, false), "same cert, stored key": in(nil, &c1.CertPEM, nil, false), "an empty key": in(nil, nil, &empty, false)} {
		if p, err := s.planTLS(id, row, input, false, now); err != nil || p.write {
			t.Errorf("%s: %+v %v", name, p, err)
		}
	}
	// The pair sent again keeps the stored sealed key (it can only be the same key).
	if p, _ := s.planTLS(id, row, in(nil, &c1.CertPEM, &c1.KeyPEM, false), false, now); string(p.next.keyCipher) != string(row.ClientKeyCipher) {
		t.Error("an unchanged pair sealed the key again")
	}
	// A new client certificate for another key: not a CA change.
	p, err = s.planTLS(id, row, in(nil, &c2.CertPEM, &c2.KeyPEM, false), false, now)
	if err != nil || !p.write || p.caChanged || !p.clientChanged {
		t.Fatalf("new pair = %+v %v", p, err)
	}
	// A CA in either direction is a trust change; so is a bundle with one more.
	for name, input := range map[string]*TLSInput{"another CA": in(&ca2.CertPEM, nil, nil, false), "more CAs": in(ptrTo(ca1.CertPEM+ca2.CertPEM), nil, nil, false), "no CA": in(&empty, nil, nil, false)} {
		if p, err := s.planTLS(id, row, input, false, now); err != nil || !p.caChanged || p.clientChanged {
			t.Errorf("%s: %+v %v", name, p, err)
		}
	}
	// Removing the client certificate removes its key, and is no CA change.
	p, err = s.planTLS(id, row, in(nil, &empty, nil, false), false, now)
	if err != nil || !p.write || p.caChanged || !p.clientChanged || p.next.keyCipher != nil || p.next.certPEM != "" || p.next.caPEM == "" {
		t.Fatalf("remove the certificate = %+v %v", p, err)
	}
	// Clear removes everything; not together with other fields.
	if p, err = s.planTLS(id, row, in(nil, nil, nil, true), false, now); err != nil || !p.next.empty() || !p.write {
		t.Fatalf("clear = %+v %v", p, err)
	}
	if _, err = s.planTLS(id, row, in(&ca2.CertPEM, nil, nil, true), false, now); err == nil {
		t.Fatal("clear with a CA")
	}
	// Another origin: the pair needs replacing or removing; a CA alone is dropped.
	if _, err = s.planTLS(id, row, nil, true, now); err == nil || !strings.Contains(err.Error(), "can't be reused") {
		t.Fatalf("origin move without a pair = %v", err)
	}
	if _, err = s.planTLS(id, row, in(&ca1.CertPEM, &c1.CertPEM, nil, false), true, now); err == nil {
		t.Fatal("origin move with a certificate and no key")
	}
	p, err = s.planTLS(id, row, in(&ca2.CertPEM, &c2.CertPEM, &c2.KeyPEM, false), true, now)
	if err != nil || !p.droppedCA || !p.droppedClient {
		t.Fatalf("origin move with a new pair = %+v %v", p, err)
	}
	if string(p.next.keyCipher) == string(row.ClientKeyCipher) {
		t.Fatal("the old sealed key followed the origin")
	}
	if p, err = s.planTLS(id, row, in(nil, &empty, nil, false), true, now); err != nil || p.next.caPEM != "" || p.next.certPEM != "" {
		t.Fatalf("origin move removing the certificate = %+v %v", p, err)
	}
	if p, err = s.planTLS(id, row, in(nil, nil, nil, true), true, now); err != nil || !p.next.empty() {
		t.Fatalf("origin move with clear = %+v %v", p, err)
	}
	// Only a CA stored: another origin drops it without asking.
	apply(tlsPlan{write: true, next: tlsState{}})
	row = apply(mustPlan(t, s, id, nil, in(&ca1.CertPEM, nil, nil, false), false, now))
	if p, err = s.planTLS(id, row, nil, true, now); err != nil || !p.droppedCA || !p.next.empty() || !p.caChanged {
		t.Fatalf("a CA alone on another origin = %+v %v", p, err)
	}
}

func ptrTo[T any](v T) *T { return &v }

func mustPlan(t *testing.T, s *Service, id uuid.UUID, row *dbgen.McpServerTl, in *TLSInput, moved bool, now time.Time) tlsPlan {
	t.Helper()
	p, err := s.planTLS(id, row, in, moved, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The review digest covers the CA bundle and the client certificate, and
// only when they are set.
func TestReviewDigestCoversTLS(t *testing.T) {
	sv := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthNone}
	base := reviewDigest(sv, nil, tlsDigest{}, nil)
	if base != ReviewDigest(sv, nil) {
		t.Fatal("ReviewDigest and an empty TLS digest differ")
	}
	ca, cert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	seen := map[string]string{"none": base}
	for name, d := range map[string]tlsDigest{"a CA": {CASHA: ca}, "a certificate": {ClientSHA: cert}, "both": {CASHA: ca, ClientSHA: cert},
		"the other way": {CASHA: cert, ClientSHA: ca}, "another CA": {CASHA: cert}} {
		got := reviewDigest(sv, nil, d, nil)
		for prev, h := range seen {
			if got == h {
				t.Errorf("%s has the digest of %s", name, prev)
			}
		}
		seen[name] = got
	}
	if reviewDigest(sv, nil, tlsDigest{CASHA: ca}, nil) != seen["a CA"] {
		t.Error("the digest isn't stable")
	}
	if digestVersion != "omp-review-v3" {
		t.Errorf("digest version %s", digestVersion)
	}
}

func TestCertStatus(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		left   time.Duration
		status string
	}{
		{-time.Second, TLSCertExpired}, {0, TLSCertExpired}, {time.Hour, TLSCertExpiring}, {13 * 24 * time.Hour, TLSCertExpiring},
		{TLSExpiryWarnDays * 24 * time.Hour, TLSCertExpiring}, {TLSExpiryWarnDays*24*time.Hour + time.Hour, TLSCertValid}, {90 * 24 * time.Hour, TLSCertValid},
	} {
		if got, _ := certStatus(now.Add(c.left), now); got != c.status {
			t.Errorf("%v left: %s, want %s", c.left, got, c.status)
		}
	}
	ca := testutil.NewCA(t, "CA")
	cert := ca.Issue(t, testutil.IssueOptions{Client: true, NotAfter: now.Add(3 * 24 * time.Hour)})
	pair, _ := upstream.ParseClientPair(cert.CertPEM, cert.KeyPEM, now)
	na := pair.Leaf.NotAfter
	v := viewOfTLS(&dbgen.McpServerTl{ClientCertPem: &cert.CertPEM, ClientKeyCipher: []byte{1}, ClientCertSha256: &pair.Leaf.SHA256, ClientNotAfter: &na}, now)
	if v == nil || v.Client == nil || v.Client.Status != TLSCertExpiring || v.Client.DaysLeft != 2 || !v.Client.HasKey || len(v.warnings()) != 1 {
		t.Fatalf("view = %+v", v)
	}
	if viewOfTLS(nil, now) != nil || (&TLSView{}).warnings() != nil {
		t.Fatal("no settings, no view")
	}
}
