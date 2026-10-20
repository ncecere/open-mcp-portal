package upstream

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func reasonOf(t *testing.T, err error) (field, reason string) {
	t.Helper()
	e, ok := IsTLSInput(err)
	if !ok {
		t.Fatalf("err = %v, want *TLSInputError", err)
	}
	return e.Field, e.Reason
}

func TestParseClientPair(t *testing.T) {
	ca := testutil.NewCA(t, "Internal CA")
	now := time.Now()
	good := ca.Issue(t, testutil.IssueOptions{CommonName: "portal", Client: true})

	// A good pair, in each of the key forms.
	for name, key := range map[string]string{"pkcs8": good.KeyPEM, "sec1": good.KeyPEMAs(t, "ec"),
		"with EC PARAMETERS": "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" + good.KeyPEMAs(t, "ec")} {
		p, err := ParseClientPair(good.CertPEM, key, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Leaf.SHA256 == "" || !strings.Contains(p.Leaf.Subject, "portal") || p.PEM != good.CertPEM {
			t.Fatalf("%s: %+v", name, p.Leaf)
		}
	}
	// RSA 2048 and Ed25519 are accepted too; RSA keys in PKCS#1 form.
	rsa := ca.Issue(t, testutil.IssueOptions{Client: true, Key: testutil.KeyRSA2048})
	for _, key := range []string{rsa.KeyPEM, rsa.KeyPEMAs(t, "rsa")} {
		if _, err := ParseClientPair(rsa.CertPEM, key, now); err != nil {
			t.Fatalf("rsa: %v", err)
		}
	}
	ed := ca.Issue(t, testutil.IssueOptions{Client: true, Key: testutil.KeyEd25519})
	if _, err := ParseClientPair(ed.CertPEM, ed.KeyPEM, now); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	// A chain: leaf first, then the CA.
	if _, err := ParseClientPair(good.CertPEM+ca.CertPEM, good.KeyPEM, now); err != nil {
		t.Fatalf("chain: %v", err)
	}
	// A self-signed leaf (pinned by the server) is fine.
	self := testutil.SelfSigned(t, testutil.IssueOptions{Client: true})
	if _, err := ParseClientPair(self.CertPEM, self.KeyPEM, now); err != nil {
		t.Fatalf("self-signed: %v", err)
	}

	other := ca.Issue(t, testutil.IssueOptions{Client: true})
	expired := ca.Issue(t, testutil.IssueOptions{Client: true, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})
	future := ca.Issue(t, testutil.IssueOptions{Client: true, NotBefore: now.Add(48 * time.Hour), NotAfter: now.Add(72 * time.Hour)})
	serverOnly := ca.Issue(t, testutil.IssueOptions{Server: true, DNSNames: []string{"x.test"}})
	weakRSA := ca.Issue(t, testutil.IssueOptions{Client: true, Key: testutil.KeyRSA1024})
	weakEC := ca.Issue(t, testutil.IssueOptions{Client: true, Key: testutil.KeyEC224})
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	legacyEncrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"
	tooMany := strings.Repeat(good.CertPEM, MaxTLSCerts+1)

	for _, c := range []struct {
		name, cert, key string
		field, reason   string
	}{
		{"empty cert", "", good.KeyPEM, TLSFieldCert, TLSReasonEmpty},
		{"empty key", good.CertPEM, "", TLSFieldKey, TLSReasonEmpty},
		{"not PEM", "hello", good.KeyPEM, TLSFieldCert, TLSReasonNotPEM},
		{"text around the PEM", "see below\n" + good.CertPEM, good.KeyPEM, TLSFieldCert, TLSReasonNotPEM},
		{"cut-off block", strings.TrimSuffix(good.CertPEM, "-----END CERTIFICATE-----\n"), good.KeyPEM, TLSFieldCert, TLSReasonNotPEM},
		{"a key in the certificate field", good.KeyPEM, good.KeyPEM, TLSFieldCert, TLSReasonPrivateKey},
		{"a key after the certificate", good.CertPEM + good.KeyPEM, good.KeyPEM, TLSFieldCert, TLSReasonPrivateKey},
		{"a certificate in the key field", good.CertPEM, good.CertPEM, TLSFieldKey, TLSReasonNotPrivateKey},
		{"too many certificates", tooMany, good.KeyPEM, TLSFieldCert, TLSReasonTooMany},
		{"too large", strings.Repeat("A", MaxTLSPEM+1), good.KeyPEM, TLSFieldCert, TLSReasonTooLarge},
		{"key too large", good.CertPEM, strings.Repeat("A", MaxTLSKeyPEM+1), TLSFieldKey, TLSReasonTooLarge},
		{"garbage certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", good.KeyPEM, TLSFieldCert, TLSReasonBadCertificate},
		{"another key", good.CertPEM, other.KeyPEM, TLSFieldKey, TLSReasonKeyMismatch},
		{"the CA first in the chain", ca.CertPEM + good.CertPEM, good.KeyPEM, TLSFieldKey, TLSReasonKeyMismatch},
		{"expired", expired.CertPEM, expired.KeyPEM, TLSFieldCert, TLSReasonExpired},
		{"not yet valid", future.CertPEM, future.KeyPEM, TLSFieldCert, TLSReasonNotYetValid},
		{"server-only usage", serverOnly.CertPEM, serverOnly.KeyPEM, TLSFieldCert, TLSReasonNotClientAuth},
		{"RSA 1024", weakRSA.CertPEM, weakRSA.KeyPEM, TLSFieldCert, TLSReasonWeakKey},
		{"P-224", weakEC.CertPEM, weakEC.KeyPEM, TLSFieldCert, TLSReasonWeakKey},
		{"encrypted PKCS#8", good.CertPEM, encrypted, TLSFieldKey, TLSReasonEncryptedKey},
		{"encrypted legacy key", good.CertPEM, legacyEncrypted, TLSFieldKey, TLSReasonEncryptedKey},
		{"two keys", good.CertPEM, good.KeyPEM + other.KeyPEM, TLSFieldKey, TLSReasonNotPrivateKey},
		{"unreadable key", good.CertPEM, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", TLSFieldKey, TLSReasonBadKey},
		{"an OpenSSH key", good.CertPEM, "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", TLSFieldKey, TLSReasonNotPrivateKey},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseClientPair(c.cert, c.key, now)
			if err == nil {
				t.Fatal("accepted")
			}
			field, reason := reasonOf(t, err)
			if field != c.field || reason != c.reason {
				t.Fatalf("field %s reason %s, want %s %s (%v)", field, reason, c.field, c.reason, err)
			}
			// What the input holds is never quoted back.
			if strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "MII") {
				t.Fatalf("message quotes the input: %v", err)
			}
		})
	}

	// A zero time skips the validity checks (reading what is stored): an expired
	// certificate is still presented, and the server's refusal says so.
	if _, err := ParseClientPair(expired.CertPEM, expired.KeyPEM, time.Time{}); err != nil {
		t.Fatalf("stored expired pair: %v", err)
	}
}

func TestParseCABundle(t *testing.T) {
	ca1, ca2 := testutil.NewCA(t, "CA one"), testutil.NewCA(t, "CA two")
	now := time.Now()
	b, err := ParseCABundle(ca1.CertPEM+ca2.CertPEM, now)
	if err != nil || len(b.Certs) != 2 || b.PEM != ca1.CertPEM+ca2.CertPEM {
		t.Fatalf("bundle = %+v, %v", b, err)
	}
	// The fingerprint names the set: the order doesn't matter, the content does.
	swapped, _ := ParseCABundle(ca2.CertPEM+ca1.CertPEM, now)
	one, _ := ParseCABundle(ca1.CertPEM, now)
	if swapped.SHA256 != b.SHA256 || one.SHA256 == b.SHA256 || len(b.SHA256) != 64 {
		t.Fatalf("fingerprints %s %s %s", b.SHA256, swapped.SHA256, one.SHA256)
	}
	leaf := ca1.Issue(t, testutil.IssueOptions{Server: true, DNSNames: []string{"x.test"}})
	expiredCA := testutil.SelfSigned(t, testutil.IssueOptions{CA: true, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})

	for _, c := range []struct {
		name, pem, reason string
	}{
		{"empty", "  ", TLSReasonEmpty},
		{"not PEM", "nope", TLSReasonNotPEM},
		{"a private key", ca1.CertPEM + ca1.KeyPEM, TLSReasonPrivateKey},
		{"only a private key", ca1.KeyPEM, TLSReasonPrivateKey},
		{"an RSA private key", ca1.KeyPEMAs(t, "ec"), TLSReasonPrivateKey},
		{"a public key", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", TLSReasonNotCertificate},
		{"eleven certificates", strings.Repeat(ca1.CertPEM, MaxTLSCerts+1), TLSReasonTooMany},
		{"too large", strings.Repeat("A", MaxTLSPEM+1), TLSReasonTooLarge},
		{"every certificate expired", expiredCA.CertPEM, TLSReasonExpired},
		{"weak key", testutil.SelfSigned(t, testutil.IssueOptions{CA: true, Key: testutil.KeyRSA1024}).CertPEM, TLSReasonWeakKey},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseCABundle(c.pem, now)
			if err == nil {
				t.Fatal("accepted")
			}
			if field, reason := reasonOf(t, err); field != TLSFieldCA || reason != c.reason {
				t.Fatalf("field %s reason %s, want %s", field, reason, c.reason)
			}
		})
	}
	// Ten certificates are the limit; one expired among valid ones is fine (a
	// rotation keeps the old root next to the new); a non-CA leaf can be the
	// anchor (a pinned server certificate).
	if _, err := ParseCABundle(strings.Repeat(ca1.CertPEM, MaxTLSCerts), now); err != nil {
		t.Fatalf("ten: %v", err)
	}
	if _, err := ParseCABundle(expiredCA.CertPEM+ca1.CertPEM, now); err != nil {
		t.Fatalf("one expired: %v", err)
	}
	if _, err := ParseCABundle(leaf.CertPEM, now); err != nil {
		t.Fatalf("leaf anchor: %v", err)
	}
	// Reading what is stored skips the time check.
	if _, err := ParseCABundle(expiredCA.CertPEM, time.Time{}); err != nil {
		t.Fatalf("stored: %v", err)
	}
}

func TestWeakSignatureAlgorithms(t *testing.T) {
	// The leaf of a client chain and the intermediates of a bundle can't be
	// signed with MD5 or SHA-1 (a self-signed certificate is exempt: nobody
	// verifies its own signature).
	for _, a := range []x509.SignatureAlgorithm{x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1} {
		if !weakSignature(a) {
			t.Errorf("%s is not refused", a)
		}
	}
	for _, a := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384,
		x509.SHA256WithRSAPSS, x509.PureEd25519} {
		if weakSignature(a) {
			t.Errorf("%s is refused", a)
		}
	}
}

func formatAll(v any) string { return fmt.Sprintf("%v|%+v|%#v|%s", v, v, v, v) }

func TestTLSIdentityNeverPrintsTheKey(t *testing.T) {
	ca := testutil.NewCA(t, "CA")
	c := ca.Issue(t, testutil.IssueOptions{Client: true})
	id, err := NewTLSIdentity(ca.CertPEM, c.CertPEM, c.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	body := pemBody(c.KeyPEM)
	tgt := Target{URL: "https://x.example/mcp", TLS: id}
	for _, s := range []string{id.String(), id.GoString(), formatAll(id), formatAll(tgt), formatAll(&tgt)} {
		if strings.Contains(s, body) || strings.Contains(s, "PRIVATE KEY") {
			t.Fatalf("a key leaks: %.120s", s)
		}
	}
	// The messages scrub the key if one ever quotes it.
	if got := tgt.safe("handshake failed " + c.KeyPEM + " and " + body); strings.Contains(got, body) {
		t.Fatalf("not scrubbed: %q", got)
	}
	if id.Fingerprint() == "" || id.Fingerprint() == (&TLSIdentity{}).Fingerprint() {
		t.Fatal("the fingerprint names the material")
	}
	var none *TLSIdentity
	if none.HasCA() || none.HasClientCert() || none.Fingerprint() != "" {
		t.Fatal("nil is empty")
	}
}

func TestTLSConfigShape(t *testing.T) {
	ca := testutil.NewCA(t, "CA")
	c := ca.Issue(t, testutil.IssueOptions{Client: true})
	// No settings: the system roots, TLS 1.2 at least, verification on.
	cfg := tlsConfig(nil)
	if cfg.RootCAs != nil || cfg.MinVersion != 0x0303 || cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil || cfg.ServerName != "" {
		t.Fatalf("default config = %+v", cfg)
	}
	id, err := NewTLSIdentity(ca.CertPEM, c.CertPEM, c.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg = tlsConfig(id)
	if cfg.RootCAs == nil || len(cfg.RootCAs.Subjects()) != 1 { //nolint:staticcheck // counting the pinned roots
		t.Fatalf("the CA bundle is the only trust: %+v", cfg.RootCAs)
	}
	if cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil || cfg.MinVersion < 0x0303 || cfg.GetClientCertificate == nil {
		t.Fatalf("config = %+v", cfg)
	}
	// Each exchange gets its own pool: changing one never reaches another.
	if tlsConfig(id).RootCAs == cfg.RootCAs {
		t.Fatal("the CA pool is shared between exchanges")
	}
	if _, err := NewTLSIdentity("", c.CertPEM, ""); err == nil {
		t.Fatal("a certificate without its key")
	}
	if _, err := NewTLSIdentity("", "", c.KeyPEM); err == nil {
		t.Fatal("a key without its certificate")
	}
	empty, err := NewTLSIdentity("", "", "")
	if err != nil || empty.HasCA() || empty.HasClientCert() {
		t.Fatalf("empty = %+v, %v", empty, err)
	}
}

// Nothing in the product code can turn verification off: the option appears
// nowhere in non-test Go source, and the dialer's address rule is the only
// thing that changes where a connection may go.
func TestNoInsecureSkipVerifyAnywhere(t *testing.T) {
	root := filepath.Join("..", "..")
	var found []string
	for _, dir := range []string{"internal", "cmd", "examples"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), "InsecureSkipVerify") && !strings.HasSuffix(p, "internal/upstream/tls_test.go") {
				found = append(found, p)
			}
			return nil
		})
	}
	if len(found) > 0 {
		t.Fatalf("InsecureSkipVerify appears in %v", found)
	}
}

func pemBody(s string) string {
	b, _ := pem.Decode([]byte(s))
	return base64.StdEncoding.EncodeToString(b.Bytes)
}
