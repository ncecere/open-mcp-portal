package upstream

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// TLS to a server (decision 74, docs/registry.md "TLS to the server").
//
// A server can have a client certificate (mTLS) and a CA bundle. The CA
// bundle REPLACES the system roots for that server: a public CA nobody
// vetted for an internal host can then never vouch for it, and the private CA
// vouches for nothing else, because no other server's connection sees it.
// The host name check stays on, always: tls.Config.ServerName is the URL's
// host (the transport sets it; the dial goes to the checked address, never
// to a name), and nothing in this package, the API or the database can turn
// verification off. TLS 1.2 is the minimum (1.3 is negotiated when both sides
// speak it).
//
// The address rule (guard.go) is a different layer and is not touched here: the
// dialer resolves once, checks every address and pins the connection, and the
// TLS handshake then runs over the connection it returns.

// Limits on what a server's TLS settings may hold.
const (
	// MaxTLSPEM bounds a certificate field (a CA bundle or a client chain).
	MaxTLSPEM = 64 << 10
	// MaxTLSKeyPEM bounds the private key field.
	MaxTLSKeyPEM = 16 << 10
	// MaxTLSCerts bounds the certificates in a CA bundle or a client chain.
	MaxTLSCerts = 10
	// MinRSABits is the smallest RSA key accepted (client key or CA).
	MinRSABits = 2048
)

// Fields of TLS input (the API's tls object).
const (
	TLSFieldCA   = "caPem"
	TLSFieldCert = "clientCertPem"
	TLSFieldKey  = "clientKeyPem"
)

// Reasons a TLS input is refused (details.reason of 422 invalid_tls).
const (
	TLSReasonEmpty          = "empty"
	TLSReasonTooLarge       = "too_large"
	TLSReasonNotPEM         = "not_pem"
	TLSReasonTooMany        = "too_many_certificates"
	TLSReasonPrivateKey     = "private_key_in_certificate_field"
	TLSReasonNotCertificate = "not_a_certificate"
	TLSReasonBadCertificate = "invalid_certificate"
	TLSReasonExpired        = "expired"
	TLSReasonNotYetValid    = "not_yet_valid"
	TLSReasonNotClientAuth  = "not_for_client_authentication"
	TLSReasonWeakKey        = "weak_key"
	TLSReasonWeakSignature  = "weak_signature"
	TLSReasonEncryptedKey   = "encrypted_key"
	TLSReasonNotPrivateKey  = "not_a_private_key"
	TLSReasonBadKey         = "invalid_key"
	TLSReasonKeyMismatch    = "key_mismatch"
)

// TLSInputError says what is wrong with one TLS input. Message is plain and
// never quotes the input.
type TLSInputError struct {
	Field, Reason, Message string
}

func (e *TLSInputError) Error() string { return e.Field + ": " + e.Message }

func tlsInput(field, reason, msg string) *TLSInputError {
	return &TLSInputError{Field: field, Reason: reason, Message: msg}
}

// CertInfo describes one certificate: only public facts.
type CertInfo struct {
	Subject, Issuer string
	SHA256          string // of the DER encoding, hex
	NotBefore       time.Time
	NotAfter        time.Time
	// Names are the DNS names and IP addresses the certificate lists
	// (client certificates only).
	Names []string
}

func infoOf(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	return CertInfo{Subject: clip(c.Subject.String(), 300), Issuer: clip(c.Issuer.String(), 300), SHA256: hex.EncodeToString(sum[:]),
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()}
}

// pemBlocks decodes a PEM field that must hold nothing but blocks: its size,
// the number of blocks and stray text around them are checked before anything
// is parsed.
func pemBlocks(field, s string, maxBytes, maxBlocks int) ([]*pem.Block, *TLSInputError) {
	if strings.TrimSpace(s) == "" {
		return nil, tlsInput(field, TLSReasonEmpty, "Paste the PEM text (-----BEGIN ...-----).")
	}
	if len(s) > maxBytes {
		return nil, tlsInput(field, TLSReasonTooLarge, fmt.Sprintf("Too large: at most %d KiB.", maxBytes>>10))
	}
	if strings.Contains(s, "\x00") {
		return nil, tlsInput(field, TLSReasonNotPEM, "That isn't PEM text.")
	}
	markers := strings.Count(s, "-----BEGIN ")
	if markers > maxBlocks {
		return nil, tlsInput(field, TLSReasonTooMany, fmt.Sprintf("Too many PEM blocks: at most %d.", maxBlocks))
	}
	var out []*pem.Block
	rest := []byte(s)
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, tlsInput(field, TLSReasonNotPEM, "That isn't PEM: remove everything outside the -----BEGIN/END----- lines.")
		}
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, tlsInput(field, TLSReasonNotPEM, "That isn't valid PEM: a -----BEGIN----- block is cut off or damaged.")
		}
		out = append(out, b)
	}
	if len(out) == 0 || len(out) != markers {
		return nil, tlsInput(field, TLSReasonNotPEM, "That isn't valid PEM.")
	}
	return out, nil
}

// certificates parses a field of CERTIFICATE blocks only. A private key block
// is refused by name, whichever field it was pasted into.
func certificates(field, s string) ([]*x509.Certificate, *TLSInputError) {
	blocks, err := pemBlocks(field, s, MaxTLSPEM, MaxTLSCerts)
	if err != nil {
		return nil, err
	}
	out := make([]*x509.Certificate, 0, len(blocks))
	for _, b := range blocks {
		switch {
		case strings.Contains(b.Type, "PRIVATE KEY"):
			return nil, tlsInput(field, TLSReasonPrivateKey, "That contains a private key. This field takes certificates only: a private key belongs in the private key field.")
		case b.Type != "CERTIFICATE":
			return nil, tlsInput(field, TLSReasonNotCertificate, "Only CERTIFICATE blocks are accepted here.")
		}
		c, perr := x509.ParseCertificate(b.Bytes)
		if perr != nil {
			return nil, tlsInput(field, TLSReasonBadCertificate, "A certificate in it can't be read (is it DER inside the PEM, unaltered?).")
		}
		out = append(out, c)
	}
	return out, nil
}

// selfSigned reports whether a certificate names itself as its issuer; the
// signature of such a certificate is never what is trusted.
func selfSigned(c *x509.Certificate) bool { return bytes.Equal(c.RawSubject, c.RawIssuer) }

func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// checkPublicKey applies the algorithm and size minimums: RSA of at least
// 2048 bits, ECDSA on P-256, P-384 or P-521, or Ed25519.
func checkPublicKey(field string, pub crypto.PublicKey) *TLSInputError {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return tlsInput(field, TLSReasonWeakKey, fmt.Sprintf("The RSA key is %d bits; at least %d are required.", k.N.BitLen(), MinRSABits))
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return tlsInput(field, TLSReasonWeakKey, "The elliptic curve isn't supported: use P-256, P-384 or P-521.")
		}
	case ed25519.PublicKey:
	default:
		return tlsInput(field, TLSReasonWeakKey, "The key type isn't supported: use RSA (2048 bits or more), ECDSA (P-256, P-384, P-521) or Ed25519.")
	}
	return nil
}

// CABundle is a validated CA bundle.
type CABundle struct {
	// PEM is the bundle re-encoded from its certificates (nothing but them).
	PEM string
	// SHA256 identifies the set of certificates (order doesn't matter).
	SHA256 string
	Certs  []CertInfo
	pool   *x509.CertPool
}

// ParseCABundle validates a CA bundle: PEM certificates only (no private key
// block), at most MaxTLSCerts of them in MaxTLSPEM bytes, each with an
// acceptable key and (unless it is self-signed) signature, and not all expired
// at now (a zero now skips the time check, for reading what is stored).
func ParseCABundle(s string, now time.Time) (*CABundle, error) {
	certs, err := certificates(TLSFieldCA, s)
	if err != nil {
		return nil, err
	}
	b := &CABundle{pool: x509.NewCertPool()}
	var sums []string
	valid := false
	for _, c := range certs {
		if e := checkPublicKey(TLSFieldCA, c.PublicKey); e != nil {
			return nil, e
		}
		if !selfSigned(c) && weakSignature(c.SignatureAlgorithm) {
			return nil, tlsInput(TLSFieldCA, TLSReasonWeakSignature, "A certificate in the bundle is signed with MD5 or SHA-1, which isn't accepted.")
		}
		if now.IsZero() || (!now.Before(c.NotBefore) && !now.After(c.NotAfter)) {
			valid = true
		}
		info := infoOf(c)
		b.Certs = append(b.Certs, info)
		sums = append(sums, info.SHA256)
		b.pool.AddCert(c)
		b.PEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if !valid {
		return nil, tlsInput(TLSFieldCA, TLSReasonExpired, "Every certificate in the bundle has expired or isn't valid yet.")
	}
	slices.Sort(sums)
	h := sha256.Sum256([]byte("omp-ca-bundle-v1\n" + strings.Join(slices.Compact(sums), "\n")))
	b.SHA256 = hex.EncodeToString(h[:])
	return b, nil
}

// ClientPair is a validated client certificate chain and its private key.
type ClientPair struct {
	// PEM is the chain re-encoded from its certificates.
	PEM string
	// Leaf describes the first certificate, the one that identifies the
	// client; Chain the others sent with it.
	Leaf  CertInfo
	Chain []CertInfo
	cert  tls.Certificate
}

// ParseClientPair validates a client certificate chain (leaf first) with its
// private key: PEM only; a private key that is a single unencrypted PKCS#8,
// PKCS#1 or SEC1 block (no passphrase-protected keys); an acceptable key
// algorithm and size; the key belongs to the leaf; the leaf isn't expired or
// not yet valid at now (a zero now skips the time check, for reading what is
// stored), isn't signed with MD5 or SHA-1 (unless self-signed) and, when it
// names its uses, includes client authentication.
func ParseClientPair(certPEM, keyPEM string, now time.Time) (*ClientPair, error) {
	certs, err := certificates(TLSFieldCert, certPEM)
	if err != nil {
		return nil, err
	}
	key, kerr := parsePrivateKey(keyPEM)
	if kerr != nil {
		return nil, kerr
	}
	leaf := certs[0]
	if e := checkPublicKey(TLSFieldCert, leaf.PublicKey); e != nil {
		return nil, e
	}
	if e := checkPublicKey(TLSFieldKey, key.Public()); e != nil {
		return nil, e
	}
	if eq, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(key.Public()) {
		return nil, tlsInput(TLSFieldKey, TLSReasonKeyMismatch,
			"The private key doesn't belong to the first certificate (the client certificate must come first, then any intermediates).")
	}
	if !selfSigned(leaf) && weakSignature(leaf.SignatureAlgorithm) {
		return nil, tlsInput(TLSFieldCert, TLSReasonWeakSignature, "The certificate is signed with MD5 or SHA-1, which isn't accepted.")
	}
	if !now.IsZero() {
		switch {
		case now.After(leaf.NotAfter):
			return nil, tlsInput(TLSFieldCert, TLSReasonExpired, "The client certificate expired on "+leaf.NotAfter.UTC().Format("2006-01-02")+".")
		case now.Add(5 * time.Minute).Before(leaf.NotBefore):
			return nil, tlsInput(TLSFieldCert, TLSReasonNotYetValid, "The client certificate isn't valid before "+leaf.NotBefore.UTC().Format("2006-01-02 15:04 MST")+".")
		}
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.ContainsFunc(leaf.ExtKeyUsage, func(u x509.ExtKeyUsage) bool {
		return u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny
	}) {
		return nil, tlsInput(TLSFieldCert, TLSReasonNotClientAuth, "The certificate isn't for client authentication (its extended key usage lacks clientAuth).")
	}
	p := &ClientPair{Leaf: infoOf(leaf)}
	for _, n := range leaf.DNSNames {
		p.Leaf.Names = append(p.Leaf.Names, clip(n, 100))
	}
	for _, ip := range leaf.IPAddresses {
		p.Leaf.Names = append(p.Leaf.Names, ip.String())
	}
	p.Leaf.Names = p.Leaf.Names[:min(len(p.Leaf.Names), 20)]
	p.cert = tls.Certificate{PrivateKey: key, Leaf: leaf}
	for i, c := range certs {
		p.cert.Certificate = append(p.cert.Certificate, c.Raw)
		p.PEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		if i > 0 {
			p.Chain = append(p.Chain, infoOf(c))
		}
	}
	return p, nil
}

// parsePrivateKey reads a private key: one unencrypted block of PKCS#8,
// PKCS#1 (RSA) or SEC1 (EC) form, optionally after the EC PARAMETERS block
// openssl writes.
func parsePrivateKey(s string) (crypto.Signer, error) {
	blocks, err := pemBlocks(TLSFieldKey, s, MaxTLSKeyPEM, 2)
	if err != nil {
		return nil, err
	}
	blocks = slices.DeleteFunc(blocks, func(b *pem.Block) bool { return b.Type == "EC PARAMETERS" })
	if len(blocks) != 1 {
		return nil, tlsInput(TLSFieldKey, TLSReasonNotPrivateKey, "Paste exactly one private key.")
	}
	b := blocks[0]
	if b.Type == "ENCRYPTED PRIVATE KEY" || b.Headers["Proc-Type"] != "" || b.Headers["DEK-Info"] != "" {
		return nil, tlsInput(TLSFieldKey, TLSReasonEncryptedKey,
			"The private key is protected by a passphrase, which isn't supported. Remove the passphrase first (for example: openssl pkey -in key.pem -out key-plain.pem).")
	}
	var key any
	var perr error
	switch b.Type {
	case "PRIVATE KEY":
		key, perr = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, perr = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, perr = x509.ParseECPrivateKey(b.Bytes)
	case "OPENSSH PRIVATE KEY":
		return nil, tlsInput(TLSFieldKey, TLSReasonNotPrivateKey, "An OpenSSH key isn't a TLS key. Use a PKCS#8, PKCS#1 or SEC1 PEM key.")
	default:
		return nil, tlsInput(TLSFieldKey, TLSReasonNotPrivateKey, "That isn't a private key (expected PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY).")
	}
	if perr != nil {
		return nil, tlsInput(TLSFieldKey, TLSReasonBadKey, "The private key can't be read.")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, tlsInput(TLSFieldKey, TLSReasonWeakKey, "The key type isn't supported: use RSA, ECDSA or Ed25519.")
	}
	return signer, nil
}

// DescribeChain describes a stored client certificate chain: the leaf (with the
// names it lists) and how many certificates there are.
func DescribeChain(certPEM string) (CertInfo, int, error) {
	certs, err := certificates(TLSFieldCert, certPEM)
	if err != nil {
		return CertInfo{}, 0, err
	}
	info := infoOf(certs[0])
	for _, n := range certs[0].DNSNames {
		info.Names = append(info.Names, clip(n, 100))
	}
	for _, ip := range certs[0].IPAddresses {
		info.Names = append(info.Names, ip.String())
	}
	info.Names = info.Names[:min(len(info.Names), 20)]
	return info, len(certs), nil
}

// TLSIdentity is a server's TLS settings, ready to dial with: the CA bundle
// that replaces the system roots (none: the system roots) and the client
// certificate presented when the server asks for one. Its String and GoString
// show nothing but what is set, so it is safe in a log line or an error.
type TLSIdentity struct {
	ca     *CABundle
	client *ClientPair
	// keyPEM is kept only so Target.Secrets can scrub it from messages.
	keyPEM string
}

// NewTLSIdentity parses stored TLS settings (without the time checks: an
// expired certificate is still presented, and the server's refusal is what
// the health check then shows). Empty fields are absent; a certificate
// without a key (or the reverse) is an error.
func NewTLSIdentity(caPEM, certPEM, keyPEM string) (*TLSIdentity, error) {
	id := &TLSIdentity{}
	if caPEM != "" {
		ca, err := ParseCABundle(caPEM, time.Time{})
		if err != nil {
			return nil, err
		}
		id.ca = ca
	}
	if certPEM != "" || keyPEM != "" {
		pair, err := ParseClientPair(certPEM, keyPEM, time.Time{})
		if err != nil {
			return nil, err
		}
		id.client, id.keyPEM = pair, keyPEM
	}
	return id, nil
}

// HasCA and HasClientCert say what is set.
func (t *TLSIdentity) HasCA() bool         { return t != nil && t.ca != nil }
func (t *TLSIdentity) HasClientCert() bool { return t != nil && t.client != nil }

// Fingerprint identifies the identity: the CA bundle and the client
// certificate (never the key). Two servers with different material never
// share it.
func (t *TLSIdentity) Fingerprint() string {
	if t == nil {
		return ""
	}
	ca, cert := "", ""
	if t.ca != nil {
		ca = t.ca.SHA256
	}
	if t.client != nil {
		cert = t.client.Leaf.SHA256
	}
	h := sha256.Sum256([]byte("omp-tls-identity-v1\n" + ca + "\n" + cert))
	return hex.EncodeToString(h[:])
}

func (t *TLSIdentity) String() string {
	if t == nil {
		return "tls(system roots)"
	}
	return fmt.Sprintf("tls(ca=%v client=%v)", t.ca != nil, t.client != nil)
}

// GoString keeps %#v from printing the key.
func (t *TLSIdentity) GoString() string { return t.String() }

// secrets are the forms of the private key a message must not contain: the
// PEM text and its base64 body.
func (t *TLSIdentity) secrets() []string {
	if t == nil || t.keyPEM == "" {
		return nil
	}
	body := strings.NewReplacer("\r", "", "\n", "").Replace(t.keyPEM)
	out := []string{strings.TrimSpace(t.keyPEM)}
	if b, _ := pem.Decode([]byte(t.keyPEM)); b != nil {
		out = append(out, base64.StdEncoding.EncodeToString(b.Bytes))
	}
	return append(out, body)
}

// tlsConfig is the client configuration of one exchange with a server. It
// never turns verification off (no skip-verify option, no custom peer check), never sets a ServerName
// (the transport uses the URL's host, which is what is verified), and no
// session cache, so nothing outlives the exchange it was made for.
func tlsConfig(t *TLSIdentity) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if t == nil {
		return cfg
	}
	if t.ca != nil {
		cfg.RootCAs = t.ca.pool.Clone() // replaces the system roots
	}
	if t.client != nil {
		cert := t.client.cert
		// Presented whenever the server asks for a client certificate, whatever
		// list of acceptable CAs it sends (Certificates would send nothing when
		// the list doesn't name our issuer, which is a silent failure).
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
	}
	return cfg
}

// IsTLSInput reports whether err is a *TLSInputError.
func IsTLSInput(err error) (*TLSInputError, bool) {
	var e *TLSInputError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
