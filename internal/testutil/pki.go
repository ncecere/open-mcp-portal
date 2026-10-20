package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// Throwaway PKI for tests of TLS to upstream servers: private CAs, server
// and client certificates, generated in memory for one test. No key material
// is ever written to the repository.

// KeyType picks the key algorithm of a generated certificate.
type KeyType string

const (
	KeyEC256   KeyType = "ec256" // the default: fast
	KeyEC224   KeyType = "ec224" // below the accepted curves
	KeyRSA2048 KeyType = "rsa2048"
	KeyRSA1024 KeyType = "rsa1024" // below the minimum
	KeyEd25519 KeyType = "ed25519"
)

// Cert is a certificate with its private key.
type Cert struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// CertPEM is the certificate; KeyPEM the key as an unencrypted PKCS#8
	// PEM block.
	CertPEM, KeyPEM string
}

// IssueOptions shapes a certificate; the zero value is a valid client
// certificate for CN "test" good for an hour, with an EC P-256 key.
type IssueOptions struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	// Server and Client select the extended key usages (neither: no EKU
	// extension at all).
	Server, Client bool
	NotBefore      time.Time
	NotAfter       time.Time
	Key            KeyType
	// CA makes a CA certificate that may sign others.
	CA bool
}

func newKey(t testing.TB, kt KeyType) crypto.Signer {
	t.Helper()
	var (
		k   crypto.Signer
		err error
	)
	switch kt {
	case "", KeyEC256:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyEC224:
		k, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case KeyRSA2048:
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA1024:
		k, err = rsa.GenerateKey(rand.Reader, 1024)
	case KeyEd25519:
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown key type %q", kt)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (c *Cert) wrap(t testing.TB, der []byte) *Cert {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	c.Cert = cert
	c.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kb, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	c.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	return c
}

func certTemplate(o IssueOptions) *x509.Certificate {
	cn := o.CommonName
	if cn == "" {
		cn = "test"
	}
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Minute)
	}
	if na.IsZero() {
		na = time.Now().Add(time.Hour)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	t := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: cn, Organization: []string{"omp-test"}},
		NotBefore: nb, NotAfter: na, DNSNames: o.DNSNames, IPAddresses: o.IPs, BasicConstraintsValid: true,
	}
	if o.CA {
		t.IsCA, t.KeyUsage = true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		return t
	}
	t.KeyUsage = x509.KeyUsageDigitalSignature
	if o.Server {
		t.ExtKeyUsage = append(t.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if o.Client {
		t.ExtKeyUsage = append(t.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	return t
}

// NewCA makes a self-signed CA certificate.
func NewCA(t testing.TB, name string) *Cert {
	t.Helper()
	c := &Cert{Key: newKey(t, KeyEC256)}
	o := IssueOptions{CommonName: name, CA: true, NotAfter: time.Now().Add(24 * time.Hour)}
	tpl := certTemplate(o)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, c.Key.Public(), c.Key)
	if err != nil {
		t.Fatal(err)
	}
	return c.wrap(t, der)
}

// Issue makes a certificate signed by ca.
func (ca *Cert) Issue(t testing.TB, o IssueOptions) *Cert {
	t.Helper()
	c := &Cert{Key: newKey(t, o.Key)}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate(o), ca.Cert, c.Key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return c.wrap(t, der)
}

// SelfSigned makes a self-signed certificate (a leaf that is its own issuer).
func SelfSigned(t testing.TB, o IssueOptions) *Cert {
	t.Helper()
	c := &Cert{Key: newKey(t, o.Key)}
	tpl := certTemplate(o)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, c.Key.Public(), c.Key)
	if err != nil {
		t.Fatal(err)
	}
	return c.wrap(t, der)
}

// TLSCertificate is the certificate (and chain, given the intermediates) as a
// tls.Certificate, for a test server.
func (c *Cert) TLSCertificate(chain ...*Cert) tls.Certificate {
	out := tls.Certificate{Certificate: [][]byte{c.Cert.Raw}, PrivateKey: c.Key, Leaf: c.Cert}
	for _, x := range chain {
		out.Certificate = append(out.Certificate, x.Cert.Raw)
	}
	return out
}

// Pool is a CertPool holding the given certificates.
func Pool(certs ...*Cert) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c.Cert)
	}
	return p
}

// KeyPEMAs re-encodes the key in another PEM form: "rsa" (PKCS#1) or "ec"
// (SEC1), which must match the key's algorithm.
func (c *Cert) KeyPEMAs(t testing.TB, form string) string {
	t.Helper()
	var (
		b   []byte
		typ string
		err error
	)
	switch k := c.Key.(type) {
	case *rsa.PrivateKey:
		b, typ = x509.MarshalPKCS1PrivateKey(k), "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		b, err = x509.MarshalECPrivateKey(k)
		typ = "EC PRIVATE KEY"
	default:
		t.Fatalf("no %s form for %T", form, c.Key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}))
}

// IssueFor makes a certificate signed by ca for an existing key (a renewal:
// same key, new certificate).
func (ca *Cert) IssueFor(t testing.TB, key crypto.Signer, o IssueOptions) *Cert {
	t.Helper()
	c := &Cert{Key: key}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate(o), ca.Cert, key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return c.wrap(t, der)
}
