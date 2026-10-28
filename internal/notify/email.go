package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Email (docs/notifications.md, "Email"): one message per recipient through
// the operator's SMTP server (trusted configuration, so no SSRF guard),
// certificates always verified, STARTTLS required (never a downgrade),
// multipart text and HTML with no images, remote content or tracking.
// Header values lose CR/LF and are RFC 2047-encoded. Dial 10 s, whole
// message 30 s.

//go:embed templates/*.tmpl
var templateFS embed.FS

var (
	textTemplate = template.Must(template.ParseFS(templateFS, "templates/email.txt.tmpl"))
	htmlTemplate = htmltemplate.Must(htmltemplate.ParseFS(templateFS, "templates/email.html.tmpl"))
)

// SMTP timeouts.
const (
	SMTPDialTimeout    = 10 * time.Second
	SMTPMessageTimeout = 30 * time.Second
	SMTPCheckTimeout   = 5 * time.Second
)

// Mail is one message to one person.
type Mail struct {
	To, ToName string
	Subject    string
	Event      string
	Text, HTML string
}

// MailError is a failed send: its class (apitypes.NotificationErrorClass)
// and whether trying again can help.
type MailError struct {
	Class     string
	Permanent bool
}

func (e *MailError) Error() string { return "email: " + e.Class }

// Mailer sends mail.
type Mailer interface {
	Send(ctx context.Context, m Mail) *MailError
}

// SMTPMailer sends through SMTP.
type SMTPMailer struct {
	Config config.SMTP
	// RootCAs replaces the system roots (tests; there is no operator setting
	// and no way to skip verification).
	RootCAs *x509.CertPool
}

func classifySMTP(err error, stage string) *MailError {
	var te *textproto.Error
	var ne net.Error
	switch {
	case errors.As(err, &te):
		switch {
		case stage == "auth":
			return &MailError{Class: ClassAuth, Permanent: te.Code >= 500}
		case stage == "rcpt" && te.Code >= 500:
			return &MailError{Class: ClassAddress, Permanent: true}
		case te.Code >= 500:
			return &MailError{Class: ClassRejected, Permanent: true}
		}
		return &MailError{Class: ClassServerError}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return &MailError{Class: ClassTimeout}
	case stage == "tls" || strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:"):
		return &MailError{Class: ClassTLS}
	case stage == "auth":
		return &MailError{Class: ClassAuth}
	}
	return &MailError{Class: ClassConnect}
}

// dial connects, greets, upgrades with STARTTLS when the mode says so (and
// fails when the server doesn't offer it) and authenticates when a
// username is set. The caller QUITs.
func dial(ctx context.Context, cfg config.SMTP, roots *x509.CertPool, total time.Duration) (*smtp.Client, *MailError) {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.EffectivePort()))
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: roots} // certificates always verified
	nd := &net.Dialer{Timeout: SMTPDialTimeout}
	var conn net.Conn
	var err error
	if cfg.Mode() == config.SMTPImplicit {
		conn, err = (&tls.Dialer{NetDialer: nd, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = nd.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, classifySMTP(err, "connect")
	}
	_ = conn.SetDeadline(time.Now().Add(total))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, classifySMTP(err, "connect")
	}
	fail := func(e *MailError) (*smtp.Client, *MailError) { _ = c.Close(); return nil, e }
	if err := c.Hello("localhost"); err != nil {
		return fail(classifySMTP(err, "connect"))
	}
	if cfg.Mode() == config.SMTPStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fail(&MailError{Class: ClassTLS, Permanent: false}) // never a downgrade
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fail(classifySMTP(err, "tls"))
		}
	}
	if cfg.Authenticates() {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fail(&MailError{Class: ClassAuth})
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fail(classifySMTP(err, "auth"))
		}
	}
	return c, nil
}

// Check connects, greets, upgrades, authenticates and QUITs within 5 s,
// sending nothing (doctor's email check). It returns nil when all went well.
func Check(ctx context.Context, cfg config.SMTP) *MailError { return CheckWith(ctx, cfg, nil) }

// CheckWith is Check trusting roots instead of the system's (tests).
func CheckWith(ctx context.Context, cfg config.SMTP, roots *x509.CertPool) *MailError {
	ctx, cancel := context.WithTimeout(ctx, SMTPCheckTimeout)
	defer cancel()
	c, merr := dial(ctx, cfg, roots, SMTPCheckTimeout)
	if merr != nil {
		return merr
	}
	_ = c.Quit()
	return nil
}

// Send delivers one message.
func (m *SMTPMailer) Send(ctx context.Context, mail Mail) *MailError {
	cfg := m.Config
	if !cfg.Enabled() {
		return &MailError{Class: ClassInternal, Permanent: true}
	}
	msg, rcpt, err := BuildMessage(cfg, mail, time.Now())
	if err != nil {
		return &MailError{Class: ClassAddress, Permanent: true}
	}
	ctx, cancel := context.WithTimeout(ctx, SMTPMessageTimeout)
	defer cancel()
	c, merr := dial(ctx, cfg, m.RootCAs, SMTPMessageTimeout)
	if merr != nil {
		return merr
	}
	defer c.Close()
	if err := c.Mail(cfg.Address()); err != nil {
		return classifySMTP(err, "mail")
	}
	if err := c.Rcpt(rcpt); err != nil {
		return classifySMTP(err, "rcpt")
	}
	w, err := c.Data()
	if err != nil {
		return classifySMTP(err, "data")
	}
	if _, err := w.Write(msg); err != nil {
		return classifySMTP(err, "data")
	}
	if err := w.Close(); err != nil {
		return classifySMTP(err, "data")
	}
	_ = c.Quit()
	return nil
}

// header makes a header value safe: CR, LF and NUL are replaced by spaces
// (no header can be injected) and non-ASCII text is RFC 2047-encoded.
func header(v string) string {
	v = strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ").Replace(v)
	return mime.QEncoding.Encode("utf-8", strings.TrimSpace(v))
}

// BuildMessage renders a message (RFC 5322, multipart/alternative with a
// plain-text and an HTML part) and returns it with the recipient address.
func BuildMessage(cfg config.SMTP, m Mail, now time.Time) ([]byte, string, error) {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, "", err
	}
	to, err := mail.ParseAddress((&mail.Address{Name: strings.NewReplacer("\r", " ", "\n", " ").Replace(m.ToName), Address: m.To}).String())
	if err != nil || strings.ContainsAny(m.To, "\r\n") {
		return nil, "", errors.New("invalid recipient")
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	domain := "localhost"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part := func(contentType, content string) error {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", contentType+"; charset=utf-8")
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(content)); err != nil {
			return err
		}
		return qp.Close()
	}
	if err := part("text/plain", m.Text); err != nil {
		return nil, "", err
	}
	if err := part("text/html", m.HTML); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	var out bytes.Buffer
	hdr := func(k, v string) { fmt.Fprintf(&out, "%s: %s\r\n", k, v) }
	hdr("From", from.String())
	hdr("To", to.String())
	hdr("Subject", header(m.Subject))
	hdr("Date", now.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-OMP-Event", header(m.Event))
	hdr("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	out.WriteString("\r\n")
	out.Write(bytes.ReplaceAll(body.Bytes(), []byte("\r\n"), []byte("\n"))) // normalised below
	return bytes.ReplaceAll(bytes.ReplaceAll(out.Bytes(), []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n")), to.Address, nil
}

type emailView struct {
	Instance, Title, Body, URL, SettingsURL string
}

// render builds the text and HTML of a message (html/template escapes the
// user-controlled text; there are no images or remote resources).
func (s *Service) render(msg Message) (text, html string, err error) {
	v := emailView{Instance: s.cfg.InstanceName, Title: msg.Title, Body: msg.Body,
		SettingsURL: strings.TrimRight(s.cfg.AppURL, "/") + "/settings/notifications"}
	if msg.Link != nil {
		v.URL = s.portalURL(msg.Link)
	}
	var t, h bytes.Buffer
	if err := textTemplate.Execute(&t, v); err != nil {
		return "", "", err
	}
	if err := htmlTemplate.Execute(&h, v); err != nil {
		return "", "", err
	}
	return t.String(), h.String(), nil
}

// subject is "[<instance>] <title>".
func (s *Service) subject(title string) string { return "[" + s.cfg.InstanceName + "] " + title }

// deliverEmail is one attempt of an email row: the person must still be
// active and their address verified (else the row is skipped). The address
// is read from the profile now, never copied.
func (s *Service) deliverEmail(ctx context.Context, row dbgen.NotificationOutbox, ev dbgen.NotificationEvent, msg Message) result {
	if isApprovalEvent(ev.Event) {
		// Approval metadata stays private even if eligibility changes while an
		// email waits in the outbox. Recheck without opening a fenced service tx.
		rs, err := s.approvalRecipients(ctx, s.q, ev)
		if err != nil {
			return result{Class: ClassInternal}
		}
		allowed := false
		for _, r := range rs {
			allowed = allowed || r.ID == row.UserID.UUID
		}
		if !allowed {
			return skipped
		}
	}
	u, err := s.q.GetNotificationUser(ctx, row.UserID.UUID)
	if err != nil {
		return skipped
	}
	if u.Status != "active" || !u.EmailVerified || u.Email == "" {
		return skipped
	}
	text, html, err := s.render(msg)
	if err != nil {
		return result{Class: ClassInternal, Permanent: true}
	}
	merr := s.mail.Send(ctx, Mail{To: u.Email, ToName: u.DisplayName, Subject: s.subject(msg.Title), Event: ev.Event, Text: text, HTML: html})
	if merr != nil {
		return result{Class: merr.Class, Permanent: merr.Permanent}
	}
	return result{OK: true}
}
