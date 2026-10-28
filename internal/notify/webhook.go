package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Webhooks (docs/notifications.md, "Delivery"): POST, 10 s, redirects never
// followed, proxies ignored, TLS verified, the response body never kept.
// The URL is checked on save and on every attempt with the guarded dialer
// of MCP servers: public addresses over https, internal ones only by the
// internal-network allowlist, loopback, link-local and metadata never, DNS
// pinned.

// Webhook timeouts and bounds.
const (
	WebhookTimeout = 10 * time.Second
	// MaxURL bounds a destination's URL (the sealed URL may carry a query).
	MaxURL = 1000
	// drainBytes is the most of a response read (and thrown away), so the
	// connection ends cleanly; nothing of it is kept.
	drainBytes = 64 << 10
)

// SecretPrefix starts every signing secret: ompwhs_ and 43 characters.
const SecretPrefix = "ompwhs_"

// Headers sent with every delivery.
const (
	HeaderEvent     = "X-OMP-Event"
	HeaderEventID   = "X-OMP-Event-Id"
	HeaderDelivery  = "X-OMP-Delivery"
	HeaderAttempt   = "X-OMP-Attempt"
	HeaderTimestamp = "X-OMP-Timestamp"
	HeaderSignature = "X-OMP-Signature"
)

// staticNetworks is the fixed allowlist of the operator's
// NOTIFY_WEBHOOK_ALLOWED_NETWORKS (upstream.NetworkPolicy).
type staticNetworks struct{ p *netpolicy.Policy }

func (n staticNetworks) Current(context.Context) *netpolicy.Policy { return n.p }

// NewWebhookClient is the address guard for webhook URLs: public addresses
// over https only, plus whatever the operator allowed in
// NOTIFY_WEBHOOK_ALLOWED_NETWORKS. It is deliberately not the MCP servers'
// client: their internal-network allowlist (Admin > Internal networks) is
// managed by platform admins for servers, and webhook URLs are chosen by
// every team owner, so letting them reach the same internal addresses would
// give any owner a POST gadget into the internal network. There is no
// development allowance either: loopback, link-local and metadata addresses
// are never allowed.
func NewWebhookClient(allowed []netpolicy.Entry, log *slog.Logger) *upstream.Client {
	return &upstream.Client{AllowPrivate: false, Networks: staticNetworks{p: netpolicy.New(allowed)}, Log: log}
}

// URLAAD, SecretAAD and PreviousSecretAAD bind a destination's sealed
// values to its row.
func URLAAD(id uuid.UUID) []byte { return []byte("notification_destination:" + id.String() + ":url") }
func SecretAAD(id uuid.UUID) []byte {
	return []byte("notification_destination:" + id.String() + ":secret")
}
func PreviousSecretAAD(id uuid.UUID) []byte {
	return []byte("notification_destination:" + id.String() + ":secret_previous")
}

// Sign is the signature of a json delivery: the hex HMAC-SHA256, keyed with
// the destination's secret, of the timestamp (Unix seconds), a dot and the
// raw body.
func Sign(secret string, timestamp int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(timestamp, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// SignatureHeader is the X-OMP-Signature value: v1=<hex> for each secret
// (two during a rotation, the new one first).
func SignatureHeader(timestamp int64, body []byte, secrets ...string) string {
	parts := make([]string, len(secrets))
	for i, s := range secrets {
		parts[i] = "v1=" + Sign(s, timestamp, body)
	}
	return strings.Join(parts, ", ")
}

// Verify is the reference verifier a receiver can follow: the header must
// carry a v1= value that matches the secret, and the timestamp must be
// within tolerance of now.
func Verify(secret, header string, timestamp int64, body []byte, now time.Time, tolerance time.Duration) bool {
	if d := now.Sub(time.Unix(timestamp, 0)); d > tolerance || d < -tolerance {
		return false
	}
	want := Sign(secret, timestamp, body)
	for _, part := range strings.Split(header, ",") {
		got, ok := strings.CutPrefix(strings.TrimSpace(part), "v1=")
		if ok && hmac.Equal([]byte(got), []byte(want)) {
			return true
		}
	}
	return false
}

// CheckURL checks a destination URL as saving it and dialling it would: at
// most MaxURL characters, https (http only for a host the internal-network
// allowlist allows it for), no user info or fragment, and an address the
// policy allows. A query is allowed (it is sealed and never shown). Problems
// are 422 url_not_allowed with details.reason: invalid, too_long, userinfo,
// fragment, scheme, private_address, blocked_address.
func (s *Service) CheckURL(ctx context.Context, raw string) error {
	raw = strings.TrimSpace(raw)
	refuse := func(reason, msg string) error {
		e := apperr.New(422, "url_not_allowed", msg)
		e.Details = map[string]any{"reason": reason}
		return e
	}
	if len(raw) > MaxURL {
		return refuse(upstream.ReasonTooLong, fmt.Sprintf("The URL is too long: at most %d characters.", MaxURL))
	}
	if strings.Contains(raw, "#") {
		return refuse(upstream.ReasonFragment, "The URL can't have a fragment (#…).")
	}
	probe, _, _ := strings.Cut(raw, "?")
	_, err := s.client.NormalizeURL(ctx, probe)
	return err
}

// display is the part of a URL that is shown: scheme and host.
func display(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/..."
}

// httpClient dials only what the guard allows, ignores proxies and never
// follows redirects.
func (s *Service) httpClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
		DialContext:           s.client.GuardedDial(),
		TLSHandshakeTimeout:   WebhookTimeout,
		ResponseHeaderTimeout: WebhookTimeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: WebhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// sendWebhook posts body to a destination: it opens the sealed URL, checks
// it again, signs a json delivery and classifies the answer. Nothing of the
// response is kept but its status.
func (s *Service) sendWebhook(ctx context.Context, d dbgen.NotificationDestination, eventType string, eventID uuid.UUID, deliveryID int64, attempt int32, body []byte) result {
	rawURL, err := s.box.Open(d.UrlCipher, URLAAD(d.ID))
	if err != nil {
		return result{Class: ClassInternal, Permanent: true, Message: "The stored URL can't be decrypted with the current ENCRYPTION_KEY. Enter it again."}
	}
	if err := s.CheckURL(ctx, string(rawURL)); err != nil {
		return result{Class: ClassNotAllowed, Message: "The address isn't allowed: it is blocked, or an internal address that isn't in the allowlist."}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(rawURL), bytes.NewReader(body))
	if err != nil {
		return result{Class: ClassInternal, Permanent: true}
	}
	version := s.cfg.Version
	if version == "" {
		version = "dev"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "open-mcp-portal/"+version)
	req.Header.Set(HeaderEvent, eventType)
	req.Header.Set(HeaderEventID, eventID.String())
	req.Header.Set(HeaderDelivery, strconv.FormatInt(deliveryID, 10))
	req.Header.Set(HeaderAttempt, strconv.Itoa(int(attempt)))
	if d.Format == "json" {
		secret, err := s.box.Open(d.SecretCipher, SecretAAD(d.ID))
		if err != nil {
			return result{Class: ClassInternal, Permanent: true, Message: "The signing secret can't be decrypted with the current ENCRYPTION_KEY. Rotate it."}
		}
		secrets := []string{string(secret)}
		if len(d.SecretPreviousCipher) > 0 && d.SecretPreviousUntil != nil && d.SecretPreviousUntil.After(s.now()) {
			if prev, err := s.box.Open(d.SecretPreviousCipher, PreviousSecretAAD(d.ID)); err == nil {
				secrets = append(secrets, string(prev))
			}
		}
		ts := s.now().Unix()
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(HeaderSignature, SignatureHeader(ts, body, secrets...))
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return classifyNetError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBytes))
	res := result{Status: resp.StatusCode}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.OK = true
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		res.Class, res.Message = ClassNotAllowed, "The destination redirected, which is never followed."
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		res.Class = ClassRejected // retried
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		res.Class, res.Permanent = ClassRejected, true
	default:
		res.Class = ClassServerError
	}
	return res
}

// classifyNetError maps a transport error to an error class.
func classifyNetError(err error) result {
	var (
		netErr  net.Error
		unknown x509.UnknownAuthorityError
		hostErr x509.HostnameError
		certErr x509.CertificateInvalidError
		recErr  tls.RecordHeaderError
	)
	switch {
	case errors.Is(err, upstream.ErrBlockedAddress):
		return result{Class: ClassNotAllowed, Message: "The address isn't allowed."}
	case errors.As(err, &unknown), errors.As(err, &hostErr), errors.As(err, &certErr), errors.As(err, &recErr), strings.Contains(err.Error(), "tls:"):
		return result{Class: ClassTLS, Message: "The certificate or TLS handshake was refused."}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return result{Class: ClassTimeout, Message: "The destination didn't answer in time."}
	}
	return result{Class: ClassConnect, Message: "The destination couldn't be reached."}
}

// deliverWebhook is one attempt of an outbox row: the destination must still
// exist, be enabled and take the event (else the row is skipped).
func (s *Service) deliverWebhook(ctx context.Context, row dbgen.NotificationOutbox, ev dbgen.NotificationEvent, team *teamInfo, msg Message) result {
	if isApprovalEvent(ev.Event) {
		return skipped // private even if a malformed/legacy outbox row exists
	}
	d, err := s.q.GetNotificationDestination(ctx, row.DestinationID.UUID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return skipped
	} else if err != nil {
		return result{Class: ClassInternal}
	}
	if !d.Enabled || !contains(d.Events, ev.Event) {
		return skipped
	}
	// A platform destination gets counts, not the names of a team's
	// capabilities (data minimisation).
	ev = forDestination(ev, d)
	msg = compose(ev, team)
	var body []byte
	if d.Format == "slack" {
		body = slackBody(s.slackText(msg))
	} else if body, err = s.payload(ev, team, msg); err != nil {
		return result{Class: ClassInternal, Permanent: true}
	}
	return s.sendWebhook(ctx, d, ev.Event, ev.PublicID, row.ID, row.Attempts+1, body)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// forDestination limits an event's payload to what a destination may see:
// capability.changed carries capability names to the team's own
// destinations only; a platform destination gets the counts.
func forDestination(ev dbgen.NotificationEvent, d dbgen.NotificationDestination) dbgen.NotificationEvent {
	if ev.Event != CapabilityChanged || d.Scope != "platform" {
		return ev
	}
	var data apitypes.CapabilityChangedData
	if json.Unmarshal(ev.Payload, &data) != nil {
		return ev
	}
	data.MoreCount += int32(len(data.Capabilities))
	data.Capabilities = data.Capabilities[:0]
	if raw, err := json.Marshal(data); err == nil {
		ev.Payload = raw
	}
	return ev
}
