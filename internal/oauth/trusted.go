package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Trusted clients (decisions 12 and 24): metadata-document clients whose
// IDs platform admins list skip the consent screen (never the sign-in).
// Registered clients can't be trusted: their IDs change.

// MaxTrustedClients bounds the list.
const MaxTrustedClients = 50

var (
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
)

// TrustedClient is one entry.
type TrustedClient struct {
	ClientID string `json:"clientId"`
	Label    string `json:"label,omitempty"`
}

// TrustedClients is the OAuth client settings of the platform: the trusted
// list, whether open client registration is on, and their revision.
type TrustedClients struct {
	Clients          []TrustedClient
	OpenRegistration bool
	Revision         int64
	UpdatedAt        time.Time
}

func decodeTrusted(raw []byte) []TrustedClient {
	out := []TrustedClient{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func trustedView(row dbgen.OauthSetting) TrustedClients {
	return TrustedClients{Clients: decodeTrusted(row.TrustedClients), OpenRegistration: row.OpenRegistration, Revision: row.Revision, UpdatedAt: row.UpdatedAt}
}

// GetTrustedClients returns the list (platform admins and auditors).
func (s *Service) GetTrustedClients(ctx context.Context, a authz.Actor) (TrustedClients, error) {
	if !a.CanReadPlatform() {
		return TrustedClients{}, errPlatformRead
	}
	row, err := s.q.GetOAuthSettings(ctx)
	if err != nil {
		return TrustedClients{}, err
	}
	return trustedView(row), nil
}

func invalidClientID(i int, reason string) error {
	e := apperr.New(http.StatusUnprocessableEntity, "invalid_client_id",
		"Each trusted client must be the https URL of a Client ID Metadata Document, with a path, listed once")
	e.Details = map[string]any{"index": i, "reason": reason}
	return e
}

// validateTrusted trims and checks entries: an https metadata-document URL
// (with a path), listed once; a label of at most 100 characters on one line.
func validateTrusted(in []TrustedClient) ([]TrustedClient, error) {
	if len(in) > MaxTrustedClients {
		e := apperr.New(http.StatusUnprocessableEntity, "invalid_client_id", "At most 50 trusted clients")
		e.Details = map[string]any{"index": MaxTrustedClients, "reason": "too_many"}
		return nil, e
	}
	out := make([]TrustedClient, 0, len(in))
	seen := map[string]bool{}
	for i, c := range in {
		id := strings.TrimSpace(c.ClientID)
		label := strings.TrimSpace(c.Label)
		switch {
		case !ValidClientIDURL(id):
			return nil, invalidClientID(i, "not_metadata_url")
		case seen[id]:
			return nil, invalidClientID(i, "duplicate")
		case utf8.RuneCountInString(label) > 100 || strings.IndexFunc(label, unicode.IsControl) >= 0:
			e := apperr.Invalid("invalid_label", "A label must be at most 100 characters on one line")
			e.Details = map[string]any{"index": i}
			return nil, e
		}
		seen[id] = true
		out = append(out, TrustedClient{ClientID: id, Label: label})
	}
	return out, nil
}

// UpdateTrustedClients replaces the list and, when openRegistration is
// given, sets the open-registration switch (platform admins; a platform
// token can't: this route is session-only), If-Match on the revision.
// Audited as settings.oauth_clients_update with the list and the switch
// before and after.
func (s *Service) UpdateTrustedClients(ctx context.Context, a authz.Actor, in []TrustedClient, openRegistration *bool, expectedRevision int64) (TrustedClients, error) {
	if !a.IsPlatformAdmin() {
		return TrustedClients{}, errAdminOnly
	}
	clients, err := validateTrusted(in)
	if err != nil {
		return TrustedClients{}, err
	}
	raw, err := json.Marshal(clients)
	if err != nil {
		return TrustedClients{}, err
	}
	var row dbgen.OauthSetting
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockOAuthSettings(ctx)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		open := cur.OpenRegistration
		if openRegistration != nil {
			open = *openRegistration
		}
		if row, err = q.UpdateOAuthClientSettings(ctx, dbgen.UpdateOAuthClientSettingsParams{TrustedClients: raw, OpenRegistration: open,
			UpdatedBy: uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}}); err != nil {
			return err
		}
		e := a.Audit("settings.oauth_clients_update", "platform_settings", "oauth_clients")
		e.Before = map[string]any{"clients": decodeTrusted(cur.TrustedClients), "openRegistration": cur.OpenRegistration}
		e.After = map[string]any{"clients": clients, "openRegistration": open}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return TrustedClients{}, err
	}
	return trustedView(row), nil
}

// trustedIDs is the current list, read now (one row; no cache, so a change
// applies on every replica at once).
func (s *Service) trustedIDs(ctx context.Context) (map[string]bool, error) {
	row, err := s.q.GetOAuthSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, c := range decodeTrusted(row.TrustedClients) {
		out[c.ClientID] = true
	}
	return out, nil
}

// Trusted reports whether a client skips the consent screen: a metadata
// document client on the list (a registered client never does).
func (s *Service) Trusted(ctx context.Context, c Client) (bool, error) {
	if c.Kind != KindMetadata {
		return false, nil
	}
	ids, err := s.trustedIDs(ctx)
	return ids[c.ID], err
}
