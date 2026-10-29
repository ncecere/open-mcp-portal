package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Internal networks (docs/registry.md, "Security"; decision 20): the
// allowlist of internal networks and hosts MCP servers may use. Platform
// admins manage their entries (network_settings, with a revision); the
// deployment adds read-only entries (UPSTREAM_ALLOWED_NETWORKS). Changing
// the entries never edits servers: a server outside the policy fails its
// next exchange (not_allowed).

// NetworkCacheTTL is how long a replica uses its copy of the admin entries
// before reading them again: a change made on another replica applies
// here within this time. The replica that saves a change applies it at
// once.
const NetworkCacheTTL = 30 * time.Second

// networkRetry is how soon a failed read is retried (the last copy, or the
// deployment entries alone, apply meanwhile).
const networkRetry = 5 * time.Second

// Networks is the allowlist in force, as upstream.Client reads it at every
// check and dial: the deployment entries plus a cached copy of the admin
// entries.
type Networks struct {
	q          *dbgen.Queries
	deployment []netpolicy.Entry
	log        *slog.Logger
	ttl        time.Duration
	now        func() time.Time

	mu      sync.Mutex
	policy  *netpolicy.Policy
	expires time.Time
}

var _ upstream.NetworkPolicy = (*Networks)(nil)

// NewNetworks returns the allowlist of the deployment entries (canonical,
// from config) and the admin entries stored in pool.
func NewNetworks(pool *pgxpool.Pool, deployment []netpolicy.Entry, log *slog.Logger) *Networks {
	if log == nil {
		log = slog.Default()
	}
	n := &Networks{deployment: deployment, log: log, ttl: NetworkCacheTTL, now: time.Now}
	if pool != nil {
		n.q = dbgen.New(pool)
	}
	return n
}

// Deployment returns the deployment entries.
func (n *Networks) Deployment() []netpolicy.Entry { return n.deployment }

// Current returns the policy in force, reading the admin entries again
// when the copy is older than NetworkCacheTTL. When they can't be read, the
// last copy (or the deployment entries alone) applies.
func (n *Networks) Current(ctx context.Context) *netpolicy.Policy {
	n.mu.Lock()
	p, fresh := n.policy, n.now().Before(n.expires)
	n.mu.Unlock()
	if p != nil && fresh {
		return p
	}
	if n.q == nil {
		return n.set(nil)
	}
	row, err := n.q.GetNetworkSettings(ctx)
	if err != nil {
		n.log.WarnContext(ctx, "internal networks: reading the allowlist failed; using the last copy", "err", err)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.expires = n.now().Add(networkRetry)
		if n.policy == nil {
			return netpolicy.New(n.deployment)
		}
		return n.policy
	}
	return n.set(decodeEntries(row.Entries))
}

// CurrentChecked uses only the exchange's serialized transaction reads when
// present. Transaction-local settings must never refresh or replace the shared
// cache, and failures must not fall back to a cached/deployment-only policy.
func (n *Networks) CurrentChecked(ctx context.Context) (*netpolicy.Policy, error) {
	if q, ok := store.EndpointReads(ctx); ok {
		row, err := q.GetNetworkSettings(ctx)
		if err != nil {
			return nil, err
		}
		return netpolicy.New(n.deployment, decodeEntries(row.Entries)), nil
	}
	return n.Current(ctx), nil
}

// set installs the admin entries (the replica that saved them applies them
// at once).
func (n *Networks) set(admin []netpolicy.Entry) *netpolicy.Policy {
	p := netpolicy.New(n.deployment, admin)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.policy, n.expires = p, n.now().Add(n.ttl)
	return p
}

func decodeEntries(raw []byte) []netpolicy.Entry {
	out := []netpolicy.Entry{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// NetworkSettings are the allowlist's entries as the API shows them.
type NetworkSettings struct {
	Entries    []netpolicy.Entry // the platform admins'
	Deployment []netpolicy.Entry // UPSTREAM_ALLOWED_NETWORKS (read-only)
	Revision   int64
	UpdatedAt  time.Time
}

func (s *Service) networkSettings(row dbgen.NetworkSetting) NetworkSettings {
	dep := s.nets.Deployment()
	if dep == nil {
		dep = []netpolicy.Entry{}
	}
	return NetworkSettings{Entries: decodeEntries(row.Entries), Deployment: dep, Revision: row.Revision, UpdatedAt: row.UpdatedAt}
}

// GetNetworkSettings returns the allowlist (platform admins and auditors).
func (s *Service) GetNetworkSettings(ctx context.Context, a authz.Actor) (NetworkSettings, error) {
	if !a.CanReadPlatform() {
		return NetworkSettings{}, errPlatformRead
	}
	row, err := s.q.GetNetworkSettings(ctx)
	if err != nil {
		return NetworkSettings{}, err
	}
	return s.networkSettings(row), nil
}

func invalidEntry(e *netpolicy.EntryError) error {
	ae := apperr.New(http.StatusUnprocessableEntity, "invalid_entry", e.Error())
	ae.Details = map[string]any{"index": e.Index, "reason": e.Reason}
	return ae
}

// UpdateNetworkSettings replaces the admin entries (platform admins). The
// entries are canonicalised; an invalid one is 422 invalid_entry with
// details.index and details.reason. Servers are not touched. Audited as
// settings.network_update with the lists before and after.
func (s *Service) UpdateNetworkSettings(ctx context.Context, a authz.Actor, entries []netpolicy.Entry, expectedRevision int64) (NetworkSettings, error) {
	if !a.IsPlatformAdmin() {
		return NetworkSettings{}, errAdminOnly
	}
	entries, problem := netpolicy.Validate(entries)
	if problem != nil {
		return NetworkSettings{}, invalidEntry(problem)
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return NetworkSettings{}, err
	}
	var row dbgen.NetworkSetting
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockNetworkSettings(ctx)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		if row, err = q.UpdateNetworkEntries(ctx, dbgen.UpdateNetworkEntriesParams{Entries: raw, UpdatedBy: by(a)}); err != nil {
			return err
		}
		e := a.Audit("settings.network_update", "platform_settings", "network")
		e.Before, e.After = map[string]any{"entries": decodeEntries(cur.Entries)}, map[string]any{"entries": entries}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return NetworkSettings{}, err
	}
	// This replica applies the change at once; others within NetworkCacheTTL.
	s.nets.set(entries)
	return s.networkSettings(row), nil
}

// CheckNetworkURL says whether the gateway would reach a URL now, and why,
// resolving its host without connecting (platform admins and auditors).
func (s *Service) CheckNetworkURL(ctx context.Context, a authz.Actor, raw string) (upstream.CheckResult, error) {
	if !a.CanReadPlatform() {
		return upstream.CheckResult{}, errPlatformRead
	}
	return s.client.Check(ctx, raw), nil
}
