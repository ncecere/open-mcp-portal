package registry

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/definitionscan"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

type ScanningSettings struct {
	DefinitionMode string `json:"definitionMode"`
	Revision       int64  `json:"revision"`
}

func (s *Service) GetScanningSettings(ctx context.Context, a authz.Actor) (ScanningSettings, error) {
	if a.IsToken() {
		return ScanningSettings{}, apperr.New(403, "token_not_allowed", "A browser session is required")
	}
	if !a.CanReadPlatform() {
		return ScanningSettings{}, errPlatformRead
	}
	st, err := s.q.GetPlatformSettings(ctx)
	return ScanningSettings{st.DefinitionScanMode, st.ScanRevision}, err
}
func (s *Service) UpdateScanningSettings(ctx context.Context, a authz.Actor, mode string, rev int64) (out ScanningSettings, err error) {
	if a.IsToken() {
		return out, apperr.New(403, "token_not_allowed", "A browser session is required")
	}
	if !a.IsPlatformAdmin() {
		return out, errAdminOnly
	}
	if mode != "off" && mode != "shadow" {
		return out, apperr.New(422, "invalid_mode", "Expected off or shadow")
	}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		old, e := q.LockPlatformSettings(ctx)
		if e != nil {
			return e
		}
		if old.ScanRevision != rev {
			return apperr.Conflict("revision_conflict", "The settings changed")
		}
		st, e := q.UpdateDefinitionScanMode(ctx, mode)
		if e != nil {
			return e
		}
		out = ScanningSettings{st.DefinitionScanMode, st.ScanRevision}
		entry := a.Audit("settings.scanning_update", "platform_settings", "scanning")
		entry.Before = map[string]any{"definitionMode": old.DefinitionScanMode}
		entry.After = map[string]any{"definitionMode": mode}
		return audit.Record(ctx, q, entry)
	})
	return
}

var scanSlots = make(chan struct{}, 2)

func (s *Service) scanDefinitions(ctx context.Context, caps []upstream.Capability, origin string, allNames ...string) map[string]definitionscan.Result {
	return s.scanDefinitionBatch(ctx, caps, origin, false, allNames)
}

// Pending-only batches leave unattempted rows untouched, so their age keeps
// them ahead of repeatedly incomplete definitions on the next backfill pass.
func (s *Service) scanDefinitionBatch(ctx context.Context, caps []upstream.Capability, origin string, onlyAttempted bool, allNames []string) map[string]definitionscan.Result {
	st, err := s.q.GetPlatformSettings(ctx)
	if err != nil {
		s.scanFailed(ctx, "settings")
		return nil
	}
	if st.DefinitionScanMode == "off" {
		return nil
	}
	select {
	case scanSlots <- struct{}{}:
		defer func() { <-scanSlots }()
	default:
		if onlyAttempted {
			s.scanFailed(ctx, "busy")
			return nil
		}
		out := make(map[string]definitionscan.Result, len(caps))
		for _, c := range caps {
			out[c.Kind+" "+c.Name] = definitionscan.Result{Status: "incomplete", RulesetVersion: definitionscan.Version, Reason: "busy", Findings: []definitionscan.Finding{}}
		}
		s.scanFailed(ctx, "busy")
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names := allNames
	if len(names) == 0 {
		names = make([]string, len(caps))
		for i, c := range caps {
			names[i] = c.Name
		}
	}
	// Compare the whole inventory before the per-definition budget can expire.
	// Completed scans then remain usable when later definitions exceed the batch budget.
	confusable := map[string]bool{}
	for i, found := range definitionscan.ConfusableNames(ctx, names) {
		if found {
			confusable[names[i]] = true
		}
	}
	out := make(map[string]definitionscan.Result, len(caps))
	for i, cp := range caps {
		if onlyAttempted && ctx.Err() != nil {
			observability.ScanIncomplete.WithLabelValues("definition", "budget").Add(float64(len(caps) - i))
			break
		}
		start := time.Now()
		r := definitionscan.ScanOrigin(ctx, cp.Definition, origin)
		if confusable[cp.Name] && len(r.Findings) < definitionscan.MaxFindings {
			location := "/name"
			switch cp.Kind {
			case upstream.KindResource:
				location = "/uri"
			case upstream.KindResourceTemplate:
				location = "/uriTemplate"
			}
			r.Findings = append(r.Findings, definitionscan.Finding{RuleID: "unicode.confusable_name", Severity: "medium", Count: 1, Location: location})
		}
		out[cp.Kind+" "+cp.Name] = r
		observeDefinitionScan(r, time.Since(start))
	}

	return out
}
func (s *Service) scanFailed(ctx context.Context, reason string) {
	s.log.WarnContext(ctx, "definition scan incomplete", "class", reason)
	observability.ScanIncomplete.WithLabelValues("definition", reason).Inc()
}

// A nested pgx transaction is a savepoint: failed findings writes cannot poison
// the transaction that stores the definitions. Never log the database error,
// whose detail can contain rejected input.
func (s *Service) writeScans(ctx context.Context, tx pgx.Tx, id uuid.UUID, results map[string]definitionscan.Result) {
	if results == nil {
		return
	}
	nested, err := tx.Begin(ctx)
	if err != nil {
		s.scanFailed(ctx, "write")
		return
	}
	defer nested.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
	q := dbgen.New(nested)
	rows, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: id})
	if err == nil {
		for _, row := range rows {
			c := row.McpCapability
			r, ok := results[c.Kind+" "+c.Name]
			if !ok {
				continue
			}
			err = q.DeleteDefinitionFindings(ctx, c.ID)
			if err != nil {
				break
			}
			err = q.StoreDefinitionScan(ctx, dbgen.StoreDefinitionScanParams{CapabilityID: c.ID, Fingerprint: c.Fingerprint, RulesetVersion: r.RulesetVersion, Status: r.Status, Reason: r.Reason})
			if err != nil {
				break
			}
			for _, f := range r.Findings {
				err = q.InsertDefinitionFinding(ctx, dbgen.InsertDefinitionFindingParams{CapabilityID: c.ID, Fingerprint: c.Fingerprint, RuleID: f.RuleID, RulesetVersion: r.RulesetVersion, Severity: f.Severity, Count: int32(f.Count), Location: f.Location})
				if err != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		err = nested.Commit(ctx)
	}
	if err != nil {
		s.scanFailed(ctx, "write")
	}
}

type CapabilityScan struct {
	CapabilityID uuid.UUID             `json:"capabilityId"`
	Scan         definitionscan.Result `json:"scan"`
}

func (s *Service) DefinitionFindings(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, admin, rescan bool) ([]CapabilityScan, error) {
	if a.IsToken() {
		return nil, apperr.New(403, "token_not_allowed", "A browser session is required")
	}
	var sv dbgen.McpServer
	var err error
	if admin {
		if !a.CanReadPlatform() {
			return nil, errPlatformRead
		}
		if rescan && !a.IsPlatformAdmin() {
			return nil, errAdminOnly
		}
		sv, err = anyServer(ctx, s.q, id, false)
	} else {
		ta, e := access(ctx, s.q, a, ref)
		if e != nil {
			return nil, e
		}
		if rescan {
			if e = ta.writable(authz.CheckServerEdit); e != nil {
				return nil, e
			}
		}
		sv, err = teamServer(ctx, s.q, ta.team.ID, id, false)
	}
	if err != nil {
		return nil, err
	}
	if rescan {
		if err = s.rescanDefinitions(ctx, sv); err != nil {
			return nil, err
		}
	}
	st, err := s.q.GetPlatformSettings(ctx)
	if err != nil {
		return nil, err
	}
	caps, err := s.q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: id})
	if err != nil {
		return nil, err
	}
	out := make([]CapabilityScan, 0, len(caps))
	for _, row := range caps {
		c := row.McpCapability
		r := definitionscan.Result{Status: "stale", RulesetVersion: definitionscan.Version, Findings: []definitionscan.Finding{}}
		if st.DefinitionScanMode == "off" {
			r.Status = "off"
		} else {
			scan, e := s.q.GetDefinitionScan(ctx, c.ID)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, e
			}
			if e == nil && scan.Fingerprint == c.Fingerprint && scan.RulesetVersion == definitionscan.Version {
				r.Status = scan.Status
				r.Reason = scan.Reason
				at := scan.ScannedAt
				r.ScannedAt = &at
				fs, e := s.q.ListDefinitionFindings(ctx, c.ID)
				if e != nil {
					return nil, e
				}
				for _, f := range fs {
					r.Findings = append(r.Findings, definitionscan.Finding{RuleID: f.RuleID, Group: definitionscan.RuleGroup(f.RuleID), Severity: f.Severity, Count: int(f.Count), Location: f.Location})
				}
			}
		}
		out = append(out, CapabilityScan{c.ID, r})
	}
	return out, nil
}
func (s *Service) rescanDefinitions(ctx context.Context, sv dbgen.McpServer, staleOnly ...bool) error {
	rows, err := s.q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: sv.ID})
	if err != nil {
		return err
	}
	var caps []upstream.Capability
	ages := map[string]time.Time{}
	pending := len(staleOnly) > 0 && staleOnly[0]
	var names []string
	for _, row := range rows {
		names = append(names, row.McpCapability.Name)
	}
	for _, row := range rows {
		c := row.McpCapability
		if pending {
			if c.GoneAt != nil {
				continue
			}
			scan, e := s.q.GetDefinitionScan(ctx, c.ID)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if e == nil {
				ages[c.Kind+" "+c.Name] = scan.ScannedAt
			}
			if e == nil && scan.Status == "scanned" && scan.Fingerprint == c.Fingerprint && scan.RulesetVersion == definitionscan.Version {
				continue
			}
		}
		caps = append(caps, upstream.Capability{Kind: c.Kind, Name: c.Name, Definition: c.Definition, Fingerprint: c.Fingerprint})
	}
	if pending {
		orderPendingDefinitions(caps, ages)
	}
	results := s.scanDefinitionBatch(ctx, caps, sv.URL, pending, names)
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		if _, err := anyServer(ctx, q, sv.ID, true); err != nil {
			return err
		}
		// Lock and re-check: a concurrent refresh must not bind old findings to new definitions.
		current, err := q.ListMCPCapabilities(ctx, dbgen.ListMCPCapabilitiesParams{ServerID: sv.ID})
		if err != nil {
			return err
		}
		fingerprints := map[string]string{}
		for _, c := range caps {
			fingerprints[c.Kind+" "+c.Name] = c.Fingerprint
		}
		for _, row := range current {
			c := row.McpCapability
			k := c.Kind + " " + c.Name
			if fingerprints[k] != c.Fingerprint {
				delete(results, k)
			}
		}
		s.writeScans(ctx, tx, sv.ID, results)
		return nil
	})
}

// RunScanBackfill performs one bounded pass; a PostgreSQL session advisory lock
// makes replicas agree on a single worker. Missing/incomplete/old scans retry.
func (s *Service) RunScanBackfill(ctx context.Context) error {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, "omp.definition_scan")
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer release()
	st, err := s.q.GetPlatformSettings(ctx)
	if err != nil {
		return err
	}
	if st.DefinitionScanMode == "off" {
		return nil
	}
	ids, err := s.q.DefinitionScanBackfill(ctx, definitionscan.Version)
	if err != nil {
		return err
	}
	for _, id := range ids {
		sv, e := anyServer(ctx, s.q, id, false)
		if e != nil {
			return e
		}
		if e = s.rescanDefinitions(ctx, sv, true); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) ScanBackfillLoop(ctx context.Context) {
	run := func() {
		if err := s.RunScanBackfill(ctx); err != nil {
			s.scanFailed(ctx, "read")
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func observeDefinitionScan(r definitionscan.Result, d time.Duration) {
	observability.ScanDuration.WithLabelValues("definition").Observe(d.Seconds())
	observability.ScanRuleset.WithLabelValues(definitionscan.Version).Set(1)
	if r.Status == "incomplete" {
		observability.ScanIncomplete.WithLabelValues("definition", r.Reason).Inc()
	}
	for _, f := range r.Findings {
		rule := f.RuleID
		if !definitionscan.KnownRule(rule) {
			rule = "other"
		}
		observability.ScanFindings.WithLabelValues("definition", rule, "annotated").Add(float64(f.Count))
	}
}

func orderPendingDefinitions(caps []upstream.Capability, ages map[string]time.Time) {
	sort.SliceStable(caps, func(i, j int) bool {
		return ages[caps[i].Kind+" "+caps[i].Name].Before(ages[caps[j].Kind+" "+caps[j].Name])
	})
}
