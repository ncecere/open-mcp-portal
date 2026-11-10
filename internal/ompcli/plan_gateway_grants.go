package ompcli

import (
	"context"
	"fmt"
	"time"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// clock is the time omp measures grant deadlines against (tests replace it).
var clock = time.Now

// grantWrite is one permanent grant the step creates. A replacement removes
// old first; any non-nil deadline is refused while the plan is built.
type grantWrite struct {
	subject string
	body    ompclient.GatewayGrantCreate // without a deadline
	// deadline records a requested/retained absolute deadline. Non-nil values
	// are not writable through the relative-day API and always refuse.
	deadline *time.Time
	clamp    bool
	// old is the permanent grant a replacement removes before creating the new
	// one. Failed creation never restores it: another actor may have revoked it.
	old  *ompclient.GatewayGrant
	days *int32 // resolved when the step starts, before its first write
}

func grantBody(g Grant, scope *ToolScope) ompclient.GatewayGrantCreate {
	body := ompclient.GatewayGrantCreate{}
	switch {
	case g.Team != "":
		team := g.Team
		body.SubjectKind, body.Team = ompclient.GatewayGrantSubjectKindTeam, &team
	case g.Group != "":
		group := g.Group
		body.SubjectKind, body.Group = ompclient.GatewayGrantSubjectKindGroup, &group
	default:
		email := g.UserEmail
		body.SubjectKind, body.UserEmail = ompclient.GatewayGrantSubjectKindUser, &email
	}
	if scope != nil && !scope.Unrestricted {
		ts := ompclient.ToolScope{}
		if scope.Classes != nil {
			cl := make([]ompclient.ToolClass, len(*scope.Classes))
			for i, c := range *scope.Classes {
				cl[i] = ompclient.ToolClass(c)
			}
			ts.Classes = &cl
		}
		ts.Tools = scope.Tools
		body.ToolScope = &ts
	}
	return body
}

// daysFor refuses writes that would need an absolute deadline. The API only
// accepts a day count relative to its own authoritative clock; subtracting a
// guessed clock-skew allowance cannot guarantee the preserved deadline. Reading
// and comparing an unchanged expiring grant is safe; recreating one is not.
func daysFor(deadline *time.Time, _ bool) (*int32, error) {
	if deadline == nil {
		return nil, nil
	}
	return nil, fmt.Errorf("the portal accepts relative whole-day lifetimes, not an absolute expiresAt; omp cannot preserve this deadline independently of clock skew, so change this grant in the web UI")
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// deadlineMet compares authoritative timestamps exactly. No allowance may
// treat a grant that lives beyond the declared deadline as compliant.
func deadlineMet(want, have time.Time) bool { return have.Equal(want) }

// grantPair is a declared grant beside the portal's grant for the same subject.
type grantPair struct {
	subject      string
	want         Grant
	deadline     *time.Time // the declared expiresAt; nil when the file leaves it out
	hg           ompclient.GatewayGrant
	have         Grant // hg in the file's form
	scopeDiffers bool
}

// planGrants compares the declared grants with the portal's, by subject: what
// to add, what to replace (a changed ceiling or a shorter deadline) and what
// to remove.
func (g *gatewayPlan) planGrants(ctx context.Context, cur ompclient.Gateway) error {
	haveGrants := map[string]ompclient.GatewayGrant{}
	if !g.create {
		grants, err := getGatewayGrants(ctx, g.p.c, cur.Id)
		if err != nil {
			return err
		}
		for _, hg := range grants {
			haveGrants[grantFrom(hg).subject()] = hg
		}
	}
	wantGrants := map[string]Grant{}
	for _, wg := range *g.d.Grants {
		wantGrants[wg.subject()] = wg
	}
	now := clock()
	for _, k := range sortedKeys(wantGrants) {
		if err := g.planGrant(k, wantGrants[k], haveGrants, now); err != nil {
			return err
		}
	}
	for _, k := range sortedKeys(haveGrants) {
		if _, ok := wantGrants[k]; !ok {
			g.planGrantRemoval(k, haveGrants[k], now)
		}
	}
	return nil
}

// planGrant plans one declared grant: new, elapsed in the portal, or active.
func (g *gatewayPlan) planGrant(k string, wg Grant, haveGrants map[string]ompclient.GatewayGrant, now time.Time) error {
	var want *time.Time
	if wg.ExpiresAt != "" {
		t, _ := time.Parse(time.RFC3339, wg.ExpiresAt) // validated by the file
		want = &t
	}
	hg, ok := haveGrants[k]
	if !ok {
		return g.planNewGrant(k, wg, want, now)
	}
	have := grantFrom(hg)
	pair := grantPair{
		subject: k, want: wg, deadline: want, hg: hg, have: have,
		scopeDiffers: wg.ToolScope != nil && scopeKey(wg.ToolScope) != scopeKey(have.ToolScope),
	}
	if hg.ExpiresAt != nil && !hg.ExpiresAt.After(now) {
		return g.planElapsedGrant(pair, now)
	}
	return g.planActiveGrant(pair)
}

func (g *gatewayPlan) planNewGrant(k string, wg Grant, want *time.Time, now time.Time) error {
	label := k
	if want != nil {
		if !want.After(now) {
			return refuseErr("gateway %s: grant %s expires at %s, which is already past: omp will not create a grant that has already expired.", g.d.Slug, k, fmtTime(*want))
		}
		if _, err := daysFor(want, false); err != nil {
			return refuseErr("gateway %s: grant %s: expiresAt %s: %v.", g.d.Slug, k, fmtTime(*want), err)
		}
		label += " (expires " + fmtTime(*want) + ")"
	}
	g.add("grant", nil, label)
	g.grantAdds = append(g.grantAdds, grantWrite{subject: k, body: grantBody(wg, wg.ToolScope), deadline: want})
	return nil
}

// planElapsedGrant handles a grant whose deadline has passed. Elapsed: it
// grants nothing now, whether or not it is still listed.
func (g *gatewayPlan) planElapsedGrant(pr grantPair, now time.Time) error {
	k, want := pr.subject, pr.deadline
	expired := *pr.hg.ExpiresAt
	switch {
	case want != nil && deadlineMet(*want, expired) && !pr.scopeDiffers:
		return nil // the file records the grant as expired: in sync
	case want != nil && want.After(now):
		if _, err := daysFor(want, false); err != nil {
			return refuseErr("gateway %s: grant %s: expiresAt %s: %v.", g.d.Slug, k, fmtTime(*want), err)
		}
		scope := pr.want.ToolScope
		if scope == nil {
			scope = pr.have.ToolScope // renewing never widens the ceiling
		}
		g.add("grant "+k, "expired "+fmtTime(expired), "expires "+fmtTime(*want))
		if pr.scopeDiffers {
			g.add("grant "+k+" toolScope", scopeKey(pr.have.ToolScope), scopeKey(pr.want.ToolScope))
		}
		g.grantAdds = append(g.grantAdds, grantWrite{subject: k, body: grantBody(pr.want, scope), deadline: want})
		return nil
	default:
		return refuseErr("gateway %s: grant %s expired at %s and grants nothing now. omp will not recreate it as a permanent grant or with a past deadline. Renew temporary grants in the web UI; to drop it, leave it out of grants (it may stay listed until cleanup).", g.d.Slug, k, fmtTime(expired))
	}
}

// planActiveGrant handles a grant that still grants access. Active: keep its
// deadline unless the file asks for a shorter one.
func (g *gatewayPlan) planActiveGrant(pr grantPair) error {
	k, want, hg := pr.subject, pr.deadline, pr.hg
	shorten := false
	if want != nil && (hg.ExpiresAt == nil || !deadlineMet(*want, *hg.ExpiresAt)) {
		if hg.ExpiresAt != nil && hg.ExpiresAt.Before(*want) {
			return refuseErr("gateway %s: grant %s expires at %s but the file says %s. omp never extends a grant (the portal cannot change a deadline, only create a grant with a new one). Change temporary grants in the web UI, or keep the portal's deadline by leaving expiresAt out.", g.d.Slug, k, fmtTime(*hg.ExpiresAt), fmtTime(*want))
		}
		shorten = true
	}
	if !pr.scopeDiffers && !shorten {
		return nil
	}
	deadline := hg.ExpiresAt // retained: same deadline, at most
	if shorten {
		deadline = want
	}
	w := grantWrite{subject: k, deadline: deadline, clamp: !shorten, old: &hg}
	scope := pr.have.ToolScope
	if pr.scopeDiffers {
		scope = pr.want.ToolScope
		g.add("grant "+k+" toolScope", scopeKey(pr.have.ToolScope), scopeKey(pr.want.ToolScope))
	}
	if shorten {
		from := any("permanent")
		if hg.ExpiresAt != nil {
			from = fmtTime(*hg.ExpiresAt)
		}
		g.add("grant "+k+" expiresAt", from, fmtTime(*want))
	}
	if _, err := daysFor(deadline, w.clamp); err != nil {
		return refuseErr("gateway %s: grant %s cannot be changed in place (the portal has no update, only remove and create): %v. omp never makes a grant outlive its current deadline: change temporary grants in the web UI.", g.d.Slug, k, err)
	}
	w.body = grantBody(pr.want, scope)
	g.grantReplaces = append(g.grantReplaces, w)
	return nil
}

func (g *gatewayPlan) planGrantRemoval(k string, hg ompclient.GatewayGrant, now time.Time) {
	label := k
	if hg.ExpiresAt != nil && !hg.ExpiresAt.After(now) {
		label += " (expired " + fmtTime(*hg.ExpiresAt) + ")"
	}
	g.add("grant", label, nil)
	g.grantRemoves = append(g.grantRemoves, hg)
}
