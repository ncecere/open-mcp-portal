package registry

import "testing"

func TestExplicitSameOwnerStillRequiresCurrentEligibility(t *testing.T) {
	for name, sql := range map[string]string{
		"left team":         `DELETE FROM team_members WHERE user_id=$1`,
		"demoted to member": `UPDATE team_members SET role='member' WHERE user_id=$1`,
		"suspended":         `UPDATE users SET status='suspended' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newGovEnv(t)
			srv := e.server("owner-check", "published")
			if _, err := e.govern(e.admin, srv, GovernanceInput{SetOwner: true, OwnerUserID: &e.editor}); err != nil {
				t.Fatal(err)
			}
			e.run(sql, e.editor)
			revision := e.rev(srv)
			if _, err := e.govern(e.admin, srv, GovernanceInput{SetOwner: true, OwnerUserID: &e.editor}); code(err) != "invalid_owner" {
				t.Fatalf("explicitly retained an ineligible owner: %v", err)
			}
			if e.rev(srv) != revision {
				t.Fatal("refused owner assignment changed revision")
			}
			// Omitting the owner is different: unrelated bookkeeping remains editable,
			// and live ownerless attention continues to identify the invalid owner.
			view, err := e.govern(e.admin, srv, GovernanceInput{SetOncall: true, OncallContact: str("#support")})
			if err != nil || !view.Governance.Ownerless {
				t.Fatalf("unrelated edit or ownerless derivation: %+v %v", view.Governance, err)
			}
		})
	}
}
