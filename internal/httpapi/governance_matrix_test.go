package httpapi_test

import "github.com/google/uuid"

// otherTeam is the fixture team a transfer goes to or comes from: A for the
// callers' own team B, and B for A.
func (c *mctx) otherTeam() teamFix {
	if c.tf.slug == c.e.a.slug {
		return c.e.b
	}
	return c.e.a
}

// transfer is a pending transfer (revision 1) of a fresh private server: out of
// the team under test, or into it (incoming). The callers who may not answer
// it get a transfer that does not exist, which is refused the same way before
// their role is looked at or after it.
func (c *mctx) transfer(incoming bool) string {
	if !c.allowed {
		return uuid.NewString()
	}
	from, to := *c.tf, c.otherTeam()
	if incoming {
		from, to = to, from
	}
	srv := c.e.newServer(from, "private")
	return c.e.exec(`INSERT INTO server_transfers (server_id, from_team_id, to_team_id, server_revision)
		SELECT id, team_id, $2::uuid, revision FROM mcp_servers WHERE id = $1 RETURNING id::text`, srv, to.id)
}
