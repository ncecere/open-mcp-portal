package httpapi_test

import (
	"context"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
)

func (c *mctx) sealAudit() {
	c.e.t.Helper()
	if _, err := (auditstream.Sealer{Pool: c.e.app.Pool}).Batch(context.Background()); err != nil {
		c.e.t.Fatal(err)
	}
}
func (c *mctx) consumerRevision() string {
	return `"` + c.e.exec(`SELECT consumer_revision::text FROM omp_audit.retention_floor`) + `"`
}
func (c *mctx) ensureConsumer(name string) {
	c.e.exec(`SELECT CASE WHEN EXISTS(SELECT 1 FROM omp_audit.consumers WHERE name=$1) THEN '' ELSE omp_audit.register_consumer($1,'summary',false,$2)::text END`, name, c.e.userIDs[cPlatformAdmin])
}
