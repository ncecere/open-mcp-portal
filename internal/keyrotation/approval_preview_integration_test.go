package keyrotation_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestTerminalApprovalPreviewRotatesWithoutDisclosureOrRestoration(t *testing.T) {
	ctx := context.Background()
	db, _ := testutil.NewDB(t)
	keys := seed(t, db, box(t, oldKey))
	id := uuid.MustParse(keys["approval_requests"])
	if _, err := db.Exec(ctx, `UPDATE approval_requests SET status='denied',review_revision=2,decided_by=requester_id,decided_at=now(),terminal_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	before, err := dbgen.New(db).GetApprovalRequest(ctx, id)
	if err != nil || before.PreviewCipher != nil {
		t.Fatalf("terminal preview visible before rotation: %v", err)
	}
	if _, err = keyrotation.Run(ctx, db, box(t, newKey, oldKey), keyrotation.Peppers{}, keyrotation.Options{BatchSize: 1}); err != nil {
		t.Fatal(err)
	}
	var cipher []byte
	if err = db.QueryRow(ctx, `SELECT preview_cipher FROM approval_requests WHERE id=$1`, id).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	clear, err := box(t, newKey).Open(cipher, approvals.PreviewAAD(id))
	if err != nil || string(clear) != "secret of approval_requests.preview_cipher" {
		t.Fatalf("preview lost key/AAD binding: %v", err)
	}
	after, err := dbgen.New(db).GetApprovalRequest(ctx, id)
	if err != nil || after.PreviewCipher != nil || after.Status != "denied" || after.ReviewRevision != before.ReviewRevision {
		t.Fatalf("rotation changed terminal authority: %v", err)
	}
	if _, err = db.Exec(ctx, `UPDATE approval_requests SET preview_cipher=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE approval_requests SET preview_cipher=$2 WHERE id=$1`, id, cipher); err == nil {
		t.Fatal("cleared terminal preview was restored")
	}
}
