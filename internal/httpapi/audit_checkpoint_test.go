package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestAuditCheckpointPublicationAndDelivery(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	ctx := context.Background()
	owner := testutil.OwnerPool(t, app.Pool)
	box, _ := secrets.New(bytes.Repeat([]byte{9}, 32))
	if _, err := app.Pool.Exec(ctx, `SELECT omp_audit.seal_batch('check','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditstream.EnsureCheckpointKey(ctx, app.Pool, box); err != nil {
		t.Fatal(err)
	}
	first, err := auditstream.SubmitCheckpoint(ctx, app.Pool, box)
	if err != nil {
		t.Fatal(err)
	}
	last, err := auditstream.RotateCheckpointKey(ctx, app.Pool, box)
	if err != nil {
		t.Fatal(err)
	}
	code, keys := anonSession(t, app).raw("GET", "/.well-known/omp-audit-keys.json", nil, nil)
	if code != 200 {
		t.Fatalf("anonymous keys: %d %s", code, keys)
	}
	var jwks struct {
		Keys []auditstream.CheckpointJWK `json:"keys"`
	}
	if err := json.Unmarshal(keys, &jwks); err != nil || len(jwks.Keys) != 2 || jwks.Keys[0].RetiredAtSeq == nil || *jwks.Keys[0].RetiredAtSeq != last || jwks.Keys[1].ActiveFromSeq != last {
		t.Fatalf("ranges: %s %v", keys, err)
	}
	code, body := admin.raw("GET", fmt.Sprintf("/v1/admin/audit/stream?after_seq=%d&profile=full", first-1), nil, nil)
	if code != 200 {
		t.Fatalf("stream %d %s", code, body)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var env auditstream.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil || env.Checkpoint == nil {
			t.Fatalf("envelope: %s %v", line, err)
		}
	}
	// Feed the actual HTTP output into the independent stdlib-only verifier.
	script := `import sys,json,struct,uuid
sys.path.insert(0,"../auditevidence/testdata")
from checkpoint_v2 import verify_checkpoint,unbase64
keys=json.loads(sys.argv[1])['keys']
authority={unbase64(k['kid']):(unbase64(k['x']),k['active_from_seq'],k['retired_at_seq']) for k in keys}
for line in sys.stdin:
 e=json.loads(line); c=e['checkpoint']
 from checkpoint_v2 import statement
 s=statement(unbase64(c['statement']))
 record=b'\2\3\0'+uuid.UUID(e['stream_id']).bytes+struct.pack('>Iq',e['epoch'],e['seq'])+bytes(16)+struct.pack('>q',s[5])+bytes.fromhex(e['summary_hash'])+bytes.fromhex(e['entry_hash'])
 assert verify_checkpoint(record,c,bytes.fromhex(c['covered_chain_hash']),authority).hex()==e['chain_hash']
`
	cmd := exec.Command("python3", "-c", script, string(keys))
	cmd.Stdin = bytes.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python real stream: %v %s", err, out)
	}
	code, full := admin.raw("GET", fmt.Sprintf("/v1/admin/audit/entries/%d/full", first), nil, nil)
	if code != 200 || !bytes.Contains(full, []byte(`"checkpoint":`)) {
		t.Fatalf("full: %d %s", code, full)
	}
	path := fmt.Sprintf("/v1/admin/audit/verify?from=%d&to=%d", first, last)
	code, body = admin.raw("GET", path, nil, nil)
	if code != 200 || !bytes.Contains(body, []byte(`"valid":true`)) {
		t.Fatalf("verify: %d %s", code, body)
	}
	// Simulate a database-owner compromise by bypassing the append-only trigger.
	if _, err := owner.Exec(ctx, `ALTER TABLE omp_audit.chain DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	// Owner tampering is detected, with the exact first bad sequence.
	if _, err := owner.Exec(ctx, `UPDATE omp_audit.chain SET checkpoint_signatures=set_byte(checkpoint_signatures,0,get_byte(checkpoint_signatures,0)#1) WHERE seq=$1`, first); err != nil {
		t.Fatal(err)
	}
	code, body = admin.raw("GET", path, nil, nil)
	if code != 200 || !bytes.Contains(body, []byte(fmt.Sprintf(`"first_bad_seq":%d`, first))) {
		t.Fatalf("tamper: %d %s", code, body)
	}
}
