package auditstream

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// This pins PostgreSQL's byte encoding independently of the Go codec. It is
// deliberately not a seal_batch acceptance test: migration 63 is still required.
func TestCheckpointSQLGolden(t *testing.T) {
	p, _ := testutil.NewDB(t)
	raw, err := os.ReadFile("testdata/checkpoint_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []checkpointVector
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		statementBytes, err := hex.DecodeString(v.Statement)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ParseCheckpointStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		signatures, err := hex.DecodeString(v.Signatures)
		if err != nil {
			t.Fatal(err)
		}
		var kids []byte
		for _, kid := range s.Kids {
			kids = append(kids, kid[:]...)
		}
		var statementHex, summaryHex, recordHex, chainHex string
		err = p.QueryRow(ctx, `WITH statement AS (
   SELECT convert_to('OMP-AUDIT-CHECKPOINT','UTF8')||decode('00563100','hex')||uuid_send($1::uuid)||int4send($2::integer)||int8send($3::bigint)||int8send($4::bigint)||$5::bytea||int8send($6::bigint)||decode(lpad(to_hex($7::integer),2,'0'),'hex')||$8::bytea AS raw
  ), summary AS (
   SELECT raw,sha256(convert_to('OMP-AUDIT-CHECKPOINT-SUMMARY','UTF8')||decode('00563100','hex')||raw||$9::bytea) AS hash FROM statement
  ), record AS (
   SELECT raw,hash,decode('020300','hex')||uuid_send($1::uuid)||int4send($2::integer)||int8send($3::bigint)||decode(repeat('00',16),'hex')||int8send($6::bigint)||hash||decode(repeat('00',32),'hex') AS bytes FROM summary
  ) SELECT encode(raw,'hex'),encode(hash,'hex'),encode(bytes,'hex'),encode(sha256(convert_to('OMP-AUDIT-EVIDENCE','UTF8')||decode('00','hex')||convert_to('CHAIN','UTF8')||decode('00563200','hex')||$5::bytea||bytes),'hex') FROM record`, s.Stream, int32(s.Epoch), s.Seq, s.CoveredSeq, s.CoveredHash[:], s.IssuedAtMicros, len(s.Kids), kids, signatures).Scan(&statementHex, &summaryHex, &recordHex, &chainHex)
		if err != nil {
			t.Fatal(err)
		}
		if statementHex != v.Statement || summaryHex != v.Summary || recordHex != v.Record || chainHex != v.Chain {
			t.Fatal("SQL checkpoint vector mismatch")
		}
	}
}
