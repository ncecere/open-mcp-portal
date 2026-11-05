package retention

import (
	"context"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"testing"
)

func TestStrictPeriods(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"call_metadata":null}`, `{"call_metadata":"90"}`, `{"call_metadata":1.0}`, `{"call_metadata":0}`, `{"call_metadata":3651}`, `{"call_metadata":true}`} {
		if _, err := decodeSettings(dbgen.RetentionSetting{Periods: []byte(raw)}); err == nil {
			t.Errorf("accepted platform %s", raw)
		}
		if _, err := TeamOverrides(dbgen.Team{RetentionOverrides: []byte(raw)}); err == nil {
			t.Errorf("accepted team %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"call_metadata":1}`, `{"call_metadata":3650}`} {
		if _, err := decodeSettings(dbgen.RetentionSetting{Periods: []byte(raw)}); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestGoSQLCallDaysParity(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	for _, raw := range []string{`{}`, `{"call_metadata":1}`, `{"call_metadata":3650}`, `null`, `[]`, `{"call_metadata":null}`, `{"call_metadata":"90"}`, `{"call_metadata":1.0}`, `{"call_metadata":0}`, `{"call_metadata":3651}`, `{"call_metadata":true}`} {
		st, goErr := decodeSettings(dbgen.RetentionSetting{Periods: []byte(raw)})
		var sqlDays int32
		sqlErr := o.QueryRow(context.Background(), `SELECT omp_audit.call_days($1::jsonb,90)`, raw).Scan(&sqlDays)
		if (goErr == nil) != (sqlErr == nil) {
			t.Fatalf("%s Go=%v SQL=%v", raw, goErr, sqlErr)
		}
		if goErr == nil && st.Periods[CallMetadata] != sqlDays {
			t.Fatalf("%s Go=%d SQL=%d", raw, st.Periods[CallMetadata], sqlDays)
		}
	}
}
