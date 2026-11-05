package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"log/slog"
	"strings"
	"testing"
)

func TestScanningSettingsAPI(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	auditor := app.signIn("auditor")
	user := app.signIn("user")
	const path = "/v1/admin/settings/scanning"
	var st apitypes.ScanningSettings
	if code := auditor.get(path, &st); code != 200 || string(st.DefinitionMode) != "shadow" || st.Revision != 1 {
		t.Fatalf("%d %+v", code, st)
	}
	if code, _ := user.raw("GET", path, nil, nil); code != 403 {
		t.Fatal(code)
	}
	body := map[string]any{"definitionMode": "off"}
	if code, _ := auditor.raw("PUT", path, body, ifMatch(1)); code != 403 {
		t.Fatal(code)
	}
	if code, _ := admin.raw("PUT", path, body, nil); code != 428 {
		t.Fatal(code)
	}
	if code, b := admin.raw("PUT", path, body, ifMatch(1)); code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	if code, b := admin.raw("PUT", path, body, ifMatch(1)); code != 409 {
		t.Fatalf("%d %s", code, b)
	}
	var before, after string
	if err := app.Pool.QueryRow(context.Background(), `SELECT before_state::text,after_state::text FROM audit_log WHERE action='settings.scanning_update'`).Scan(&before, &after); err != nil {
		t.Fatal(err)
	}
	if before != `{"definitionMode": "shadow"}` || after != `{"definitionMode": "off"}` {
		t.Fatalf("%s %s", before, after)
	}
	if code, b := admin.raw("GET", "/v1/admin/scanning/rules", nil, nil); code != 200 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestScanningPrivacySentinel(t *testing.T) {
	logs := &syncBuffer{}
	sr := tracingOn(t)
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app := newTestAppLog(t, nil, log)
	admin := app.signIn("admin")
	ctx := context.Background()
	canary := "scanSentinel" + strings.ReplaceAll(uuid.NewString(), "-", "")
	token := "ghp_" + canary
	raw, _ := json.Marshal(map[string]any{"name": "sentinel", canary: canary, "inputSchema": map[string]any{"properties": map[string]any{canary: map[string]string{"description": token + " unmatched-" + canary}}}})
	var team, server string
	if err := app.Pool.QueryRow(ctx, `INSERT INTO teams(slug,name)VALUES('scan-sentinel','Scan')RETURNING id::text`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	if err := app.Pool.QueryRow(ctx, `INSERT INTO mcp_servers(team_id,slug,name,url)VALUES($1,'s','S','https://example.org')RETURNING id::text`, team).Scan(&server); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pool.Exec(ctx, `INSERT INTO mcp_capabilities(server_id,kind,name,definition,fingerprint)VALUES($1,'tool','sentinel',$2,repeat('a',64))`, server, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pool.Exec(ctx, `INSERT INTO team_members(team_id,user_id,role)SELECT $1,id,'editor' FROM users WHERE email='admin@localhost'`, team); err != nil {
		t.Fatal(err)
	}
	paths := []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/admin/mcp-servers/" + server + "/scan", nil},
		{"GET", "/v1/admin/mcp-servers/" + server + "/scan-findings", nil},
		{"POST", "/v1/teams/scan-sentinel/mcp-servers/" + server + "/scan", nil},
		{"GET", "/v1/teams/scan-sentinel/mcp-servers/" + server + "/scan-findings", nil},
		{"GET", "/v1/admin/scanning/rules", nil},
		{"GET", "/v1/admin/settings/scanning", nil},
	}
	for _, p := range paths {
		code, body := admin.raw(p.method, p.path, p.body, nil)
		if code != 200 {
			t.Fatalf("%s: %d %s", p.path, code, body)
		}
		if p.method == "POST" && !strings.Contains(string(body), `"ruleId":"secret.github"`) {
			t.Fatal("rescan did not detect the matched-span canary")
		}
		if strings.Contains(string(body), canary) {
			t.Fatal("HTTP response leaked canary")
		}
	}
	code, body := admin.raw("PUT", "/v1/admin/settings/scanning", map[string]any{"definitionMode": canary}, ifMatch(1))
	if code != 422 || strings.Contains(string(body), canary) {
		t.Fatalf("error %d %s", code, body)
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatal("debug log leaked canary")
	}
	if len(sr.Ended()) == 0 {
		t.Fatal("no exported spans")
	}
	for _, span := range sr.Ended() {
		evidence := fmt.Sprint(span.Name(), span.Attributes(), span.Events(), span.Links(), span.Status())
		if strings.Contains(evidence, canary) {
			t.Fatal("span leaked canary")
		}
	}
	families, err := observability.NewMetrics(app.Pool).Gather().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if strings.Contains(f.String(), canary) {
			t.Fatal("metric leaked canary")
		}
	}
	rows, err := app.Pool.Query(ctx, `SELECT schemaname,tablename FROM pg_tables WHERE schemaname IN ('public','omp_private')`)
	if err != nil {
		t.Fatal(err)
	}
	var tables [][2]string
	for rows.Next() {
		var table [2]string
		if err = rows.Scan(&table[0], &table[1]); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	for _, table := range tables {
		query := `SELECT coalesce(json_agg(to_jsonb(t)`
		if table[0] == "public" && table[1] == "mcp_capabilities" {
			query += `-'definition'`
		}
		query += `),'[]'::json)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` t`
		var dump string
		if err = app.Pool.QueryRow(ctx, query).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(dump, canary) {
			t.Fatalf("database canary in %v", table)
		}
	}
}
