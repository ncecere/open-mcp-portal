package keyrotation_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/doctor"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

const (
	oldKey   = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	newKey   = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY="
	strayKey = "enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmF6eXh3dnU="
)

func box(t *testing.T, current string, previous ...string) *secrets.Box {
	t.Helper()
	k, _ := secrets.ParseKey(current)
	var prev [][]byte
	for _, p := range previous {
		pk, _ := secrets.ParseKey(p)
		prev = append(prev, pk)
	}
	b, err := secrets.New(k, prev...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func scalar(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var out string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&out); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// seed stores one sealed value in every column, sealed with b, and returns
// each column's key.
func seed(t *testing.T, pool *pgxpool.Pool, b *secrets.Box) map[string]string {
	t.Helper()
	user := scalar(t, pool, `INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('t', 's', 'a@example.com', 'A') RETURNING id::text`)
	team := scalar(t, pool, `INSERT INTO teams (slug, name) VALUES ('t', 'T') RETURNING id::text`)
	keys := map[string]string{
		"mcp_servers":               scalar(t, pool, `INSERT INTO mcp_servers (team_id, slug, name, url, auth_header_name, auth_value_cipher) VALUES ($1, 's', 'S', 'https://x', 'X-Api-Key', '\x00') RETURNING id::text`, team),
		"signing_keys":              "kid-1",
		"auth_providers":            scalar(t, pool, `INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url) VALUES ('p', 'P', 'c', 'none', true, 'https://a', 'https://t') RETURNING id::text`),
		"provider_auth_states":      strings.Repeat("a", 64),
		"provider_connect_requests": strings.Repeat("B", 43),
		"secret_requests":           strings.Repeat("C", 43),
	}

	keys["mcp_server_credentials"] = scalar(t, pool, `INSERT INTO mcp_server_credentials (server_id, position, kind, value_cipher, secondary_cipher) VALUES ($1, 0, 'basic', '\x00', '\x00') RETURNING id::text`, keys["mcp_servers"])
	keys["person_secrets"] = scalar(t, pool, `INSERT INTO person_secrets (user_id, server_id, origin, secret_cipher) VALUES ($1, $2, 'https://x', '\x00') RETURNING id::text`, user, keys["mcp_servers"])
	// A machine OAuth client (decision 73) is keyed by its server.
	scalar(t, pool, `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) VALUES ($1, 'https://idp.example/token', 'c', '\x00') RETURNING server_id::text`, keys["mcp_servers"])
	keys["mcp_server_machine_oauth"] = keys["mcp_servers"]
	keys["mcp_server_tls"] = scalar(t, pool, `INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after)
		VALUES ($1, 'x', '\x00', repeat('a', 64), now() + interval '30 days') RETURNING server_id::text`, keys["mcp_servers"])
	keys["provider_connections"] = scalar(t, pool, `INSERT INTO provider_connections (user_id, provider_id, status, access_token_cipher) VALUES ($1, $2, 'active', '\x00') RETURNING id::text`, user, keys["auth_providers"])
	keys["service_connections"] = scalar(t, pool, `INSERT INTO service_connections(team_id,provider_id,name) VALUES($1,$2,'shared') RETURNING id::text`, team, keys["auth_providers"])
	keys["service_connection_auth_states"] = strings.Repeat("d", 64)
	scalar(t, pool, `INSERT INTO service_connection_auth_states(state_digest,user_id,session_digest,connection_id,revision,generation,provider_id,provider_revision,client_revision,scopes,expires_at) VALUES($1,$2,$1,$3,1,1,$4,1,1,'{}',now()+interval '1 hour') RETURNING state_digest`, keys["service_connection_auth_states"], user, keys["service_connections"], keys["auth_providers"])
	gw := scalar(t, pool, `INSERT INTO gateways (slug, name, owner_kind) VALUES ('g', 'G', 'platform') RETURNING id::text`)
	keys["mcp_call_payloads"] = scalar(t, pool, `INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome) VALUES ('tools/call', $1, 'g', 'G', $2, 'ok') RETURNING id::text`, gw, user)
	scalar(t, pool, `INSERT INTO signing_keys (kid, private_key_cipher, public_jwk, state, retire_after)
		VALUES ('kid-1', '\x00', '{}', 'retiring', now() + interval '1 day') RETURNING kid`)
	scalar(t, pool, `INSERT INTO provider_auth_states (state_digest, user_id, session_digest, provider_id, scopes, expires_at) VALUES ($1, $2, $1, $3, '{}', now() + interval '1 hour') RETURNING state_digest`, keys["provider_auth_states"], user, keys["auth_providers"])
	scalar(t, pool, `INSERT INTO provider_connect_requests (id_digest, id_cipher, user_id, provider_id, required_scopes, reason, gateway_id, gateway_slug, gateway_name, capability_id, capability_kind, exposed_name, expires_at) VALUES ($1, '\x00', $2, $3, '{}', 'not_connected', $4, 'g', 'G', gen_random_uuid(), 'tool', 'x', now() + interval '1 hour') RETURNING id_digest`, keys["provider_connect_requests"], user, keys["auth_providers"], gw)
	scalar(t, pool, `INSERT INTO secret_requests (id_digest, id_cipher, user_id, server_id, server_origin, reason, gateway_id, gateway_slug, gateway_name, capability_id, capability_kind, exposed_name, expires_at) VALUES ($1, '\x00', $2, $3, 'https://x', 'secret_missing', $4, 'g', 'G', gen_random_uuid(), 'tool', 'x', now() + interval '1 hour') RETURNING id_digest`, keys["secret_requests"], user, keys["mcp_servers"], gw)
	scalar(t, pool, `INSERT INTO mcp_call_payloads (call_id, occurred_at, by_gateway, by_server, arguments_cipher, result_cipher, arguments_bytes) VALUES ($1::bigint, now(), true, false, '\x00', '\x00', 1) RETURNING call_id::text`, keys["mcp_call_payloads"])
	keys["notification_destinations"] = scalar(t, pool, `INSERT INTO notification_destinations (scope, name, format, url_cipher, url_display, secret_cipher, secret_previous_cipher, events)
		VALUES ('platform', 'hook', 'json', '\x00', 'https://h.example.com/...', '\x00', '\x00', '{publish.requested}') RETURNING id::text`)
	for _, c := range keyrotation.Columns {
		ct, err := b.Seal([]byte("secret of "+c.Name()), c.AAD(keys[c.Table]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE `+c.Table+` SET `+c.Column+` = $1 WHERE `+c.Key+`::text = $2`, ct, keys[c.Table]); err != nil {
			t.Fatalf("%s: %v", c.Name(), err)
		}
	}
	return keys
}

// Every *_cipher column in the schema is listed in Columns.
func TestColumnsCoverTheSchema(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	rows, err := pool.Query(context.Background(), `SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type = 'bytea' AND column_name LIKE '%cipher%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var listed []string
	for _, c := range keyrotation.Columns {
		listed = append(listed, c.Name())
	}
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		if !slices.Contains(listed, name) {
			t.Errorf("%s holds sealed values but rotate-keys doesn't re-encrypt it", name)
		}
	}
}

func TestRotateKeys(t *testing.T) {
	ctx := context.Background()
	pool, dbURL := testutil.NewDB(t)
	keys := seed(t, pool, box(t, oldKey))
	rotating := box(t, newKey, oldKey)
	pep, _ := secrets.ParseKey(oldKey)
	peppers := keyrotation.Peppers{Current: pep}

	// Doctor sees every value on the previous key.
	cfg := config.Defaults()
	cfg.DatabaseURL, cfg.AppURL, cfg.DevAuth = dbURL, "http://localhost:8088", true
	cfg.EncryptionKey, cfg.EncryptionKeyPrevious, cfg.APIKeyPepper = newKey, oldKey, oldKey
	rep := doctor.Run(ctx, cfg, doctor.Options{Timeout: 10 * time.Second})
	if c := find(rep, "encryption"); c.Status != doctor.Info || !strings.Contains(c.Detail, fmt.Sprintf("%d sealed value(s) still on ENCRYPTION_KEY_PREVIOUS", len(keyrotation.Columns))) {
		t.Fatalf("doctor before = %+v", c)
	}

	var out bytes.Buffer
	sum, err := keyrotation.Run(ctx, pool, rotating, peppers, keyrotation.Options{DryRun: true, Out: &out})
	if err != nil || sum.Reencrypted() != 0 {
		t.Fatalf("dry run = %v %d", err, sum.Reencrypted())
	}
	for _, c := range sum.Columns {
		if c.Previous != 1 || c.Total != 1 {
			t.Errorf("dry run %s = %+v", c.Column, c)
		}
	}
	if scalar(t, pool, `SELECT count(*)::text FROM audit_log WHERE action LIKE 'platform.%'`) != "0" {
		t.Fatal("a dry run wrote to the audit log")
	}

	sum, err = keyrotation.Run(ctx, pool, rotating, peppers, keyrotation.Options{BatchSize: 1, Out: &out})
	if err != nil || sum.Reencrypted() != len(keyrotation.Columns) {
		t.Fatalf("run = %v %d\n%s", err, sum.Reencrypted(), out.String())
	}
	// Every value opens with the new key alone, with the same AAD.
	onlyNew := box(t, newKey)
	for _, c := range keyrotation.Columns {
		var ct []byte
		if err := pool.QueryRow(ctx, `SELECT `+c.Column+` FROM `+c.Table+` WHERE `+c.Key+`::text = $1`, keys[c.Table]).Scan(&ct); err != nil {
			t.Fatal(err)
		}
		plain, err := onlyNew.Open(ct, c.AAD(keys[c.Table]))
		if err != nil || string(plain) != "secret of "+c.Name() {
			t.Errorf("%s after rotation: %q %v", c.Name(), plain, err)
		}
	}
	if n := scalar(t, pool, `SELECT count(*)::text FROM audit_log WHERE action = 'platform.secrets_reencrypt'`); n != strconv.Itoa(len(keyrotation.Columns)) {
		t.Errorf("per-batch audit entries = %s", n)
	}
	if meta := scalar(t, pool, `SELECT metadata::text FROM audit_log WHERE action = 'platform.key_rotation'`); strings.Contains(meta, "secret of") {
		t.Errorf("rotation audit holds a secret: %s", meta)
	}
	// Idempotent.
	sum, err = keyrotation.Run(ctx, pool, rotating, peppers, keyrotation.Options{})
	if err != nil || sum.Reencrypted() != 0 {
		t.Fatalf("second run = %v %d", err, sum.Reencrypted())
	}
	rep = doctor.Run(ctx, cfg, doctor.Options{Timeout: 10 * time.Second})
	if c := find(rep, "encryption"); c.Status != doctor.Info || !strings.Contains(c.Detail, "can be removed") {
		t.Fatalf("doctor after = %+v", c)
	}

	// A value sealed with a key that is neither: nothing is written, and the
	// row is named.
	stray, _ := box(t, strayKey).Seal([]byte("x"), keyrotation.Columns[0].AAD(keys["mcp_servers"]))
	if _, err := pool.Exec(ctx, `UPDATE mcp_servers SET auth_value_cipher = $1`, stray); err != nil {
		t.Fatal(err)
	}
	// ... and a value still on the previous key, which must not be touched.
	argsCol := keyrotation.Columns[len(keyrotation.Columns)-2]
	old, _ := box(t, oldKey).Seal([]byte("x"), argsCol.AAD(keys["mcp_call_payloads"]))
	if _, err := pool.Exec(ctx, `UPDATE mcp_call_payloads SET arguments_cipher = $1`, old); err != nil {
		t.Fatal(err)
	}
	payloadBefore := scalar(t, pool, `SELECT encode(arguments_cipher, 'hex') FROM mcp_call_payloads`)
	_, err = keyrotation.Run(ctx, pool, rotating, peppers, keyrotation.Options{})
	var bad *keyrotation.UndecryptableError
	if !errors.As(err, &bad) {
		t.Fatalf("an undecryptable value must stop the run: %v", err)
	}
	if !strings.Contains(err.Error(), "mcp_servers.auth_value_cipher "+keys["mcp_servers"]) {
		t.Errorf("error names %s", err)
	}
	if scalar(t, pool, `SELECT encode(arguments_cipher, 'hex') FROM mcp_call_payloads`) != payloadBefore {
		t.Fatal("values were re-encrypted despite an undecryptable one")
	}
	cfg.EncryptionKeyPrevious = ""
	if c := find(doctor.Run(ctx, cfg, doctor.Options{}), "encryption"); c.Status != doctor.Fail {
		t.Fatalf("doctor with an undecryptable value = %+v", c)
	}
}

func find(rep doctor.Report, name string) doctor.Check {
	for _, c := range rep.Checks {
		if c.Group == "keys" && c.Name == name {
			return c
		}
	}
	return doctor.Check{}
}
