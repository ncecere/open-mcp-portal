// Package keyrotation rotates the install-wide secrets
// (docs/phase6-operations.md "Key rotation", decision 36; adapted from
// Grounded's internal/keyrotation):
//
//   - ENCRYPTION_KEY: Run re-seals every stored ciphertext still on
//     ENCRYPTION_KEY_PREVIOUS with the current key, column by column, in
//     batches with row locks, one transaction per batch, with the same
//     associated data. It first checks that every value opens with one of
//     the two keys and stops, naming table and row, if any doesn't. It is
//     idempotent, resumable and safe while the app serves (readers accept
//     both keys). Audited as platform.secrets_reencrypt (per batch) and
//     platform.key_rotation (counts only).
//   - API_KEY_PEPPER: digests can't be re-made without the key, so
//     internal/apikeys and internal/serviceaccounts re-digest each key on its
//     next use while API_KEY_PEPPER_PREVIOUS is set. Run lists the usable
//     keys still on another pepper.
package keyrotation

import (
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// Column is one column of internal/secrets ciphertexts, in a table keyed by
// Key (of SQL type KeyType: uuid, text or bigint), with the associated data
// each value is sealed with.
type Column struct {
	Table, Column, Key, KeyType string
	AAD                         func(key string) []byte
}

// Name is "table.column".
func (c Column) Name() string { return c.Table + "." + c.Column }

func (c Column) table() string { return pgx.Identifier{c.Table}.Sanitize() }
func (c Column) col() string   { return pgx.Identifier{c.Column}.Sanitize() }
func (c Column) key() string   { return pgx.Identifier{c.Key}.Sanitize() }

// start is the keyset position before the first row.
func (c Column) start() string {
	switch c.KeyType {
	case "uuid":
		return uuid.Nil.String()
	case "bigint":
		return "-1"
	}
	return ""
}

func uuidAAD(f func(uuid.UUID) []byte) func(string) []byte {
	return func(k string) []byte {
		id, _ := uuid.Parse(k)
		return f(id)
	}
}

func callAAD(part string) func(string) []byte {
	return func(k string) []byte {
		id, _ := strconv.ParseInt(k, 10, 64)
		return capture.AAD(id, part)
	}
}

// Columns is every column that holds sealed values. Other secrets (OIDC)
// come from the environment and are rotated there. A test fails if the
// schema gains a *_cipher column that is not listed here.
var Columns = []Column{
	{Table: "mcp_servers", Column: "auth_value_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(registry.ServerAAD)},
	// A server's own credential parts (registry.CredentialAAD): the value (or
	// Basic user name) and the Basic password.
	{Table: "mcp_server_credentials", Column: "value_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(registry.CredentialAAD)},
	{Table: "mcp_server_credentials", Column: "secondary_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(registry.CredentialSecondaryAAD)},
	// A person's own secret for a server in person_secret mode (decision 72;
	// registry.PersonSecretAAD), and the link a call returns for entering one
	// (personsecrets.RequestAAD).
	{Table: "person_secrets", Column: "secret_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(registry.PersonSecretAAD)},
	{Table: "secret_requests", Column: "id_cipher", Key: "id_digest", KeyType: "text",
		AAD: func(k string) []byte { return personsecrets.RequestAAD(k) }},
	// identity.keyAAD
	{Table: "signing_keys", Column: "private_key_cipher", Key: "kid", KeyType: "text",
		AAD: func(k string) []byte { return []byte("signing_key:" + k) }},
	{Table: "auth_providers", Column: "client_secret_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(providers.SecretAAD)},
	{Table: "provider_connections", Column: "access_token_cipher", Key: "id", KeyType: "uuid",
		AAD: uuidAAD(func(id uuid.UUID) []byte { return providers.TokenAAD(id, "access") })},
	{Table: "provider_connections", Column: "refresh_token_cipher", Key: "id", KeyType: "uuid",
		AAD: uuidAAD(func(id uuid.UUID) []byte { return providers.TokenAAD(id, "refresh") })},
	// providers.stateAAD
	{Table: "provider_auth_states", Column: "code_verifier_cipher", Key: "state_digest", KeyType: "text",
		AAD: func(k string) []byte { return []byte("provider_auth_state:" + k) }},
	// providers.requestAAD
	{Table: "provider_connect_requests", Column: "id_cipher", Key: "id_digest", KeyType: "text",
		AAD: func(k string) []byte { return []byte("provider_connect_request:" + k) }},
	// Webhook destinations (internal/notify): the URL and the signing secrets.
	{Table: "notification_destinations", Column: "url_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(notify.URLAAD)},
	{Table: "notification_destinations", Column: "secret_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(notify.SecretAAD)},
	{Table: "notification_destinations", Column: "secret_previous_cipher", Key: "id", KeyType: "uuid", AAD: uuidAAD(notify.PreviousSecretAAD)},
	{Table: "mcp_call_payloads", Column: "arguments_cipher", Key: "call_id", KeyType: "bigint", AAD: callAAD(capture.PartArguments)},
	{Table: "mcp_call_payloads", Column: "result_cipher", Key: "call_id", KeyType: "bigint", AAD: callAAD(capture.PartResult)},
}
