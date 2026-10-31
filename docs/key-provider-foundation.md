# Key-provider adapter foundation (#41 only)

`internal/keyprovider` is isolated, unused by portal runtime code, and does not
change `secrets.Box`, version-1 ciphertext, `ENCRYPTION_KEY`, `Derive`, schema,
rotation, doctor, configuration loading, authorities or sealed-column coverage.
This is **not** acceptance of envelope encryption or live KMS security.

## Narrow API and profile

`Provider` wraps/unwraps exactly 32-byte caller-owned data keys, with a stable,
non-secret `Reference`. `Rewrapper` is optional and never returns plaintext.
`Wrapped` is an in-memory adapter result, not an allocated storage format.
Reference equality is checked before I/O. References include the exact origin,
mount and key name, but exclude credentials and wrapping-key versions. Use a
single canonical configured origin; equivalent spelling is not normalized.
A reference is routing metadata, not an authenticated envelope or proof of
provenance. Do not deserialize it as authority to select arbitrary providers.

The Transit adapter's deliberately narrow profile requires a **pre-provisioned,
derived, non-convergent aes256-gcm96 key**. The service/operator is trusted to
configure that profile correctly; this adapter does not read configuration or
prove server-side key attributes. The nonempty binding (1–1024 bytes) is base64
Transit **derivation context**, not portal row AAD. Callers must retain exactly
that context. This does not decide future AAD/epoch/restore contracts.

`TransitConfig` takes an origin (HTTPS, no path/query/userinfo/fragment), a mount
(one or more slash-separated segments), key name and explicit positive
`WriteVersion`. Segments allow only ASCII letters, digits, `_`, `-`, length
1–128; the mount is capped at 512 bytes. No leading/trailing slash or encoded
path syntax is allowed. Writes/rewraps send `key_version` and reject another
returned version; unwrap accepts any positive version encoded in a valid blob
and leaves minimum-version policy to Transit. Rewrap refuses a local downgrade.
Provision/rotate separately and construct a new adapter with the target version;
there is no version discovery, key creation or management API here.

Inject a `TokenSource(context.Context)`; it must cooperate with deadlines and
must not log credentials. No environment, home auth files, login exchange,
renewal, default token or fallback is consulted. The adapter cannot preempt an
arbitrary non-cooperating caller function. The credential is used only in the
`X-Vault-Token` header. The caller should supply only existing encrypt/decrypt/
rewrap authority: in particular no `create` capability (Transit encrypt can
upsert missing keys with `create`). No RBAC mutations are performed.

System TLS verification is the default, TLS >=1.2; an optional cloned CA pool
replaces system roots. There is no verification bypass, proxy discovery,
redirect following (even same-origin), retry, replay, or fallback. HTTP is only
allowed with explicit `AllowLoopbackHTTP` and a literal loopback IP, never DNS
`localhost` or arbitrary private hosts. No public fixture is hosted.

## Wire protocol and bounds

Single POSTs to `/v1/<mount>/encrypt/<key>`, `decrypt/<key>`, `rewrap/<key>`
use JSON base64 plaintext/context and opaque `vault:vN:<base64>` ciphertext.
Only HTTP 200 is success. The AES-GCM blob must be exactly 60 decoded bytes
(12-byte nonce, 32-byte data key, 16-byte tag), canonical padded base64, with a
canonical positive uint32 version; ciphertext text is capped at 4096 bytes.
Unwrap requires canonical base64 decoding to exactly 32 bytes. Writes require
`data.ciphertext`; if returned, `data.key_version` must agree. Missing/wrong
required field types, duplicates anywhere (including escaped field aliases),
trailing JSON, depth >32, success/error hybrids and response-wrapping envelopes
are refused. Unknown metadata fields remain allowed for protocol compatibility.
The total response and response headers are each bounded at 16 KiB. Requests
are bounded by fixed fields and validated inputs; token length <=4096 bytes.
Timeout defaults to 5s, can be lowered, cannot exceed 30s, and includes token
acquisition, dialing, TLS, headers and body. Parent cancellation applies.
Each valid operation makes at most one HTTP attempt; connections are not reused.
A failure may still mean the remote write completed; no automatic replay occurs.

Errors are typed `*Error` with fixed `Kind` and optional HTTP `Status`; original
transport/source/service errors and bodies are never wrapped, returned or
logged. 401/403 are authorization refusal; other non-200 statuses are service
refusal. No master-key/export/backup endpoint exists. Unwrap necessarily returns
confidential data-key bytes to its caller. Go cannot promise complete memory
zeroization; callers must not log keys, request objects, or credential sources.

## Sources and tests

Protocol reviewed against official, versioned sources (read as untrusted data):
- [Vault v1.21.x Transit API](https://developer.hashicorp.com/vault/api-docs/v1.21.x/secret/transit), encrypt/decrypt/rewrap, derived-key context and upsert capabilities.
- [OpenBao v2.4.0 Transit API source](https://github.com/openbao/openbao/blob/v2.4.0/website/content/api-docs/secret/transit.mdx), corresponding endpoints and AES-GCM profile.

Tests use owned `httptest` TLS servers and locally generated AES-GCM keys,
with HKDF solely to model context-dependent keys (not a claim to reproduce
Transit's internal KDF). They exercise real encrypt/decrypt/rewrap round trips,
version changes, wrong context/key reference/version, response corruption,
size limits, duplicates, service failures, authorization, redirects, TLS trust,
timeouts/cancellation, input injection and sentinel-safe errors/logs. They
assert HTTP attempt counts and that redirects never reach another origin.
Run `go test -p 2 -timeout 20m ./internal/keyprovider` and the same with `-race`.

No genuine OpenBao/Vault instance or owner's services were contacted. Real-KMS,
full-suite/database-role, browser/deployment and restore gates remain separate.
Before envelope integration the parent must review crypto/profile attestation,
AAD/context binding, epoch IDs, restore/rotation, storage format and failure/
cache semantics. No outage availability claim is made here.
