# Operating audit webhook sinks

Use a platform-admin browser session and its CSRF protection for `/v1/admin/settings/audit-sinks`. Automation tokens
cannot manage or read sink configuration. Auditors may list and inspect sinks; stream status also accepts a
`platform:read` token at `/v1/admin/audit/stream/status`. The Admin Audit stream page is a separate implementation part.

Create with POST, for example `{"name":"Evidence","url":"https://receiver.example/audit","profile":"full",
"required":true,"enabled":true,"batch_max_records":100}`. Store the returned `secret` immediately: it is generated
from 32 random bytes and shown once. URLs are write-only; responses expose only the destination host. Destination
resolution is checked at save and at dial under the separate `AUDIT_STREAM_ALLOWED_NETWORKS` policy.

Read the sink's `revision` and pass `If-Match: "<revision>"` on PUT, DELETE and every action. A stale revision returns
409. PUT changes supplied settings; omitted fields are preserved. POST `/{id}/rotate-secret` shows the new secret once,
with both old and new signatures for 24 hours. POST `/{id}/test` sends a signed `audit.test` containing no audit records,
reports a fixed `error_class` (empty on success), and never moves the cursor. Configure/test before enabling the
rollout gate described in [deployment](deploy.md).

Required sinks cap retention even when disabled. Receiver outages can therefore grow database usage without bound;
monitor lag, storage, silence and failures. Unrequiring or deleting a sink releases that hold and is audited. Optional
sinks may expire when retention passes their cursor. Resume an expired sink with POST `/{id}/resume`, `If-Match` and
`{"cursor_seq":<observed cursor>}`. The resulting signed gap has fixed endpoints and must be acknowledged before data
continues. A portal resume never approves a new trust anchor at the receiver; preserve previous evidence and approve
the discontinuity locally. Promotion to required is refused until recovery and gap delivery complete.

A required full sink delivers an oversized envelope but holds at the preceding sequence. Retrieve the complete row
through `/v1/admin/audit/entries/{seq}/full`, preserve it, then POST `/{id}/oversized/{seq}/acknowledge` with the observed
revision. The database validates the exact next oversized sequence, advances one, and audits atomically. Optional
sinks deliver the envelope and advance automatically.

Verify `X-OMP-Signature` against the exact request body before parsing. The signing key is the displayed secret text
(not its base64-decoded bytes). Accept any matching `v1` during rotation, use constant-time comparison and reject stale
timestamps, for example in Python:

```python
import hashlib, hmac, time

def authentic(secret, headers, body):
    timestamp = headers['X-OMP-Timestamp']
    if abs(time.time() - int(timestamp)) > 300:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b'.' + body,
                        hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(part.strip(), 'v1=' + expected)
               for part in headers['X-OMP-Signature'].split(','))
```

Persist by pinned stream id and sequence, verify the chain and checkpoint signatures using authenticated key
enrollment, and return 2xx only after durable storage. Apply records by sequence: delayed stale-leader requests may
arrive after newer ranges. Ignore only identical duplicates. Preserve a different hash at an existing sequence as
fork evidence and alert; buffer future sequences and alert on gaps and silence. Delivery ids support retry deduplication,
not trust. A compromised runtime can forge delivery acknowledgements and signing operations; earlier independently
stored evidence and receiver monitoring provide the boundary.
