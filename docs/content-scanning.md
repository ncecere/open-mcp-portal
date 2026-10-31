# Content scanning: design (#52, decision 50)

**Status: design with the shared secret-registry foundation implemented (#71).** No scanner, migration, API or
setting is wired into refresh or call paths. The portal today fingerprints and withholds changed tool definitions, and redacts secret-looking values
in *captured* payloads, but it does not read definitions, arguments or results for prompt injection, hidden
Unicode or data loss ([threat model 7.5](threat-model.md#75-tool-poisoning-and-change-detection)). Everything below
marked **proposed default (owner may override)** is the assistant's recommendation under the owner's delegation of
the issue's open questions, not an owner decision. Latency and false-positive figures are targets to be proven by
the acceptance tests in [section 11](#11-acceptance-tests-the-first-build-issue-must-pass), not measurements.

A scanner that misses a novel injection makes people relax. The design therefore starts from what scanning cannot
do ([section 9](#9-what-this-will-not-catch)) and treats findings as input for human review and for the controls
that already exist (approval of definitions, classification, scopes, curation, exact-call approvals), never as a
safety verdict.

Names: Open MCP Portal is "the portal"; a **gateway** is the feature (a curated set of capabilities at
`/mcp/{slug}`). The sister project Open Model Gateway (OMG) is the LLM gateway; the portal is not one
([roadmap](roadmap.md#what-the-portal-is-and-isnt)).

## 0. Summary and recommendation

**Go, narrowly.** Build detection that runs in shadow mode first, starting where it is cheapest and safest: static
checks of tool definitions when they are refreshed, shown to the people who already review them. Do not build
blocking, a hosted model or default external scanning. Each later stage is gated on measured false positives.

| # | Proposed default (owner may override) | Reasoning |
|---|---|---|
| P1 | **Detection-only (shadow) first.** Findings are recorded and shown; nothing is blocked, redacted, rewritten or approved on their basis. Enforcement needs measured false positives per rule group ([section 7](#7-rollout-plan)). The platform ceiling defaults to `shadow` for every stage. | A lexical detector has unknown false-positive rates on your tools, and an unexplained block of a tool call is an outage. The issue's recommendation, adopted. |
| P2 | **External scanning only on explicit per-gateway opt-in**, enabled first by a platform admin, vetoable by the server's team, off by default and not in the first slices. Content is redacted before sending, identity is never sent, only rule ids and counts come back. | Decision 45 already treats names and emails going to third parties as a data-protection matter; call content is more sensitive. The issue's recommendation, adopted. |
| P3 | **Review-time definition checks before argument DLP.** | Off the hot path, in process, no data leaves, reuses the approval and review flow. The issue's recommendation, adopted. |
| P4 | **The portal hosts no model and calls no LLM as a scanner.** An operator who wants a model classifier runs it behind the external contract in [3.4](#34-optional-external-scanning-service). | The portal is not an LLM gateway; classifiers are also bypassable ([section 9](#9-what-this-will-not-catch)). |
| P5 | **Evidence is rule id, stage, severity, count, action and (definitions only) a location pointer. Never matched text, excerpts, offsets into calls or hashes of matched values.** | Findings about calls link a person to a behaviour; storing the text would make the findings table a second, unprotected payload store. |
| P6 | **Fail open at every stage by default**; fail closed only where a policy asks for it and the platform ceiling allows. A scan that did not finish is recorded as `scan_incomplete`, never as "clean". | A scanner bug must not become an outage; an incomplete scan must not look like a pass. |
| P7 | **Findings are never part of the review digest, never auto-act on an approved definition, and the UI never shows a "passed" or "safe" badge.** | The digest binds what a reviewer read ([registry.md](registry.md#discovery-and-change-detection)); a ruleset update must not invalidate reviews, and "no findings" must not read as "safe". |
| P8 | **No personal-data (PII) detectors in the first slices.** Secrets and credential shapes only. | Detecting personal data is itself processing personal data; see [5.4](#54-data-protection-review-note). |
| P9 | **Argument scans see the effective (curation-merged) arguments without the top-level members the gateway owner fixed.** | Fixed values are owner policy, not model output, and "equal versus omitted fixed value" must give the same findings, as it does for approval bindings ([gateway-curation.md](gateway-curation.md#execution-and-retries)). |
| P10 | **A scan-triggered "require approval" reuses the exact-call approval path and is additive only** ([4.4](#44-interaction-with-exact-call-approvals-decisions-48-52-82)). Scan outcomes after authorization was spent never restore it. | Decision 82. |
| P11 | **Policy editing mirrors payload-capture opt-in** (decision 32): gateway owners and admins for their gateway (platform admins for platform gateways), the server's team owners and admins for their server, platform admins for ceilings. Browser session only, audited. | An existing, reviewed permission shape. |
| P12 | **Call findings follow call-metadata retention** (90 days by default), not the 14-day payload retention. | They hold no content. |

**Not decided here** (owner input needed, [section 12](#12-owner-input-and-open-questions)): how this design relates to
OMG's guardrails design, and the data-protection review.

## 1. Threat catalogue

The portal sits between an MCP client (with its model) and servers that teams register. What reaches a model
through a gateway is: tool, prompt and resource **definitions** (lists), **results** (`tools/call`, `prompts/get`,
`resources/read`, error text, relayed progress and elicitation text), and nothing else the server chose. What goes
the other way is **arguments**. The research below is why each row exists; sources are in
[Appendix B](#appendix-b-sources).

| ID | Threat | Public evidence | Already covered (code) | Not covered |
| --- | --- | --- | --- | --- |
| T1 | **Tool poisoning**: instructions hidden in a tool's description or schema that the model follows and the user does not see (read a secret file and pass it in an extra parameter, conceal it). Applies to every string in the definition: name, title, description, parameter names, parameter descriptions, defaults, enum values, `outputSchema`, annotations, prompt arguments, resource names and URIs. | Invariant Labs' disclosure [B1]; MCPTox: 1,348 poisoning test cases built on 45 real servers and 353 tools, tested on 20 agents, attack success up to 72.8%, highest refusal rate under 3% [B4]; OWASP says to treat the entire schema as an injection surface [B13] | Fingerprint of the whole definition without `_meta` (`internal/upstream/capability.go`); a catalog tool is served only while `approved_fingerprint = fingerprint` (`internal/gateways/selection.go` `Availability`); approval is bound to what the reviewer saw (`reviewDigest`, `internal/registry/digest.go`, F-2); titles clipped to 200 and descriptions to 10,000 characters, definitions over 64 KiB fail discovery (`capability.go` `MaxTitle`, `MaxDescription`, `MaxDefinition`). Annotations are never trusted (SPEC §10) | Nothing **reads** the text; the reviewer is the control. A team's own server needs no approval for its own gateways (threat model UP-2 gap), so a poisoned description reaches teammates immediately. A gateway owner's `descriptionOverride` (≤2,000 characters) is authored text no one reviews. Property descriptions are not rewritten by curation |
| T2 | **Hidden or bidirectional Unicode**: tag characters (U+E0000 block) that models read and people do not see, bidi controls that reorder what a reviewer sees (Trojan Source), zero-width and variation-selector payloads, mixed-script confusable names. | Tag-character prompt injection [B10]; Trojan Source (CVE-2021-42574, CVE-2021-42694) [B9]; data hidden in variation selectors [B11]; UTS #39 [B12] | Tool and resource **names** must be valid UTF-8 without control characters (`validName` in `capability.go` rejects only `unicode.IsControl`, category Cc) | Format characters (category Cf: bidi controls, zero-width, tag characters) pass `validName` and are accepted in titles, descriptions and schema text. The review UI renders what it is given |
| T3 | **Rug pull**: a server changes a definition after approval, or behaves differently from its description. | Invariant's sleeper server that changes its tool description after a trigger [B2] | A changed definition drops out of the gateway once a refresh stores it (`Availability`), and a refresh never approves. Definitions change in the portal only when someone refreshes (`registry/discovery.go` `refresh`; the scheduled loop stores health checks, not capabilities) | Behaviour change behind an unchanged definition; nothing compares what a result does with what the description promised |
| T4 | **Cross-tool instructions and shadowing**: one server's description tells the model how to use another server's tool (redirect all email, add a recipient). One gateway mixing servers puts them in one model context. | Invariant's shadowing and WhatsApp experiments [B1][B2]; Snyk Agent Scan lists "cross-server tool reference" as an issue [B17] | Exposed names are `{serverSlug}__{name}`, so two servers cannot define the same exposed tool (`gateways.ExposedName`) | Text that merely *refers* to another tool; confusable names across servers; the gateway composition is not analysed |
| T5 | **Indirect injection in results**: instructions inside a tool result, a resource's contents or a prompt's messages (web pages, tickets, mail, files), written by a third party the tool fetched from. `prompts/get` messages go straight into the model context. | Indirect prompt injection [B19]; Microsoft's MCP write-up [B16]; benchmarks in [section 10](#10-test-corpus-plan) | Results are scrubbed of `_meta.serverInfo` and echoed tokens, non-object `structuredContent` is dropped for legacy clients, bodies are capped at 1 MiB (`internal/mcpgw/call.go` `relay`, `scrubMetaFor`, `MaxResponseBytes`) | Content is relayed unread. Error text from servers (≤300 characters, redacted of credentials, `upstream.SafeMessage`), relayed progress messages (≤1,000 bytes, ≤64 events, `mcpgw/stream.go`) and relayed elicitation messages (≤4 KiB, `mcpgw/relay.go`, modern clients) reach the client/model/person unread too |
| T6 | **Exfiltration through arguments to a third-party server**: an injected model puts private data in a parameter (an extra "sidenote", a search query, an email subject). The lethal trifecta: private data, untrusted content, an outward channel. | Invariant [B1]; Willison's lethal trifecta [B15]; OWASP "data exfiltration via legitimate channels" [B13]; the MCP specification says clients should show tool inputs to the user before calling and validate results before passing them to the model, and servers must validate inputs and sanitize outputs [B14] | Owner-set classes and tool scopes limit which tools a credential can call (#28, #29); curation can fix or restrict argument values (#30); exact-call approvals can stop sensitive tools (#31); `sendIdentity` limits what a server learns about the person (decisions 45, 64) | The arguments themselves are forwarded unread. Nothing limits free-text parameters |
| T7 | **Secrets and personal data in either direction**: a credential pasted into an argument, a token in a result. | n/a | Captured copies are redacted (built-in rules, sensitive key names, admin patterns, the call's own credentials; `internal/capture/redact.go`); approval previews are redacted too; the live result has echoed tokens replaced (`relay`) | The live arguments and results are not scanned or altered; capture redaction protects only the stored copy. No personal-data detection at all |
| T8 | **Active content in results**: markdown images or links with data in the URL, HTML, URLs a client may fetch on its own (`resource_link`). | Willison [B15] ("external communication" vectors) | None | Not inspected |
| T9 | **Confused deputy, over-broad credentials, SSRF from the portal** | OWASP [B13] | Sections 6.4, 6.5 and 7.1, 7.2 of the threat model | Not a scanning problem; out of scope here |
| T10 | **Threats scanning itself creates**: a scanner oracle (an attacker probes what is blocked), denial of service by crafted input (catastrophic regexes, deep JSON), tuning that locks out legitimate tools, a findings table that becomes a payload store, an external service that receives call content. | n/a | Go's `regexp` is RE2 and runs in linear time; admin patterns are already bounded (`capture.Compile`: 50 patterns, 500 characters) | Designed for in sections 2 to 6 |

**What definitions look like in practice.** Because the review digest covers every capability's fingerprint and the
fingerprint covers the whole definition, a reviewer *could* read everything. In practice a server can list up to
500 entries per kind with up to 64 KiB each, and reviewers do not read schema text or invisible characters.
Scanning's job is to direct attention, not to replace the approval.

## 2. Where scanning can run

Six places, one of them not a scan. All budgets are **proposed starting points**, not measurements: the first build
issue measures on CI hardware and then fixes gates with at least 2x headroom. Go's `regexp` is linear-time but not
fast, so any stage that scans up to 1 MiB needs literal prefilters (for example, look for `eyJ`, `-----BEGIN`,
`AKIA`, `ghp_` before running a pattern) and a deadline, rather than running every pattern over every byte.

| Stage | Hook (verified at v0.8.0) | What it sees | Possible actions | Proposed budget and limits | On error or over budget |
| --- | --- | --- | --- | --- | --- |
| **S-def**: discovery and refresh | `(*Service).refresh` in `internal/registry/discovery.go`, over `d.Capabilities` after `probe` and **before** the `InTx` that calls `storeCapabilities`; findings written in the same transaction as the upsert. Reached by a manual Refresh, an automation-token refresh, or the setup sign-in refresh (`registry/oauth.go`). Scheduled health checks do not store capabilities and are not a hook | One definition: ≤64 KiB canonical JSON, ≤500 per kind (`upstream/client.go` `pager`), titles/descriptions already clipped | Annotate only. Never changes, withholds or re-approves a definition (that stays the existing fingerprint rule) | In process, CPU only, no network. Start: ≤25 ms p99 per definition, ≤2 s total wall time per refresh; capabilities not reached inside it are marked `scan_incomplete` (reason `budget`) and picked up by the next rescan or backfill | Capability marked `scan_incomplete`; the refresh succeeds. Never fails a refresh |
| **S-cur**: curation text | Gateway selection save in `internal/gateways` (`curation.Policy.DescriptionOverride`, ≤2,000 characters; the name override is limited to `[A-Za-z0-9_.-]`) | The owner-authored text and fixed values | Annotate (follow-up F11) | Microseconds | Fail open |
| **S-arg**: arguments before forwarding | `(*request).call` in `internal/mcpgw/call.go`, **after** `curation.Merge` and **before** `checkRetry`/`forward`, so a finding precedes credential lookup, consent links, approval `Begin` and any transport. `resources/read` has only a URI (≤8 KiB, `maxReadURI`) | Effective arguments: request bodies are ≤1 MiB, tool arguments are normally a few KiB; prompt arguments are strings | Annotate; block; require approval (tools only: approvals apply to `tools/call`); `redact` is **not** offered ([4.1](#41-actions)) | Request path, adds to every call's latency. Start: ≤2 ms p95 for ≤16 KiB; a hard deadline (start: 25 ms) | Per policy: open (default) records `scan_incomplete`; closed refuses with `content_scan_unavailable` |
| **S-res**: results before relay | `(*request).relay` in `internal/mcpgw/call.go` (the issue cites `relay.go`; `relay.go` now holds the elicitation relay). `tools/call`, `prompts/get` and `resources/read` all end in `forwardCall` → `relay`. Runs on `encoded` **after** `scrubMetaFor` and the token scrub, **before** `captureResult` and `reply`, i.e. it scans exactly what the client will receive | `content[]` text, embedded resource text, `resource_link` fields, `structuredContent`, prompt `messages[]`, `contents[]` of a read, `isError` text; ≤1 MiB | Annotate; redact (secret rules only); withhold ([4.3](#43-results-after-a-call-ran)) | Adds to the response path after the upstream wait. Start: ≤5 ms p95 for ≤64 KiB, hard deadline 100 ms | As above |
| **S-prog**: streamed progress | `fwd.OnProgress` in `(*request).forward` (`call.go`) already applies `rc.scrubText` to `p.Message`; `(*stream).progress` in `mcpgw/stream.go` writes it. ≤64 events, ≤1,000 bytes each, ≤4 MiB total (`maxProgressEvents`, `maxProgressMessage`, `maxStreamBytes`) | `message` only (the progress numbers are numbers) | Annotate; redact (secret rules only; progress carries nothing the call needs) | ≤64 × 1,000 bytes: negligible | Event passes (open) |
| **S-cap**: captured payloads | `internal/capture/redact.go` `Redactor.Redact`, called from `capture.Service.Prepare`. **This is storage-time redaction, not detection**, and stays that way | The captured copy, after the call outcome is fixed | none | n/a | Capture failures are already only logged (`Observer.Failed`) |

### 2.1 What each stage gets right and wrong

- **Definitions** are the best first target: a stored, size-bounded value, scanned once per fingerprint and not per
  call, whose findings go to people who already review (the publish dialog, the Capabilities tab, `registry.md`
  "Publishing"). They are also where the research evidence (T1, T2) is strongest. Because definitions change only on
  refresh, a ruleset update is applied by a **rescan of stored definitions** (no upstream contact), not by waiting
  for refreshes.
- **Arguments** are the only stage that can stop data *before* it leaves, and the only one where a block cannot have
  had a side effect. They are also the hot path: every `tools/call` pays. Secrets and credential shapes are the
  one category with a plausible precision.
- **Results** carry the largest injection surface (T5) and the weakest signal: instructions in results look like
  ordinary text, and a tool that fetches a security article legitimately quotes them. A result is scanned **after
  the tool ran**, so for a write or destructive tool a "block" would hide an effect that already happened
  ([4.3](#43-results-after-a-call-ran)).
- **Progress** is committed to the SSE stream as it arrives (`startStream` commits the 200 response when the call
  is about to reach the server), so it can be scanned inline but never held back for a later verdict.
- **Capture** must not grow a second job. Its redaction counts per rule (`capture.Part.Rules`, metric
  `omp_payload_redactions_total{rule}`) are the model for evidence, not a source of findings.

### 2.2 `structuredContent`, binary parts and shape-specific rules

A scan walks the parsed JSON, never raw text, because JSON escapes hide characters (`\u202e`, a tag character as a
surrogate pair) from a byte-level search. It scans every string **value** and, with a length cap, every object
**key** (keys are attacker text too), with a depth limit (start: 64) and a node limit (start: 200,000). Beyond a
limit the stage reports `scan_incomplete` with reason `depth` or `size`; truncating silently would let an attacker
put the payload after the cut.

| Part | Treatment |
| --- | --- |
| `content[].text`, embedded `resource.text`, prompt message text | Scanned. |
| `structuredContent` (any JSON value in the modern era; object only for legacy, after `scrubMetaFor`) | String leaves and keys scanned. Text and `structuredContent` usually repeat each other: identical strings are scanned once per call (in-memory dedupe, never stored). |
| `image` and `audio` parts, `blob` of embedded resources (base64) | **Not scanned** by the text detectors in any proposed slice; counted as `binary_unscanned` (info, count only) so an operator can see what fraction of content was never read. Image-borne instructions, steganography and OCR are explicitly out of reach ([section 9](#9-what-this-will-not-catch)). A later option is to decode small `text/*` and `application/json` blobs (≤64 KiB); that is not in the first slices. The capture redactor already treats these parts as `[binary N bytes]`. |
| `resource_link` (`uri`, `name`, `title`, `description`) and embedded resource `uri` | Scanned as text; the URI is also examined for markup-style exfiltration shapes (T8) once result rules ship. The portal does not fetch the link. |
| `_meta` and `annotations` | Strings scanned at lowest priority (clients may show them; models rarely do). |
| Error text from a server | Already ≤300 characters; scanned with the result rules. |
| `isError: true` results | Scanned like any result (tool errors are text the model reads). |

Scanning runs on **what the client receives**, so `relay` scans after the portal's own scrub. That keeps the
rules about the portal's credentials (the exact-value scrub of `rc.scrub`) ahead of the pattern rules.

### 2.3 Concurrency and cost control

Scans run in the request goroutine under a deadline, so a crafted input cannot hold a request or a CPU. The build
issue adds a per-replica bound on concurrent scans (start: the number of CPUs); a request that cannot take a slot
is treated as over budget (`scan_incomplete`, reason `busy`), under the stage's fail policy. There is no queue.
Scanning never holds a database transaction, an approval lock or the server lease across the scan, and never uses
the network (except the optional external service, [3.4](#34-optional-external-scanning-service)).

## 3. Detectors

All built-in detectors are deterministic, run in process and are versioned as one **ruleset** (for example
`scan-rules-v1`). A ruleset change is a code change with its own corpus results; findings record the ruleset
version that produced them, so shadow data from two versions are never mixed.

### 3.1 Secret and credential shapes, reusing the redaction engine

`internal/capture/redact.go` already holds the portal's secret patterns (`BuiltInRules`: `private_key_pem`, `bearer`,
`jwt`, `gateway_credentials`, `github`, `gitlab`, `slack`, `google`, `aws_access_key`, `url_userinfo`), the
sensitive JSON member names (`SensitiveKeys`) and the exact-value rule for the call's own credentials. The design
reuses them rather than writing a second list:

- Move the patterns to one rule registry (the build issue chooses the package; the proposal is `internal/scan`),
  imported by `capture`. **Redaction behaviour must not change**: `TestBuiltInRules`, `TestCompileRefusals` and the
  capture sentinel tests keep passing unmodified.
- Add a *detect* view over the same rules: `Find(text)` returns rule id and count, never the match.
- Ids are `secret.<capture rule name>` (`secret.github`, `secret.aws_access_key`, `secret.private_key_pem`, ...).

**Detection needs a stricter profile than redaction.** Redaction can afford to over-match (a false positive costs a
`[REDACTED]` in a stored copy); detection that blocks or pages a reviewer cannot. Reading the current patterns:

| Rule | Why it is too loose to detect with as written |
| --- | --- |
| `bearer`: `(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*` | Matches ordinary prose ("the bearer of this letter", "bearer bonds"). The detect profile requires a token of at least 20 characters that is not a dictionary-shaped word, or an `Authorization:` prefix. |
| `google`: `ya29\.[A-Za-z0-9_.-]+` | No minimum length. |
| `github`, `gitlab`, `slack`, `aws_access_key` | Documentation placeholders match: `ghp_` followed by 36 `x`, and AWS's documented example key `AKIAIOSFODNN7EXAMPLE` [B18]. The detect profile suppresses single-repeated-character runs and values containing `EXAMPLE`, `example`, `xxxx` or `<...>`. |
| `url_userinfo` | `postgres://user:password@localhost` in documentation. |
| `jwt` | Sample tokens in documentation and tests. High confidence only if all three segments decode as JSON/base64url of plausible length; otherwise `low`. |
| `sensitive_keys` (by member **name**) | Any `login` tool has a `password` parameter. It is `info`, count only, and off by default in detect profiles. |

Findings for these rules at `high` severity are the only ones proposed for early enforcement ([section 7](#7-rollout-plan)),
and only after the benign corpus in [section 10](#10-test-corpus-plan) and shadow data show the placeholder
suppression holds.

Admin-supplied patterns (the capture settings' RE2 expressions) are **not** reused for detection by default: they
are redaction patterns, written for a different purpose. A separate, bounded custom-rule list for scanning is a
later follow-up (F13), with the same limits (`capture.MaxPatterns` = 50, 500 characters, no pattern that matches
the empty string) and the metric label `pattern`.

#### Shared-registry foundation (#71)

`internal/secretrules` now owns the unchanged redaction implementation, built-in regexes,
sensitive keys and exact-value normalization. `capture` retains compatibility aliases and wrappers;
its output, rule names, ordering, binary handling, counts and truncation remain unchanged.

The registry's `Redactor.Find(text)` is a text primitive, not a stage scanner. It returns only
`Finding{RuleID, Count}`, in catalog order (`secret.<capture name>`), with counts saturating at
100,000. Rules count independently, including overlaps; exact values count last, longest first,
without overlapping each other. Known exact values retain the six-byte/encoded-form handling and
are not suppressed as placeholders. Admin redaction patterns and sensitive-key names are not detected.
A future JSON scanner must explicitly select and traverse strings and keys and track unscanned data.

`DefaultDetectProfile()` returns separate data: bearer payloads require 20 characters and a
non-letter character unless preceded by `Authorization:`; Google OAuth payloads require 20
characters. Placeholder suppression excludes case-insensitive `example`, `xxxx`, angle brackets,
single-character runs in token payloads, and URL userinfo `user:password`. These are initial
heuristics, not calibrated enforcement thresholds. `FindWithProfile` changes detection only.
JWT shapes are counted without assigning confidence: segment validation and severity remain future
scanner work, and no result here can authorize enforcement.

There is no JSON traversal, deadline, completeness status, persistence, metric, policy or network
operation in this primitive. Callers must not interpret an empty result as safe, or an incomplete
stage as clean. No caller uses detection in this slice.

### 3.2 Unicode and length heuristics

Parsed text is examined, not raw bytes ([2.2](#22-structuredcontent-binary-parts-and-shape-specific-rules)). Unicode
rules apply to definitions and, with lower severity, to results and arguments.

| Rule id | Looks for | Severity (definitions) | Legitimate uses that must not trigger |
| --- | --- | --- | --- |
| `unicode.tag_chars` | U+E0000 to U+E007F [B10] | high | Emoji tag sequences (flags of England and Scotland use tag characters after U+1F3F4): the rule ignores a tag run that follows an emoji base and terminates with U+E007F |
| `unicode.bidi_override` | U+202A to U+202E [B9] | high | None expected in tool text |
| `unicode.bidi_isolate_unbalanced` | U+2066 to U+2069 not balanced within the string (Trojan Source's recommended check is "unterminated" bidi controls [B9]) | medium | Balanced isolates in mixed Arabic/Hebrew and Latin descriptions |
| `unicode.bidi_mark` | U+200E, U+200F, U+061C | info (count) | Routine in right-to-left text |
| `unicode.invisible` | U+200B, U+2060, U+FEFF not at the start, U+00AD, U+180E, U+034F inside an ASCII word, or any run of three or more | medium | A single leading byte order mark; soft hyphens in prose are low |
| `unicode.joiner` | U+200D and U+200C | info unless between ASCII letters | Emoji ZWJ sequences; ZWNJ in Persian and Indic text |
| `unicode.variation_selector` | U+FE00 to U+FE0F and U+E0100 to U+E01EF as a run, or following a non-base character [B11] | medium | A single U+FE0F after an emoji |
| `unicode.control` | C0/C1 controls other than tab, line feed and carriage return | medium in definitions, low elsewhere | Escape sequences in terminal-output results (low) |
| `unicode.private_use` | Private use areas, noncharacters | low | Icon fonts (rare in tool text) |
| `unicode.mixed_script_name` | A tool, parameter or resource **name** mixing scripts, by UTS #39 resolved script sets [B12] | medium | Names in one non-Latin script |
| `unicode.confusable_name` | Two capabilities of one server (and, in a gateway-aware follow-up, of one gateway) whose UTS #39 skeletons are equal but whose names differ | medium | None expected |
| `length.description` | Description over 2,000 characters (low), over 5,000 (medium) | low to medium | Long, honest documentation. Thresholds start at `info` and are set from corpus data, not intuition |
| `length.schema_text` | One parameter description, default or enum value over 1,000 characters | low | Large enums |

Unicode normalisation is applied before the **phrasing** rules in 3.3 only (NFKC, drop default-ignorable code
points, case-fold, collapse whitespace), so `ｉｇｎｏｒｅ` and `ig\u200bnore` match the same pattern. This is
cheap evasion-resistance, not a defence against a motivated attacker ([section 9](#9-what-this-will-not-catch)).
`golang.org/x/text` is already an indirect dependency (`go.mod`), so NFKC needs no new module, only a
direct-dependency promotion the build issue must justify.

### 3.3 Instruction-phrasing and structure heuristics

A small, English-only list of lexical patterns modelled on the published examples [B1][B2][B3][B17], run over every
string in a definition (including parameter names, descriptions, defaults and enum values: the whole schema, per
[B13]) and, with separate ids and tuning, over results.

| Rule id (definitions / results) | Pattern family | Notes |
| --- | --- | --- |
| `poison.override_instructions` / `inject.override_instructions` | "ignore/disregard/forget (all\|any\|the\|previous\|prior\|above) instructions", "new instructions", "you must now" | Results quote these legitimately (a tool that returns a security article) |
| `poison.concealment` / `inject.concealment` | "do not (tell\|mention\|reveal\|inform) (the )?user", "without (telling\|informing) the user", "this could upset the user" | Rare in honest text; the strongest lexical signal in the published poisoning examples |
| `poison.sensitive_path` | References to `~/.ssh`, `id_rsa`, `.env`, `mcp.json`, `/etc/passwd`, cloud credential files | High only in combination with an instruction verb; a tool that legitimately reads SSH config will trigger it |
| `poison.pseudo_tag` / `inject.pseudo_tag` | `<IMPORTANT>`, `<system>`, `[SYSTEM]`, `<instructions>` blocks | |
| `poison.precondition` | "before using this tool, (you must\|first)", "always call X first" | Very common and benign: starts at `info` |
| `poison.cross_tool_reference` | A description that names another tool, "instead of", "override", "when `<tool>` is (called\|used)" | The server-only version cannot know the gateway's other tools; a gateway-aware version is F11 |
| `poison.parameter_sink` | Parameters whose name or description asks for context, conversation history, file contents or credentials ("sidenote", "context", "notes") | The published poisoning example adds exactly such a parameter [B1] |
| `poison.external_url` | URLs in a description to a host other than the server's own origin | Documentation links are common: `info` |
| `poison.encoded_blob` | Base64 or hex runs of 200 or more characters | `info` to `low` |
| `inject.exfil_markup` (results only) | Markdown images or links, or HTML, whose URL carries a query string or encoded data | Not a definition rule |
| `inject.assistant_directive` (results only) | Text addressed to the assistant ("AI assistant:", "when you read this, call ...") | |

These rules are **lexical heuristics, trivially evaded** by paraphrase, other languages, encoding or splitting
text across fields. Their purpose is to put the same few suspicious items in front of a reviewer that an attentive
reviewer would notice; they are not a security boundary and the interface must not present them as one.

### 3.4 Optional external scanning service

An operator may run their own classifier (or a vendor's) behind a small HTTP contract. The portal supplies only the
adapter. **Proposed default: off; first available in follow-up F10, never in the first slices.**

- **Configuration.** A platform admin registers one service: URL (sealed, checked on save and before every call),
  an optional sealed auth header, per-stage enablement, timeout (start: 2 s, at most 5 s), maximum request
  size (start: 64 KiB), failure policy. The URL is dialled with the **same SSRF guard as notification webhooks**:
  `notify.NewWebhookClient` in `internal/notify/webhook.go`, i.e. `upstream.Client{AllowPrivate: false, ...}` with
  `GuardedDial`: public https only, internal destinations only through a dedicated operator allowlist (proposed
  `SCAN_EXTERNAL_ALLOWED_NETWORKS`, never the MCP servers' internal-network list, for the reason `notify` records:
  a URL chosen by owners must not become a POST gadget into the internal network), no redirects, no proxy, TLS
  verified, DNS pinned. The response is capped (64 KiB) and never stored.
- **Consent (three parties).** The service is used for a (gateway, server) pair only if **all** hold: a platform
  admin enabled it; the gateway's owners or admins opted in for that gateway (a visible setting, not inherited
  from a platform default); and the server's team did not veto it. A gateway owner in team A must not be able to
  send team B's server results to a third party. This extends decision 45's concern from names and emails to
  call content.
- **What is sent.** The text parts to scan, after the portal's own redaction (the same built-in rules and the
  call's known credentials, through `capture.Redactor`), truncated to the size limit, plus the stage and a random
  per-request id. **Never** the identity token, person, email, team, gateway slug, server URL or client name.
- **What comes back.** `{"findings": [{"rule": "<id>", "severity": "...", "count": n}]}`. Any other field is
  ignored; returned text, excerpts and scores are never stored or shown. Rule ids from outside the catalog are
  collapsed to `external` (metrics) and `external:<sanitised id, at most 40 characters>` in findings.
- **Failure.** Timeout, error, oversize or non-conforming answers are `scan_incomplete` with reason
  `external_timeout` or `external_error`, under the stage's fail policy (default open). A small in-process circuit
  breaker (as the upstream breaker, bounded state) stops a failing service from adding its timeout to every call.
- **Data protection.** Enabling it makes the operator's service a recipient of call content; the settings page
  says so in words, and [5.4](#54-data-protection-review-note) applies. Snyk's Agent Scan is an example of the
  model: its README states that it sends tool names and descriptions to a hosted analysis API and that using the
  standard API for large-scale scanning is considered abuse [B17]. Such a vendor service can be wrapped by an
  operator's adapter; the portal does not integrate one by default.

### 3.5 No hosted model

**Decision (proposed default P4): the portal hosts no model and calls no LLM as part of scanning.** Reasons: the
portal is not an LLM gateway (that is OMG's role); inference adds cost, latency, nondeterminism and a large
dependency to a stateless Go binary; the model would itself read attacker text and be an injection target; and
published results show guardrail systems and defences of diverse designs evaded by adaptive attackers [B5][B6].
Operators who want a classifier use [3.4](#34-optional-external-scanning-service) and own its cost and data flow.

### 3.6 OMG's guardrails design

The issue names OMG's guardrails design as the reference. A file with that name exists in the sister repository
(`docs/guardrails-design.md`, [B18]); **this document does not use or summarise its contents** and nothing here
should be read as consistent or inconsistent with it. It is owner input ([section 12](#12-owner-input-and-open-questions)).

### 3.7 Expected false-positive rates

There is no honest published number to quote. The public corpora in [section 10](#10-test-corpus-plan) are of
attacks against chat prompts and agents, not of benign MCP definitions; the one MCP-specific benchmark (MCPTox
[B4]) has a repository that states no licence. The rates are therefore **measured, not predicted**, in three ways:
(1) per-rule precision and recall on the in-repo corpus including benign near-misses, as a CI gate; (2) the
benign definitions of reference servers and the fake servers in this repository; (3) shadow mode on real
deployments, reported by operators as counts per rule ([6.4](#64-metrics-decision-35)) and triaged by
reproduction (the findings do not hold the text, [5.2](#52-what-is-never-stored)). Starting gates are in
[section 11](#11-acceptance-tests-the-first-build-issue-must-pass); enforcement of any rule group waits for
operator-reported shadow data.

## 4. Actions and modes

### 4.1 Actions

| Action | Meaning | Where it can apply | Notes |
| --- | --- | --- | --- |
| `annotate` | Record a finding; show it in the UI and metrics | every stage | The only action in the first slices |
| `block` | Refuse the call or withhold the result | arguments; results (with the caveat in 4.3); never definitions | Arguments blocks happen before anything is forwarded |
| `require_approval` | Treat the call as governed by an exact-call approval | arguments of **`tools/call` only** (approvals do not govern prompts or resources today) | See 4.4 |
| `redact` | Replace the matched value with `[REDACTED]` | results and progress messages, secret rules only | **Not offered for arguments**: silently editing what the model sent makes a different call from the one a person approved or a client sent, with a confusing failure. Use `block` or `require_approval` |
| `suppress` | Count the finding as `suppressed` instead of acting | a false-positive valve for a rule on a scope | Never silent: counted in `omp_scan_findings_total{action="suppressed"}` |

Definition findings never change a definition. "Changing approved definitions automatically" is out of scope (the
issue), and withholding stays the job of the fingerprint rule. A later, explicit option is a **reviewer
acknowledgement** of findings bound to (fingerprint, ruleset version) (F12); it records a human decision, it does
not alter the definition.

### 4.2 Modes, ceilings and overrides

Each stage has a mode: `off`, `shadow` or `enforce`. **Shadow evaluates exactly like enforce, records findings and
the action the policy *would* have taken (`would_block`, `would_redact`, `would_require_approval`), and takes no
action.** That distinction is what lets operators measure what enforcement would have done before turning it on.

- **Platform** (platform admins): a default per stage; a **ceiling** (`max_mode`; default `shadow`) that no
  gateway or server can exceed; a **floor** (`min_mode`; default `off`); whether the external service may be used
  at all (default no); the failure-policy ceiling (can fail-closed be chosen at all, default no).
- **Gateway** (gateway owners/admins; platform admins for platform gateways): mode per stage, rule groups
  (`secret`, `unicode`, `poison`/`inject`, `length`), minimum severity to act, action, failure policy, external
  opt-in, the optional approval rule for `require_approval`.
- **Server** (the server's team owners/admins): the same fields for **calls to its server through any gateway**,
  because the server's team owns that server's data (as capture's per-server switch does, decision 32).
- **Resolution.** (1) Platform floor and ceiling bound everything. (2) Between gateway and server settings the
  **more protective** wins (mode, groups, fail-closed). (3) External scanning needs **all** of platform enabled,
  gateway opted in, server not vetoed. (4) Suppression lists (rule ids per scope) are the false-positive valve and
  only for rules marked suppressible; private-key and portal-credential rules are not. (5) Editors, members,
  automation tokens and service accounts cannot change any of this; it is browser-session only, `If-Match` on a
  revision, audited with before and after settings (never content).
- **Initial state (proposed default).** Definitions: platform default `shadow`, all groups, on at upgrade because it
  is in process, off the call path and sends nothing anywhere. Arguments and results: `off` until their slices
  ship, then `shadow`. Ceiling `shadow`, so no gateway can enforce until a platform admin raises it.
- **Fail policy per stage.** Default `open` everywhere. A deterministic in-process scanner fails only on its own
  bugs, deadlines or overload; failing closed would turn each of those into an outage for every call on a gateway.
  `closed` is available per stage only when the ceiling allows it, and is recorded as `content_scan_unavailable`.
  For definitions `closed` does not exist: there is nothing to refuse.

### 4.3 Results after a call ran

A result is scanned after the server acted. For a tool the owner classified `read`, and for prompts and resource
reads, withholding a result has no side effect. For a `write`, `destructive` or **unclassified** tool (unclassified
is treated as destructive here, as approval matching does for rules, decision 82), the effect may already have
happened: a "blocked" result reads to a client as a failure and invites a retry that duplicates it. Therefore:

- the proposed default for such tools is `annotate` and, for secret rules, `redact`; `withhold` is allowed only by
  an explicit policy flag that says so;
- a withheld result carries the same warning approvals use when authorization was spent and the outcome is unknown
  (`approvalUnknown` in `mcpgw/approvals.go`): the call ran, the result was withheld by policy, repeating it may
  duplicate its effects;
- the response shape follows decision 59: a tool call answers a result with `isError: true` and a generic text
  naming the rule id (not the match); a prompt or resource read answers `-32010` with `data.reason`
  `result_withheld` (`codeDenied` in `mcpgw/mcpgw.go`);
- the call is recorded with a distinct class (`result_withheld`); whether it needs a new `outcome` value
  (widening `mcp_calls_outcome_check`, last widened in migration `00035`) is a decision for the enforcement issue,
  because usage rollups and alerts group by outcome and `upstream_error` would pollute them;
- the withheld content is **not captured**: capture stores what the client received.

### 4.4 Interaction with exact-call approvals (decisions 48, 52, 82)

The approval path is `prepareApproval` in `internal/mcpgw/approvals.go` (`Begin`, then `Consume` in
`target.BeforeTransport` immediately before the tool transport; spent means authorization spent, never restored). A
scan must fit it exactly:

1. **Order.** Argument scanning completes **before** `prepareApproval`. A `block` therefore never creates, reuses or
   spends an approval, and no human is asked to approve a call that would have been blocked.
2. **Additive only.** `require_approval` can make a call governed that no approval rule matched. It can never waive
   a rule that matched. It reuses the existing path: `Begin` with a rule chosen by the scan policy
   (`approval_rule_id`, an existing enabled rule on the same gateway or server scope, checked when saved and again
   on every call; this needs an extension of `Begin`'s input, which today matches rules only by target, capability
   and class), the same reviewers (decision 52: the server team's owners and admins by default, never the
   requester, platform admins as fallback), expiry, single use, redacted preview ≤16 KiB, notifications, audit.
3. **Binding.** The approval binding gains a **scan digest** over the ruleset version and the sorted (rule id,
   count) pairs, computed with the existing installation binding key (decision 82's root), so the stored digest is
   not a dictionary oracle for the values. A ruleset change or a changed finding set is a different binding and
   needs a new approval; change-and-revert never resurrects one (the same property as rules). Arguments are
   bound **after curation merge** as today; the scan sees the merged arguments minus fixed members (P9), so equal
   and omitted fixed values bind identically.
4. **Reviewers see rule ids and stage, not text**, next to the existing redacted preview. The approval page says
   "required by a content policy" with the ids; it does not say "safe".
5. **No replay.** A scan-required call is governed, so it advertises no upstream elicitation, never retries
   automatically and is **primary-only** under failover (decision 85: "Governed/NoReplay calls remain
   primary-only"). Enabling `require_approval` on a gateway therefore removes failover and read retries for the
   calls it governs; the settings page must say so.
6. **After spend.** Scanning after the dispatch boundary (results, progress) can annotate, redact or withhold but
   can never restore, extend or reuse the approval, never retries the call and never re-enters `Consume`.
7. **Prompts and resources** are not governed by approvals; `require_approval` is rejected for them at save and
   they get `annotate` or `block` only.

### 4.5 Interaction with the other shipped features

| Feature | Interaction |
| --- | --- |
| Classification (#28, decision 75) | Class decides which result actions are safe (4.3). Annotations are never trusted: a server's `readOnlyHint` is not a reason to withhold or to skip a scan. Unclassified is treated as destructive for approval matching and for 4.3. |
| Credential scopes (#29, decision 77) | A tool outside a credential's scope is already an unknown tool before any scan; it produces no call findings. Definition findings are per server and independent of who may call. |
| Curation (#30, decision 80) | Arguments are scanned after `curation.Merge`, minus fixed members. A `descriptionOverride` replaces the tool description for that gateway's clients, so a gateway owner can neutralise a suspicious upstream description; it does not rewrite schema property descriptions. The override text and fixed values are scanned at save (F11); the portal's curation doc already says fixed values are "not an encrypted credential vault". |
| Approvals (#31, decision 82) | 4.4. |
| Access requests (#32, decision 83) | No interaction. Requester reasons and decision notes are private human text, not tool content, and are not scanned. |
| Upstream protection and failover (#33, decisions 84, 85) | A scan never causes a retry or a failover (a finding is not a transient failure), is not charged to the server quota and does not hold the server lease. Scanning happens once per **logical** call: arguments before the first attempt, the result after the last. A discarded attempt is never relayed and never scanned. An extra endpoint's result is scanned like the primary's: it comes from a different origin the review did not read. Findings do not record the endpoint URL. Definition scanning stays primary-owned like discovery. |
| Capture and retention (decisions 32, 33) | 5.3. |
| Tracing (decision 71) | The span attribute allow-list is fixed and pinned by a test; the design adds no attribute. |
| Notifications (decision 56) | Eight stable events; none is added. A "findings on a changed capability" notice would be a decision of its own. |
| Identity to servers (decisions 45, 64) | The external service never receives identity (3.4). |

## 5. Evidence and privacy

### 5.1 What is stored

| Field | Definitions | Calls |
| --- | --- | --- |
| rule id (closed catalog; `external:<id>` for the external service) | yes | yes |
| ruleset version | yes | yes |
| stage | `definition` | `arguments`, `results`, `progress` |
| severity | yes | yes |
| count (how many matches of the rule) | yes | yes |
| action taken or "would have taken" | `annotated`, `suppressed`, `incomplete` | `annotated`, `would_*`, `blocked`, `redacted`, `approval_required`, `suppressed`, `incomplete` |
| location | a JSON pointer into the stored definition (≤200 characters), e.g. `/inputSchema/properties/sidenote/description` | a coarse class only: `arguments`, `result.content`, `result.structuredContent`, `result.resource`, `result.prompt`, `result.error` |
| subject | the capability and its **fingerprint** | the `mcp_calls` row |

A definition finding may carry a pointer into the definition because the definition text is already stored catalog
data that a reviewer can read (`mcp_capabilities.definition`); the pointer adds no exposure. Pointer segments are
attacker text too (a property *name* can hold a tag-character payload), so a pointer is stored **escaped**: control,
format and other non-printable characters are written as `\u{E0041}`, and a segment longer than 80 characters is
replaced by its array or member index. A **call** finding never carries a pointer, a key name or an offset, because
those would leak the shape of the payload.

### 5.2 What is never stored

Matched text; surrounding text or excerpts; offsets or lengths into a call payload; hashes of matched values (an
unkeyed hash of a low-entropy secret is a dictionary oracle, the reason decision 82 keys its argument digests);
argument or result text of any kind; the external service's returned text or scores. These are enforced
structurally, not only by convention: the only text-valued columns of `scan_findings` are identifiers constrained
by `CHECK` to `^[a-z0-9_.:-]{1,64}$` and `location`, which holds an escaped pointer into a stored definition or,
for calls, one of six class names (also a `CHECK`); a test lists the table's columns and fails when one is added
([section 11](#11-acceptance-tests-the-first-build-issue-must-pass)).

Logs, metrics, spans and audit follow: logs carry stage, rule id, severity and count (and the request id the access
log already has), never text; metric labels are the closed sets in 6.4; the tracing allow-list is untouched; the
audit log records policy changes (before and after settings), never findings.

**Triage consequence.** Because findings hold no text, a false positive is investigated by reproduction, not by
reading the finding. When a gateway or server already has payload capture on, the (redacted, 16 KiB-truncated,
14-day) capture row of the same call is available to people who may read captures; secrets are redacted there by
design. A reviewed-excerpt option (a few redacted characters of context) is **not** proposed; it would reopen
5.2 and is an owner decision if triage proves impractical.

### 5.3 Interplay with payload capture and retention

- Findings do not depend on capture and do not turn it on. Capture does not create findings.
- Capture stores what the client received and what was forwarded; a call refused by a scan has no arguments
  captured (no forward happened, the same as other pre-forward refusals) and a withheld result is not captured.
- Call findings are kept with **call metadata** (90 days by default, `retention.CallPeriods`), not the 14-day
  payload period, because they hold no content. The model is `mcp_call_payloads`, whose `call_id` references
  `mcp_calls` with `ON DELETE CASCADE` (migration `00011`). The purge functions of the split-role design
  ([database-roles.md](database-roles.md)) must be reviewed against a second child table; the build issue owns that.
- Definition findings belong to a capability fingerprint: replaced by the latest scan per (fingerprint, ruleset
  version), deleted with the capability row.
- Metrics hold counts only and no per-person or per-call dimension.

### 5.4 Data-protection review note

This is a note for the owner and the deployer's data-protection function, **not legal advice**.

- Scanning argument and result content processes whatever that content contains, including personal data. In the
  portal's own process this is the same processing the portal already does to relay it; nothing is added to what
  leaves. Storing only rule ids and counts keeps the findings table out of the "content" class.
- A finding on a call still links, through the call row's principal (a person or a service account), someone to
  "sent something that looked like a credential". In some jurisdictions and workplaces that is employee monitoring and needs a legal basis,
  notice, and possibly works-council involvement. The design does not add identity (the call row already has it),
  limits retention to call metadata retention, and keeps findings readable only where call metadata already is;
  it cannot decide for the operator whether that is acceptable. Recommended before enabling `arguments` or
  `results` stages: a short review by the deployer's data-protection function, recorded in their register.
- Personal-data detectors (email addresses, national identifiers, card numbers) are **not proposed**: detecting
  them is processing them, their false positives are common (order numbers, IDs), and enforcement on them has
  legal consequences. If wanted, they are a separate decision after the first stages (P8).
- External scanning (3.4) makes the service operator a processor of call content (redacted by the portal's rules
  first, identity removed). That needs a contract with the service's operator, the three-party consent in 3.4, and
  a visible statement on the settings page. The portal's default is off.
- The review UI's definition text is already visible to the people who see the server; showing a pointer to it
  discloses nothing new.

### 5.5 Who can read findings

| Findings | Readers |
| --- | --- |
| Definition findings | Whoever can already read the server's capabilities (the server's team members; platform admins and auditors; the review dialog). They are shown beside the definition, with the ruleset version, and are never labelled "safe". |
| Call findings | Wherever the call row is readable (the server team's owners/admins and the gateway's team through the call lists; platform admins and auditors). No payload-style access gate is needed because there is no content, and no view of findings is itself audited. |
| Policies | The same people who may edit them (P11), plus platform auditors read-only. |

## 6. Data model and API sketch

**Sketch only. No migration, query, endpoint or setting exists.** Names are proposals. Any migration is forward-only
and expand-only (CONTRIBUTING: the previous release must keep working on the new schema), numbered after `00047`
when written. Per the repository rules, the build issues change `api/openapi.yaml` first and run `make generate`.

### 6.1 Tables

```sql
-- Ceilings, floors and platform defaults: new columns (or a JSON column) on the
-- single-row platform_settings table with its revision, like the capture and
-- publishing settings.

CREATE TABLE scan_policies (            -- gateway and server overrides only
    id            uuid PRIMARY KEY,
    scope_kind    text NOT NULL CHECK (scope_kind IN ('gateway', 'server')),
    scope_id      uuid NOT NULL,        -- gateways.id or mcp_servers.id (no FK, like approval rules)
    stage         text NOT NULL CHECK (stage IN ('definition', 'arguments', 'results', 'progress')),
    mode          text NOT NULL CHECK (mode IN ('off', 'shadow', 'enforce')),
    action        text NOT NULL CHECK (action IN ('annotate', 'block', 'require_approval', 'redact')),
    min_severity  text NOT NULL DEFAULT 'high' CHECK (min_severity IN ('info', 'low', 'medium', 'high')),
    groups        text[] NOT NULL DEFAULT '{secret}',
    fail_policy   text NOT NULL DEFAULT 'open' CHECK (fail_policy IN ('open', 'closed')),
    external      boolean NOT NULL DEFAULT false,
    approval_rule_id uuid,              -- approval_rules.id, for require_approval
    suppressed    text[] NOT NULL DEFAULT '{}',
    revision      bigint NOT NULL DEFAULT 1,
    updated_by    uuid, updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_kind, scope_id, stage)
);

CREATE TABLE scan_findings (
    id               bigserial PRIMARY KEY,
    occurred_at      timestamptz NOT NULL DEFAULT now(),
    call_id          bigint REFERENCES mcp_calls (id) ON DELETE CASCADE,         -- call findings
    capability_id    uuid REFERENCES mcp_capabilities (id) ON DELETE CASCADE,    -- definition findings
    fingerprint      text,                                                       -- definition findings
    stage            text NOT NULL CHECK (stage IN ('definition', 'arguments', 'results', 'progress')),
    rule_id          text NOT NULL CHECK (rule_id ~ '^[a-z0-9_.:-]{1,64}$'),
    ruleset_version  text NOT NULL CHECK (ruleset_version ~ '^[a-z0-9_.-]{1,32}$'),
    severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
    count            integer NOT NULL CHECK (count BETWEEN 1 AND 100000),
    action           text NOT NULL CHECK (action IN ('annotated', 'suppressed', 'would_block', 'would_redact',
                         'would_require_approval', 'blocked', 'redacted', 'approval_required', 'incomplete')),
    location         text CHECK (char_length(location) <= 200),   -- definitions: JSON pointer; calls: coarse class
    CHECK ((call_id IS NULL) <> (capability_id IS NULL)),
    CHECK (call_id IS NULL OR location IN ('arguments', 'result.content', 'result.structuredContent',
                                           'result.resource', 'result.prompt', 'result.error'))
);
```

Notes: no free-text column beyond the constrained ones above; no hash column; `count` is the only number. The exact column set is pinned by a test.
`mcp_calls.error_class` already exists as `text` limited to 64 characters (no enumerated `CHECK`), so new classes need
no migration: `content_blocked` (outcome `denied`, nothing forwarded), `content_approval_required` (existing
outcome `needs_approval`), `content_scan_unavailable` (outcome `denied`, fail-closed only), `result_withheld` (outcome
open question, 4.3). The first slice adds no outcome and touches no call row.

### 6.2 JSON-RPC shapes

An argument block answers `-32010` (`codeDenied`) with `data.reason: "content_blocked"` and
`data.rules: ["secret.github"]`; the message names the rule id and says the call was not sent. Results follow 4.3.
`require_approval` reuses the approval answers of decision 59 and `approvalRequired` in `mcpgw/approvals.go`
(modern URL-capable clients: `input_required`; other modern clients: `isError` with the link; legacy: `-32042`).

### 6.3 Management API (proposed; browser session only, no `x-omp-token-scopes`)

| Operation | Purpose |
| --- | --- |
| `GET`/`PUT /v1/admin/settings/scanning` | Platform defaults, ceilings, floors, external enablement. `If-Match` on its revision; audited |
| `GET /v1/admin/scanning/rules` | The rule catalog: ids, groups, severity, description, ruleset version |
| `GET /v1/teams/{team}/mcp-servers/{id}/scan-findings`, admin equivalent | Definition findings per capability (also summarised in the capability views: `scan.status` = `scanned`, `stale`, `incomplete` or `off`, with counts by severity and the ruleset version) |
| `POST /v1/teams/{team}/mcp-servers/{id}/scan` | Rescan stored definitions (no upstream contact); rate limited |
| `GET`/`PUT /v1/teams/{team}/gateways/{gw}/scan-policy`, `/v1/admin/gateways/{gw}/scan-policy` | Gateway overrides (`If-Match`) |
| `GET`/`PUT /v1/teams/{team}/mcp-servers/{id}/scan-policy` | Server overrides (the server team's owners/admins) |
| call detail | `scanFindings: [{stage, ruleId, severity, count, action}]`; a call-list filter `hasScanFindings` and `scanRule` |

The first slice needs only the settings operation, the rule catalog, the capability `scan` summary and the findings
operation.

### 6.4 Metrics (decision 35)

Decision 35 and the package comment in `internal/observability/metrics.go` allow low-cardinality labels from fixed
sets, including rule names, and forbid person, key, team and request ids. Proposed metrics:

| Metric | Labels | Bound |
| --- | --- | --- |
| `omp_scan_findings_total` | `stage` (4), `rule`, `action` (9) | `rule` is from the closed built-in catalog (about 40 ids) plus `pattern` and `external`; most stage and rule pairs do not exist, so the practical series count is low hundreds. A test enumerates the catalog and fails on a label value outside it (the existing precedent: `redactionLabel` in `internal/app/app.go` collapses `pattern:N` to `pattern`) |
| `omp_scan_duration_seconds` | `stage` | histogram, buckets from 100 µs to 1 s |
| `omp_scan_incomplete_total` | `stage`, `reason` (`budget`, `depth`, `size`, `busy`, `panic`, `external_timeout`, `external_error`) | fixed |
| `omp_scan_external_requests_total` | `result` (`ok`, `refused`, `unavailable`, `timeout`) | fixed, like `omp_machine_token_requests_total` |
| `omp_scan_ruleset_info` | `version` | one series |

**No gateway, server or provider slug labels**: multiplying rule x stage x action by up to 200 gateways and servers
would defeat the bound. Per-gateway visibility is in the management UI (findings per gateway from the table), not in
Prometheus. Dashboards and alert rules under `deploy/` must use these real names (`TestOpsArtifactsUseRealMetrics`,
`TestDashboardsUseRealMetrics`); the build issue adds a panel for findings by rule and by `would_*` action, which
is what an operator needs to decide whether to enforce.

## 7. Rollout plan

Each slice is independently releasable, additive, and reversible by a setting. Slices after the first are gated on
the evidence from the one before. Follow-up issue drafts are in [Appendix A](#appendix-a-follow-up-issues-drafts).

| Slice | Contents | Follow-ups | Hot path? | Gate to start |
| --- | --- | --- | --- | --- |
| **0. Foundations** | The corpus and benchmark harness ([section 10](#10-test-corpus-plan)); the rule registry extracted from `capture` with **no behaviour change** | F1, F2 | no | This design accepted |
| **1. Smallest first slice: definition scanning in shadow, shown at review** | Ruleset v1 for definitions (secret, unicode, poison, length groups); a refresh hook before the transaction in `registry.refresh`; `scan_findings` (definition rows); a platform setting (`off` or `shadow`); rescan of stored definitions (explicit, plus a leader-elected backfill after upgrade or a ruleset change); capability `scan` summary and a findings panel on the Capabilities tab and in the publish and review dialogs, with wording that never says "safe"; definition-stage metrics | F3, F4 | **no**: refresh only | Slice 0 |
| **2. Argument secret detection in shadow** | Hook in `(*request).call` after `curation.Merge`; call findings rows; call detail; `would_block` actions; call-stage metrics and latency gates | F5 | yes | Slice 1 shipped; the deployer's data-protection note ([5.4](#54-data-protection-review-note)) |
| **3. Policies** | Platform ceilings and floors, gateway and server overrides, suppression, UI. Ceiling still defaults to `shadow` | F6 | no | Slice 2 |
| **4. Enforce secrets in arguments** | `block` for high-confidence `secret.*` rules on arguments, behind the ceiling | F7 | yes | Enforcement gate below |
| **5. Results in shadow** | Hook in `relay`; `structuredContent`, reads, prompts, errors and progress; `inject.*` rules | F8 | yes | Slice 2 latency data |
| **6. Result redaction and withholding** | `redact` for secrets; `withhold` with the post-effect semantics of 4.3; the outcome decision | F9 | yes | Slice 5 shadow data |
| **7. Scan-triggered approval** | Extension of the exact-call approval path (4.4) | F14 | yes | Slices 3 and 4 |
| **8. External service** | Contract, three-party consent, SSRF guard, breaker | F10 | yes (network) | Slices 3 and 5; owner decision on the data flow |
| **Later** | Curation text and fixed values at save plus gateway-aware shadowing (F11); reviewer acknowledgement bound to fingerprint and ruleset (F12); custom scan rules (F13) | | | |

**Why this first slice.** It is off the call path (refresh only), reads only what is already stored, sends nothing
anywhere, adds no new permission (the people who see a server's capabilities see its findings), reuses the
review flow the approval model already depends on (F-2 binds a reviewer to what they saw), carries the strongest
research evidence (T1, T2), and writes only ids and counts. It deviates from the issue's "likely" first slice
(definition scanning *plus* argument secret detection) on purpose: argument scanning puts code on every
`tools/call` and carries the data-protection question, so it follows as slice 2 with its own measurements.

**Enforcement gate (proposed).** A rule group may be enforced on a gateway only when all hold: the corpus gates pass
at the same ruleset version; at least 14 days of shadow data on at least one real gateway; every `would_block`
finding in a sample (all if at most 200, otherwise 200 chosen at random) was triaged by reproduction with at least 95%
true positives for that group; production p95 added latency is inside the stage budget; and the owner has recorded
the choice in a decision row. A rule group that fails the gate stays in shadow.

**Compatibility.** Schema changes are expand-only. A previous-release replica ignores scan tables, settings and
policies: **it does not enforce**. As with approvals, access requests and failover, drain older serving replicas
before relying on enforcement; schema compatibility is not enforcement compatibility. Rollback: turn the stage `off`
(findings stay for their retention) or roll back the image; no data is rewritten.

## 8. Decision entry and documentation updates

This change adds this document and updates [threat-model.md](threat-model.md) (7.5, the 7.6 result-content row and
the gap table in section 11: they now point here and still say nothing is implemented), [roadmap.md](roadmap.md)
(content scanning is designed, with a proposed first slice, and decision 87 records it) and the changelog. It adds
**decision 87** to [decisions.md](decisions.md), quoted at the end of this document ([Decision entry](#decision-entry)). Decision 50 ("design
before building") is satisfied by this document; the proposed row records go or no-go.

## 9. What this will not catch

State this next to every findings view and in the operator documentation. A scan that finds nothing means the
heuristics found nothing, not that content is safe.

1. **Anything an adaptive attacker tunes against.** An evaluation of 12 recent defences against injection and
   jailbreak, built on diverse techniques, found attack success above 90% for most once the attacker adapted, and
   most had originally reported near-zero success [B6]. Character-injection and adversarial-ML evasion reached up
   to 100% in some instances against six guardrail systems, including Azure Prompt Shield and Meta's Prompt Guard
   [B5]. Lexical rules are not stronger than those. The rules are public; treat them as known to the attacker.
2. **Paraphrase, other languages, encodings and splitting.** The phrasing rules are English-only and lexical.
   Base64, hex, rot13, leetspeak, homoglyphs beyond the Unicode rules, a payload split across several fields,
   parameters or calls, or an instruction written as ordinary prose, will pass.
3. **Content that is not text the portal parses.** Images, audio and base64 blobs ([2.2](#22-structuredcontent-binary-parts-and-shape-specific-rules));
   text inside images; steganography; a `resource_link` the *client* fetches itself; anything past a size, depth or
   deadline limit (recorded as `scan_incomplete`, not as clean).
4. **Behaviour.** A server that does something other than its description says, that changes what a tool does per
   caller or over time without changing the definition, or whose effect on its backend is harmful. The portal
   sees definitions and the bytes of one call, not what the server does.
5. **Exfiltration that is not a known credential shape.** Source code, business data, personal data, secrets split
   across arguments or calls, data encoded by the model, covert channels in timing or tool choice. There is no
   cross-call or session state in the portal, and so no detection of a lethal-trifecta flow across calls [B15].
6. **What the model and client do.** The portal does not see the model's context, other servers connected to the
   client directly, local tools, or how the client renders results. Client-side defences (spotlighting [B16],
   architectural patterns such as those in [B7][B8]) are outside it.
7. **A malicious or careless reviewer, gateway owner or server team.** Scanning informs reviewers; it does not
   replace them. Under `self_publish`, or for a team's own gateway, no reviewer is in the loop (UP-2).
8. **Personal data**, by decision (P8).
9. **Definition lists served by other surfaces or servers not behind the portal.**
10. **Tool annotations.** They stay untrusted and unscanned as safety information; owner classification is the
    only trusted class.

Scanning complements, and does not replace: least privilege and scopes (#29), owner classification (#28),
curation (#30), exact-call approvals (#31), human review of definitions, and client-side controls. Its defensible
claim is narrower than "detects prompt injection": it **raises the chance that a reviewer or operator notices
specific, already-known suspicious patterns, and stops specific credential shapes leaving in arguments once a
rule group has earned enforcement**.

## 10. Test corpus plan

### 10.1 Policy

- **No third-party corpus text is committed to this repository.** Permissively licensed public corpora are
  downloaded by a scheduled CI job at a **pinned revision** (commit or dataset revision plus content hash) into a
  cache; the job publishes per-rule results as numbers, not data. Anything whose licence is missing, inconsistent or
  gated is excluded from CI and used, if at all, only for manual evaluation. Licences below were read from the
  official dataset card or repository on 2026-10-30; the first build issue **re-checks each at the pinned revision**.
- **In-repo fixtures are authored here**, modelled on the published *patterns*, never copied from unlicensed
  examples. Secret-shaped fixtures are **generated at test time** from a fixed seed (with the correct prefix and
  length) so the repository never contains strings that look like live tokens (they would trip secret scanning and
  push protection). Hidden-Unicode fixtures are built in code from ASCII (`U+E0000 + code point`) so no invisible
  character sits in a source file.

### 10.2 Categories of in-repo fixtures

| Category | Examples | Expected |
| --- | --- | --- |
| **Must catch** | A tool description with a `<IMPORTANT>` block telling the model to read a credentials file and pass it in an extra `sidenote` parameter, then not to mention it (pattern from [B1], rewritten); a description naming another server's tool ("when `send_email` is used, also add ..."; [B1]); a sleeper pair (innocuous at refresh 1, poisoned at refresh 2); a tag-character payload in a description, in a parameter default and in a resource name; a bidi override in a description; zero-width characters inside "ignore"; a schema whose enum value carries instructions; a JWT, GitHub token, AWS access key id and PEM private key in arguments, in a result and in a definition | Rule id and severity as listed in the fixture |
| **Benign near-misses** | "Call this tool before `create_issue` to get label names"; "important: dates are UTC"; a documentation string with `Authorization: Bearer <token>`; "the bearer of this letter"; `postgres://user:password@localhost:5432/db`; the AWS documentation example key [B18]; `ghp_` followed by 36 `x`; a sample JWT from library docs; emoji ZWJ sequences (family, flags, tag-sequence flags); Persian text with ZWNJ; Arabic and Hebrew text with LRM, RLM and balanced isolates; Korean, Chinese and Japanese descriptions; a long honest README-style description of 6,000 characters; a tool that legitimately reads `~/.ssh/config`; a security-article search result quoting "ignore previous instructions"; a login tool with a `password` parameter; markdown links to the project's own docs | **No finding at medium or above.** Low and info findings are counted and capped |
| **Known misses** (the ledger) | Paraphrased override in plain English; the same instruction in German; base64-encoded instruction; instruction split over two parameter descriptions; image-borne text; a secret split across two arguments; a PII-bearing result | **No finding, and listed** in `testdata/scan/known-misses.md` with the reason. A test asserts that the set of fixtures that produce no finding equals the ledger, so a rule that starts catching one must move it, and the documentation of misses cannot rot |
| **Evasions of the rules themselves** | Fullwidth `ｉｇｎｏｒｅ`; NFKC-equivalent forms; zero-width splitting; combining marks; mixed case; JSON-escaped characters (`\u202e`, surrogate pairs) in arguments and results | Caught by the normalisation pass, or in the ledger |
| **Pathological** | 1 MiB of repeated near-matches; 64 KiB single word; deeply nested JSON; 200,000-node `structuredContent`; invalid UTF-8 and lone surrogates; repeated keys | Completes inside the deadline or `scan_incomplete`; never panics, never exceeds a memory multiple of the input |
| **Interplay** | Fixed curation values (equal vs omitted); consent retry; failover to an extra endpoint; read retry; governed call; streamed call | 4.4, 4.5 and A7 below |

### 10.3 Public corpora

| Corpus | What it is | Licence (official source) | Use here |
| --- | --- | --- | --- |
| Lakera `gandalf_ignore_instructions` (Hugging Face) | 1,000 "ignore instructions"-style prompt-injection texts (777/111/112 train/validation/test) | MIT (dataset card) | Recall of override phrasing; mostly chat-style, so many are *expected* misses for definition rules |
| Lakera `gandalf_summarization` | under 1,000 rows (the name suggests summarisation-themed injections; the build issue reads the card) | MIT (dataset card) | Result-stage phrasing |
| Lakera `mosscap_prompt_injection` | 100K to 1M rows | MIT (dataset card) | Throughput and stress, not precision |
| `deepset/prompt-injections` | 546 train, 116 test labelled texts | **Inconsistent**: the card says `apache-2.0` and its `dataset_info` says `cc-by-4.0` | Excluded from CI until the maintainers clarify; its label-0 texts would be a useful benign set for the phrasing rules |
| HackAPrompt dataset (arXiv 2311.16119 [B23]) | 100K to 1M competition submissions | MIT on the card, **gated** (terms must be accepted) | Excluded from CI; manual stress sampling at most |
| BIPIA (`microsoft/BIPIA`, arXiv 2312.14197 [B22]) | Benchmark of indirect prompt injection | MIT (`LICENSE`); the Summarization and WebQA context data must be fetched from their original sources under their own terms (README) | Result-stage attack strings; the build issue verifies which files are attack text |
| AgentDojo (`ethz-spylab/agentdojo`, arXiv 2406.13352 [B20]) | Dynamic environment for injection attacks on tool-using agents | MIT (`LICENSE`) | Injection templates only; the environment needs an LLM and is not run |
| InjecAgent (`uiuc-kang-lab/InjecAgent`, arXiv 2403.02691 [B21]) | Indirect injections in tool responses | MIT (`LICENCE`) | Result-stage strings |
| **MCPTox** (arXiv 2508.14925 [B4]; `zhiqiangwang4/MCPTox-Benchmark`) | 1,348 poisoning cases on 45 live servers and 353 tools | **No licence file in the repository** | **Cannot be used or redistributed** until the authors state a licence; ask them. Its published results are cited, not its data |
| Invariant `mcp-injection-experiments` [B3] | Example poisoned servers | No licence file | Reference for patterns only; our fixtures are rewritten |
| Snyk Agent Scan (formerly Invariant MCP-Scan) [B17] | Scanner and issue taxonomy | Apache-2.0 | Taxonomy inspiration only; not a corpus; see 3.4 for its data flow |
| NVIDIA `garak` | LLM vulnerability scanner with injection and encoding probes | Apache-2.0 (GitHub API) | Possible generator of obfuscation strings for the known-miss ledger; the build issue verifies which probes apply |
| `gitleaks` (MIT, `LICENSE`), `detect-secrets` (Apache-2.0) | Secret rules and fixtures | as stated | Token shapes to compare against the rule list; not vendored |

The `modelcontextprotocol/servers` repository's GitHub licence field is "Other" (no single SPDX identifier), so
its definitions are **not** assumed usable as a benign corpus; read each directory's licence first.

### 10.4 Measurement

Per rule: true and false positives and negatives on the authored corpus; on public corpora the numbers are
published as informational trend lines with the pinned revision, with **no pass threshold** (they are attacks
against chat prompts, not MCP definitions). Every false positive or miss reported from shadow data becomes a
synthetic fixture (reproduced, never copied from a deployment), and every ruleset change reports the delta in a
corpus-result table in the pull request.

## 11. Acceptance tests the first build issue must pass

"First build issue" means F3 (with F4 for the UI wording and F1, F2 as prerequisites; [Appendix A](#appendix-a-follow-up-issues-drafts)).
Numeric gates marked *(proposed)* are starting points to be replaced by measured values with at least 2x headroom
before the issue's own gate is fixed; they are not measurements. Later slices re-run the relevant tests and add their own.

**A1. Corpus results.** (a) Every must-catch fixture produces its expected rule ids at the expected severity.
(b) **No benign near-miss produces a finding at medium or above**; low and info findings over the benign corpus
stay at or under 2 per 100 definitions *(proposed)*. (c) The set of fixtures with no finding equals the
known-miss ledger. (d) Public-corpus results are generated and archived by the scheduled job; they gate nothing.
(e) Secret-rule coverage: every built-in `secret.*` rule has generated positive and placeholder-negative fixtures,
and `TestBuiltInRules` and the capture sentinel tests pass **unmodified**.

**A2. Latency and resource budget.** A benchmark in CI measures (a) one 64 KiB definition: p99 ≤ 25 ms *(proposed)*;
(b) a refresh of 500 tools of 2 KiB: ≤ 250 ms of added CPU *(proposed)*; (c) the pathological inputs of 10.2 finish
inside the deadline or report `scan_incomplete`, allocate no more than a fixed multiple of the input (*proposed*: 8x),
and leave no goroutine behind; (d) a refresh against a server of 2,000 maximum-size definitions completes without
failing the refresh. **No code is added to `internal/mcpgw` in this issue**, and a test (or an import check) proves
the call path is unchanged; the call-path benchmark is identical within noise.

**A3. No payload text in logs, metrics, spans, audit, API or database.** A sentinel test, in the style of
`TestEchoedProviderTokenIsRedactedEverywhere` and `TestTracingCallTrace`, scans definitions that carry unique
canary strings (inside a matched span, in unmatched text, in a JSON key, in a parameter name) and then searches for
them in: every table (a full-text dump of the test database, excluding the stored definition itself), captured
`slog` output at debug level, the registered Prometheus metric families (names, help, label values), audit entries,
all API responses of the new operations (findings carry rule id, severity, count and pointer only; a pointer holds
only escaped structure names, never a matched value, and a property name carrying a tag-character payload is
returned escaped and truncated), error messages and spans. A schema test pins the column set of `scan_findings` (no free-text column beyond the constrained ones; the
`CHECK`s hold: inserting a long or spaced `rule_id`, or an arbitrary call `location`, fails).

**A4. Metric cardinality.** The `rule` label values are a subset of the catalog plus `pattern` and `external`; an
unknown rule id is rejected at registration and collapsed to `other` when it arrives from outside; no label carries
a gateway, server, team, person or request id; the new metrics appear in the registry that
`TestOpsArtifactsUseRealMetrics` parses.

**A5. Shadow is non-interfering.** With the definition stage `off` and `shadow`, everything except the new scan
fields (refresh results, stored definitions, fingerprints, `reviewDigest`, approvals, publish states) is
**byte-identical**; findings
never enter the digest (changing a ruleset version does not change a digest); a database error while writing findings
does not fail the refresh (it logs the class and increments `omp_scan_incomplete_total{reason="..."}`).

**A6. Failure behaviour.** A panic inside a rule is recovered and recorded as `scan_incomplete` (`panic`); over-budget
and over-limit inputs are `scan_incomplete`; an incomplete scan never shows as clean in the API or the UI.

**A7. Interplay (the tests that exist from slice 2 on, listed here so the design is held to them):**
curated fixed values equal vs omitted produce the same findings; a consent retry rescans without duplicating
approvals; a failover or read retry scans once per logical call and the discarded attempt is never scanned or
relayed; the result of an extra endpoint is scanned like the primary's; a governed call that spends an approval
and then gets a result-stage finding **does not restore the approval**; a scan block creates no approval request
and spends none; `require_approval` is additive (it cannot remove a rule's approval); a streamed call blocks before
the SSE stream starts and after it as the final response event; unclassified tools are treated as destructive for
withholding.

**A8. Authorization.** Findings and the rescan operation follow capability visibility (another team gets the
same `404` as a missing server); policy and settings operations are browser-session only (an automation token gets
`403 token_not_allowed`, per decision 58, and the token-scope contract test is unchanged); every
change is audited with before and after settings and no content; `If-Match` conflicts answer 409.

**A9. UI wording.** A Vitest test asserts the findings panel states that heuristics found *nothing*, that this does not
mean the definition is safe, and the ruleset version, and that no "passed", "safe", "clean" or green success state
exists for a capability with zero findings. The panel passes the axe checks the repository already requires.

**A10. Migration and compatibility.** Expand-only; the previous release runs against the new schema (existing
previous-image compatibility tooling); no ciphertext columns (so `TestColumnsCoverTheSchema` is unaffected; any
later sealed external-service secret joins `keyrotation.Columns` in its own issue); the purge functions and
retention treat the new table (database-roles review noted in 5.3).

**A11. Dependency and licence.** Any new direct dependency (for example promoting `golang.org/x/text`) is justified in
the pull request; no third-party corpus text is committed; corpus licences re-checked at the pinned revisions.

**A12. Documentation.** Threat model 7.5 is updated to describe what was shipped, and still lists "what this will
not catch"; the operator documentation repeats it next to the setting; no document claims blocking, redaction or
protection that the release does not provide.

## 12. Owner input and open questions

Delegated defaults are P1 to P12 above. Still needed from the owner:

1. **OMG's guardrails design.** Read `docs/guardrails-design.md` in the sister repository [B18] and say whether the
   portal's rule groups, severities, modes (`off`/`shadow`/`enforce`) and action names should line up with it, and
   whether OMG could be the first external service behind the contract in 3.4. This document makes no claim about
   its contents.
2. **Data-protection review** ([5.4](#54-data-protection-review-note)) before slice 2. Who owns it for this deployment?
3. **Default-on definition scanning at upgrade** (P1/section 4.2). The proposal is on, in shadow, because it is
   in process and sends nothing; the alternative is off until an admin enables it.
4. **Post-effect withholding** (4.3). May a policy ever withhold the result of a write or unclassified tool?
5. **Excerpts for triage** (5.2): never, or a small redacted-context option later.
6. **Thresholds.** The *(proposed)* latency, false-positive and enforcement-gate numbers are the assistant's
   starting points.
7. **Whether to ask the MCPTox authors for a licence** so its data can serve as a corpus.

## Appendix A: Follow-up issues (drafts)

F1–F4 (slices 0 and 1) are created on GitHub (#70–#73); F5–F14 remain **drafts, not created**, because each is gated on evidence from the slice before. Sizes follow [CONTRIBUTING.md](../CONTRIBUTING.md) (S a few days, M a week
or two, L several weeks). Every issue also requires the repository's usual gates (`make generate`, `make lint`,
tests including PostgreSQL integration, web checks when the UI changes) and its own docs and changelog line.

**F1 ([#70](https://github.com/ncecere/open-mcp-portal/issues/70)). Scanning test corpus and benchmark harness.** *Size M. Depends on: this design accepted.*
Build the in-repo corpus of section 10 (must-catch, benign near-misses, known-miss ledger, evasions, pathological,
generated secret fixtures, runtime-built Unicode fixtures), the scheduled job that downloads pinned permissive
public corpora and publishes per-rule numbers, and the benchmark harness for the budgets in 2 and A2.
*Acceptance:* the ledger test (A1c); generated fixtures never appear as literals in the repository; the harness runs
in CI with a measured baseline recorded; the job refuses a corpus whose licence is missing, inconsistent or gated;
no third-party text committed.

**F2 ([#71](https://github.com/ncecere/open-mcp-portal/issues/71)). Extract the secret rules into a shared registry (no behaviour change).** *Size S. Depends on: none (can
precede F1).* Move `capture.BuiltInRules`, sensitive keys and the exact-value rule behind a registry that offers
`Redact` (unchanged) and `Find` (rule id and count only); add the detect profile (minimum lengths, placeholder
suppression) as separate data. *Acceptance:* `TestBuiltInRules`, `TestCompileRefusals`, `TestPayloadCapture` and the
sentinel tests pass unmodified; redaction output is byte-identical on the existing corpus; `Find` returns no text.

**F3 ([#72](https://github.com/ncecere/open-mcp-portal/issues/72)). Definition scanning at refresh, in shadow (first build issue).** *Size M. Depends on: F1, F2.*
Ruleset v1 for definitions (secret, unicode, poison, length groups; ids as in 3); a hook in
`(*Service).refresh` in `internal/registry` before the transaction, written in the same transaction as `storeCapabilities`;
`scan_findings` (definition rows, CHECK-constrained identifiers, cascade with the capability); the platform setting
(`off`/`shadow`, default `shadow`, session-only, audited, `If-Match`); rescan of stored definitions (explicit
operation, plus a leader-elected backfill after upgrade or a ruleset change); the rule catalog operation; the
definition-stage metrics; threat-model and operator docs. *Acceptance:* A1 to A6, A8, A10 to A12.

**F4 ([#73](https://github.com/ncecere/open-mcp-portal/issues/73)). Findings in the Capabilities tab and the review dialogs.** *Size S. Depends on: F3.* A findings panel per
capability and a summary in the publish and review dialogs, with the ruleset version, the "found nothing does not
mean safe" wording and no success state. *Acceptance:* A9; keyboard and screen-reader use verified by axe in Vitest;
no hard-coded colours (the styling check).

**F5. Argument secret detection in shadow mode.** *Size M. Depends on: F3; the data-protection note.* Hook in
`(*request).call` after `curation.Merge` and before `checkRetry`; effective arguments minus fixed members;
detect-profile `secret.*` rules only; call findings rows with the coarse location class; `would_block` actions;
call detail and list filter; call-stage metrics. *Acceptance:* A1 to A7 for the call path; added p95 ≤ 2 ms for
≤ 16 KiB *(proposed)*; responses byte-identical with the stage on and off; a failure to write findings never fails
a call; the call row is the only link to a person.

**F6. Scan policies, platform ceilings and overrides.** *Size L. Depends on: F5.* `scan_policies`; platform
ceilings, floors, defaults; gateway and server overrides with the resolution rules of 4.2; suppression lists;
session-only, audited, revision-checked operations; UI. *Acceptance:* more-protective-wins, the external three-party
rule (stored, not yet usable), suppressible-rule restrictions, editors and tokens refused, mixed-version caution
documented.

**F7. Enforce blocking of high-confidence secrets in arguments.** *Size M. Depends on: F6 and the enforcement gate of
section 7.* `block` for `secret.*` high-severity rules; `-32010` `content_blocked` in both protocol eras (a block is never an
`input_required` result); the recorded outcome and class. *Acceptance:* a block precedes
credential lookup, consent and `Begin`; no approval is created or spent; no capture of the blocked arguments; the
gate evidence is attached; load test of the call path.

**F8. Result scanning in shadow mode.** *Size M. Depends on: F5.* Hook in `relay` after `scrubMetaFor` and the token
scrub; `content`, embedded resources, `resource_link`, `structuredContent`, prompt messages, read contents, error
text and progress messages; `binary_unscanned` counts; `inject.*` rules; deadlines and `scan_incomplete`.
*Acceptance:* A1 to A7 for the result path; scans exactly what the client receives; streamed calls unaffected
(progress inline, final response unchanged); added p95 ≤ 5 ms for ≤ 64 KiB *(proposed)*.

**F9. Result redaction and withholding.** *Size M. Depends on: F8.* `redact` for secret rules; `withhold` with the
post-effect warning and class-dependent defaults of 4.3; the outcome decision (new value or class only) and its
migration if needed; not captured. *Acceptance:* write and unclassified tools never lose a result by default; a
withheld result never restores or reuses an approval; usage rollups and alerts unaffected by the new class.

**F10. External scanning service.** *Size L. Depends on: F6, F8; owner decision on the data flow.* The contract of
3.4; platform registration with a sealed URL and secret (joins key rotation); `SCAN_EXTERNAL_ALLOWED_NETWORKS`;
three-party consent; redaction before send; breaker; metrics; settings-page data statement. *Acceptance:* the SSRF
cases of `notify.NewWebhookClient` (private, metadata, redirect, DNS rebinding, plain http) refuse; identity and
URLs never sent; returned text never stored; timeouts are `scan_incomplete`; a team A gateway cannot send team B's
server content without B's non-veto; key rotation covers the secret.

**F11. Curation text, fixed values and gateway-aware shadowing.** *Size M. Depends on: F3.* Scan
`descriptionOverride` and fixed/allowed values at save; flag secrets in fixed values ("not a vault"); add
`poison.cross_tool_reference` and `unicode.confusable_name` across the servers selected in one gateway.
*Acceptance:* audit still stores no raw values; a save is never blocked by shadow findings; selection save stays
within its work budgets.

**F12. Reviewer acknowledgement of findings.** *Size M. Depends on: F3, F4.* A reviewer can acknowledge specific
findings for a (fingerprint, ruleset version); the acknowledgement is recorded and audited and does not alter the
definition, the digest or approval. *Acceptance:* a changed fingerprint or ruleset invalidates it; an
acknowledgement never approves anything.

**F13. Custom scan rules.** *Size S. Depends on: F6.* Bounded, admin-authored RE2 rules for scanning (limits of
`capture.Compile`), separate from redaction patterns, label `pattern`. *Acceptance:* the compile refusals; matches
reported as counts only; patterns never logged.

**F14. Scan-triggered exact-call approval.** *Size L. Depends on: F6, F7; #31 shipped.* The approval-path extension
of 4.4: an explicit approval rule per policy, the scan digest in the binding, reviewers see rule ids, governed
semantics (primary-only, no retry, no upstream elicitation), `tools/call` only. *Acceptance:* additive-only;
a block never creates an approval; a spent approval is never restored by a later scan outcome; change-and-revert of
the ruleset does not resurrect an approval; requester self-approval refused; the preview stays redacted.

## Appendix B: Sources

Consulted for this design on 2026-10-30 (fetched, or read as search excerpts where marked). Claims taken from a
source are limited to what its abstract or text states.

- **B1** Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks" (2025-04-01): https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- **B2** Invariant Labs, "WhatsApp MCP Exploited" (2025-04-07), read as search excerpts: https://invariantlabs.ai/blog/whatsapp-mcp-exploited
- **B3** `invariantlabs-ai/mcp-injection-experiments` (no licence file): https://github.com/invariantlabs-ai/mcp-injection-experiments
- **B4** Wang et al., "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers", arXiv 2508.14925 (v2 2026-09-29; AAAI): https://arxiv.org/abs/2508.14925 ; repository (no licence file): https://github.com/zhiqiangwang4/MCPTox-Benchmark
- **B5** Hackett et al., "Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks against Prompt Injection and Jailbreak Detection Systems", arXiv 2504.11168: https://arxiv.org/abs/2504.11168
- **B6** Nasr et al., "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections", arXiv 2510.09023: https://arxiv.org/abs/2510.09023
- **B7** Beurer-Kellner et al., "Design Patterns for Securing LLM Agents against Prompt Injections", arXiv 2506.08837: https://arxiv.org/abs/2506.08837
- **B8** "Defeating Prompt Injections by Design", arXiv 2503.18813: https://arxiv.org/abs/2503.18813 (only its existence and title were consulted)
- **B9** Boucher and Anderson, "Trojan Source: Invisible Vulnerabilities" (USENIX Security 2023; CVE-2021-42574, CVE-2021-42694): https://trojansource.codes/ , https://arxiv.org/abs/2111.00169
- **B10** Rehberger, "ASCII Smuggler Tool: Crafting Invisible Text and Decoding Hidden Codes" (Unicode Tags): https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
- **B11** Butler, "Smuggling arbitrary data through an emoji" (variation selectors), read as a search excerpt: https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/
- **B12** Unicode Technical Standard #39, "Unicode Security Mechanisms", read as search excerpts: https://www.unicode.org/reports/tr39/
- **B13** OWASP, "MCP Security Cheat Sheet": https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- **B14** Model Context Protocol specification 2026-07-28, "Tools", security considerations (servers must validate inputs and sanitize outputs; clients should show inputs and validate results before passing them to the model): https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- **B15** Willison, "The lethal trifecta for AI agents: private data, untrusted content, and external communication" (2025-06-16), read as search excerpts: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- **B16** Young, "Protecting against indirect prompt injection attacks in MCP" (Microsoft for Developers, 2025-04-28), read as search excerpts: https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/ ; Hines et al., "Defending Against Indirect Prompt Injection Attacks With Spotlighting" (listed in the same results, not read)
- **B17** Snyk Agent Scan (formerly Invariant MCP-Scan; `invariantlabs-ai/mcp-scan` redirects to it), README and `docs/issue-codes.md` (Apache-2.0): https://github.com/snyk/agent-scan
- **B18** Corpus and licence pages read on 2026-10-30: Lakera datasets on Hugging Face (`Lakera/gandalf_ignore_instructions`, `gandalf_summarization`, `mosscap_prompt_injection`: MIT on the cards); `deepset/prompt-injections` (card licence fields disagree); `hackaprompt/hackaprompt-dataset` (MIT, gated); GitHub licence files for `microsoft/BIPIA`, `ethz-spylab/agentdojo`, `uiuc-kang-lab/InjecAgent` (MIT), `NVIDIA/garak`, `Yelp/detect-secrets` (Apache-2.0), `gitleaks/gitleaks` (MIT); AWS IAM documentation page containing the example access key id `AKIAIOSFODNN7EXAMPLE`: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html ; the sister repository's `docs/guardrails-design.md` was **listed (its existence confirmed) and not read**: https://github.com/ncecere/open-model-gateway/blob/main/docs/guardrails-design.md
- **B19** "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", arXiv 2302.12173: https://arxiv.org/abs/2302.12173 (title consulted)
- **B20** "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents", arXiv 2406.13352: https://arxiv.org/abs/2406.13352 (title consulted)
- **B21** "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents", arXiv 2403.02691: https://arxiv.org/abs/2403.02691 (title consulted)
- **B22** "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models" (BIPIA), arXiv 2312.14197: https://arxiv.org/abs/2312.14197 (title consulted)
- **B23** "Ignore This Title and HackAPrompt: Exposing Systemic Vulnerabilities of LLMs through a Global Scale Prompt Hacking Competition", arXiv 2311.16119: https://arxiv.org/abs/2311.16119 (title consulted)

## Decision entry

Recorded as **decision 87** in [decisions.md](decisions.md) (86 is the in-development tasks relay, #35). The text:

| N | Content scanning: go for shadow-mode detection, no for a hosted model *(#52; owner delegated defaults to the assistant, 2026-10-30)* | Decision 50's "design before building" is satisfied by [content-scanning.md](content-scanning.md). **Go, narrowly.** The first build is static scanning of tool definitions when they are refreshed, in **shadow mode**, with findings shown beside the capabilities and in the review and publish dialogs (rule id, severity, count, location pointer, ruleset version; never "safe"); it adds no code to the call path. Argument secret detection follows in shadow mode, then per-gateway and per-server policies under platform ceilings that default to `shadow`; **blocking, redaction, result withholding and scan-triggered approvals each need measured false positives and a decision row of their own.** Definition findings never change a definition, never enter the review digest and never auto-act. **The portal hosts no model and calls no LLM as a scanner.** An **external scanning service** is optional, off by default, available only on explicit per-gateway opt-in enabled by a platform admin and not vetoed by the server's team, never receives identity, receives content redacted by the portal's rules first, and returns only rule ids and counts (SSRF-guarded like notification webhooks, with its own allowlist). Evidence is rule id, stage, severity, count, action and (definitions only) a pointer: **never matched text, excerpts, offsets, or hashes of matched values**; call findings are kept with call metadata retention. Fail open by default; an incomplete scan is recorded as incomplete, never clean. Argument scans see curation-merged arguments minus fixed members and run before approval `Begin`, so a block never creates or spends an approval; a scan that requires approval is additive and reuses the exact-call path, and no later stage restores a spent approval; results of write, destructive and unclassified tools are not withheld by default because the effect has already happened. Personal-data detectors are not proposed. The proposed defaults are the issue's recommendations (detection-only first, external only by explicit opt-in, review-time checks before argument DLP); the owner may override any of them. **Nothing is implemented**; threat model 7.5 says so. Owner input still needed: the relationship to OMG's guardrails design and the data-protection review |
