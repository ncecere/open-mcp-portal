# Definition ruleset v1 known misses

Original, generated fixtures; no third-party text. A no-finding result is not a
safety verdict. TestDefinitionKnownMissLedger pins these identifiers.

| ID | Missing capability |
| --- | --- |
| paraphrase-guidance | Semantic paraphrase |
| paraphrase-disclosure | Semantic instruction analysis |
| unicode-spread-selectors | One selector per emoji base avoids run detection |
| length-split-fields | Many short fields evade per-field length thresholds |

This list is distinct from the primitive-only ledger: primitive tests intentionally
remain unchanged. Full Script_Extensions resolution, newer confusable tables,
split-field/non-English/encoded instructions, binary data and behaviour changes
are unsupported classes, not evaluated recall successes.
