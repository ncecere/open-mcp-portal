# Known misses (primitive-only baseline)

These original fixtures produce no findings. This is not a safety verdict.
Removing or detecting any entry requires updating both this ledger and the pinned
expectation set in TestKnownMissLedger. Unicode/phrasing/JSON scanners are absent,
not successful detectors. No stage severity/completeness is asserted.

| ID | Missing capability |
| --- | --- |
| paraphrase | phrasing |
| german | phrasing |
| base64 | encoding |
| split-secret | cross-field |
| split-instruction | phrasing |
| image | binary |
| personal-data | personal-data |
| tag | unicode |
| bidi | unicode |
| zero-width | unicode |
| fullwidth | normalization |
| json-escape | json-scanner |
| json-secret-escape | json-scanner |
| combining | normalization |
