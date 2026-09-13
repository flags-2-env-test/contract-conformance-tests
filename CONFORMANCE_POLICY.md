# Conformance policy

This public sibling test repository is executable conformance evidence; it is not a source of production authority.

- TypeSpec and JSON Schema Draft 2020-12 are independent, human-authored peer authorities.
- TypeSpec may be transpiled to generated JSON Schema B only as disposable comparison evidence.
- Generated Schema B, Contract IR, SARIF, receipts, and language projections never outrank or overwrite either authored source.
- Semantic comparison and consumer admission are fail-closed and use immutable TJSV revisions.
- A TypeSpec-only semantic drift and a JSON-Schema-only semantic drift must each be capable of failing admission independently.
- Exact pull-request head identity must be verified before test evidence is treated as merge evidence.
- Zero-step, startup-failed, cancelled, or no-runner Actions are not green evidence.
- Diagnostic artifact transport may be best-effort; semantic admission may not be softened to compensate for artifact quota or transport failures.
- `ores-cli` may lint repository wiring and provenance, but TJSV remains the semantic comparison/admission engine.
- Authored contract files must remain byte-for-byte unchanged by generation and verification.

A green canary certifies only the declarations and runtime boundary exercised by that canary. It does not imply production readiness for unrelated contracts.
