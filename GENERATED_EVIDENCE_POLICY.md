# Generated contract evidence policy

Generated contract artifacts are disposable verification evidence, never authored authority.

- Keep generated JSON Schema, Contract IR, SARIF, parity reports, receipts, and temporary drift copies under `.typespec-json-schema-validator/` or another explicitly disposable evidence root.
- Never emit generated artifacts into an authored `contracts/**` source path or overwrite `main.tsp` / `authored.schema.json`.
- Promotion must bind the exact current TypeSpec source, independently authored JSON Schema source, generated Schema B, report, Contract IR, and complete declaration inventory.
- Evidence from a previous commit, another branch, or an incomplete declaration scope must fail admission.
- Negative drift fixtures must mutate scratch copies only; both authored lanes remain byte-for-byte unchanged.
- Artifact upload/retention is diagnostic transport and may be best-effort. Parity and consumer admission remain fail-closed.
- CI should clean or recreate the evidence root before each positive run so stale output cannot satisfy current-head verification.

The repository may retain selected receipts as release evidence, but retention never promotes generated material into a peer authority.
