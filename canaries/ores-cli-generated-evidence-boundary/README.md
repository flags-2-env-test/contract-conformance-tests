# ORES CLI generated-evidence boundary canary

This public `*-test` canary executes the exact `ORESoftware/ores-cli#191` generated-evidence lint source, byte-bound to product head `3893f8473c6b178d892b586469cb84469d9215fa`.

The invariant is deliberately structural and complements semantic TJSV admission already exercised in this repository:

- independently authored TypeSpec remains a first-class editable authority;
- independently authored JSON Schema Draft 2020-12 remains an equal editable peer;
- TJSV transpiles TypeSpec into generated JSON Schema B for comparison with authored Schema A;
- generated Schema B, Contract IR, parity reports, SARIF and similar output are evidence only;
- generated evidence must be isolated under explicit evidence/generated roots and can never occupy or contain an authored-authority location.

The workflow verifies the exact product module Git blob `35bccf979615f64aee88c4ffe204c0140038adb8` and exact production dispatcher snapshot `7f83f651d8e2d7694ac8a020d279ad047ab595fc` before running the product module's embedded positive/negative Rust regressions under debug and release profiles plus strict Clippy.
