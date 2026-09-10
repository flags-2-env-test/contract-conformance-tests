# Immutable contract snapshots

These files are downstream evidence only. They are exact Git-blob copies of independently authored contract authorities from private repositories so public `*-test` workflows can run TJSV without cross-organization credentials.

- rate-limit: `ores-rate-limit/ores-rl-interfaces@241353d0f5269450690d9646be03db2aba59a2ae`
- Redis/LRU: `ores-redis-lru-cache/ores-lru-redis-interfaces@4474d240b38a4fe1dd24f01dcd2e9ab7a4c34b27`
- Shared Auth: `shared-auth/shared-auth-interfaces@52b7ac7fbf0c7c169684f613eda923f3aa6c82e9`

`verify_toml_config_convergence.py` recomputes Git blob identities before use. A changed snapshot fails closed. Generated TJSV schemas, Contract IR, reports, and these copies are not authored authorities and never override upstream TypeSpec or JSON Schema Draft 2020-12.
