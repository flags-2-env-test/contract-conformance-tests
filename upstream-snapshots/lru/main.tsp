import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace Ores.LruRedis.V1;

@id("CacheOperation")
enum CacheOperation {
  upsert: "upsert",
  delete: "delete",
  replace: "replace",
  invalidate: "invalidate",
  resync: "resync",
}

@id("BackendSyncMode")
enum BackendSyncMode {
  localOnly: "local_only",
  readOnly: "read_only",
  writeThrough: "write_through",
  bidirectional: "bidirectional",
}

@id("UpsertOverflowMode")
enum UpsertOverflowMode {
  evictLru: "evict_lru",
  rejectAndReconcile: "reject_and_reconcile",
}

@id("RepositoryRole")
enum RepositoryRole {
  client: "client",
  server: "server",
}

@id("RedisTransportConfig")
model RedisTransportConfig {
  urlEnv: string;
  keyPrefix: string;
  pubsubChannel: string;
  reconcileIntervalMs: integer;
  reconnectMinMs: integer;
  reconnectMaxMs: integer;
}

@id("CacheDefaults")
model CacheDefaults {
  capacity: integer;
  syncMode: BackendSyncMode;
  overflowMode: UpsertOverflowMode;
  failOpenOnStartup: boolean;
}

@id("RoleConfig")
model RoleConfig {
  role: RepositoryRole;
  capacity?: integer;
  syncMode?: BackendSyncMode;
  overflowMode?: UpsertOverflowMode;
  failOpenOnStartup?: boolean;
}

@id("ConfiguredCache")
model ConfiguredCache {
  name: string;
  role: RepositoryRole;
  capacity?: integer;
  syncMode?: BackendSyncMode;
  overflowMode?: UpsertOverflowMode;
  failOpenOnStartup?: boolean;
}

@id("OresLruConfig")
model OresLruConfig {
  protocol: "ores.lru-config.v1";
  `namespace`: string;
  roles: RepositoryRole[];
  redis?: RedisTransportConfig;
  defaults: CacheDefaults;
  roleOverrides?: RoleConfig[];
  caches: ConfiguredCache[];
}

@id("CacheEntry")
model CacheEntry {
  key: string;
  value: string;
}

@id("CacheState")
model CacheState {
  revision: integer;
  ready: boolean;
  stale: boolean;
  entryCount: integer;
}

@id("CacheSnapshot")
model CacheSnapshot {
  revision: integer;
  entries: CacheEntry[];
}

@id("CacheEvent")
model CacheEvent {
  protocol: "ores.lru-redis.v1";
  `namespace`: string;
  cache: string;
  revision: integer;
  operation: CacheOperation;
  entries?: CacheEntry[];
  keys?: string[];
  source: string;
  publishedAt: string;
}

@id("RateLimitBlock")
model RateLimitBlock {
  protocol: "ores.rate-limit.block.v1";
  policyId: string;
  keyVersion: string;
  issuedAtUnixMs: integer;
  expiresAtUnixMs: integer;
  reasonCode: string;
}
