import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace OresRateLimit;

// Independent top-level authority for the normalized `.ores-rl.toml` shape.
// This file is human-authored and must not be generated from JSON Schema.

@id("RateLimitRepositoryLayout")
enum RateLimitRepositoryLayout {
  clientOnly: "client-only",
  serverOnly: "server-only",
  combined: "combined",
}

@id("RateLimitConfigBackend")
enum RateLimitConfigBackend {
  local: "local",
  redis: "redis",
}

@id("RateLimitConfigAlgorithm")
enum RateLimitConfigAlgorithm {
  tokenBucket: "token-bucket",
  fixedWindow: "fixed-window",
  slidingWindow: "sliding-window",
  gcra: "gcra",
}

@id("RateLimitConfigEnforcementMode")
enum RateLimitConfigEnforcementMode {
  enforce: "enforce",
  observeOnly: "observe-only",
  disabled: "disabled",
}

@id("RateLimitConfigConsistencyMode")
enum RateLimitConfigConsistencyMode {
  strict: "strict",
  bounded: "bounded",
  advisory: "advisory",
}

@id("RateLimitConfigBackendFailureMode")
enum RateLimitConfigBackendFailureMode {
  failOpen: "fail-open",
  failClosed: "fail-closed",
  localFallback: "local-fallback",
}

@id("RateLimitConfigIdentityScope")
enum RateLimitConfigIdentityScope {
  anonymousIp: "anonymous-ip",
  authenticatedSubject: "authenticated-subject",
  authenticatedTenantSubject: "authenticated-tenant-subject",
}

@id("RateLimitConfigDenyCacheMode")
enum RateLimitConfigDenyCacheMode {
  localDenials: "local-denials",
  redisDenialFanout: "redis-denial-fanout",
  redisStrictBlocks: "redis-strict-blocks",
}

@id("RateLimitConfigEnforcementLayer")
enum RateLimitConfigEnforcementLayer {
  edge: "edge",
  loadBalancer: "load-balancer",
  service: "service",
  authentication: "authentication",
  dataStore: "data-store",
}

@id("RateLimitClientConfigV1")
model RateLimitClientConfigV1 {
  @minLength(1)
  @maxLength(255)
  root: string;

  exposePolicyMetadata: boolean;
}

@id("RateLimitServerConfigV1")
model RateLimitServerConfigV1 {
  @minLength(1)
  @maxLength(255)
  root: string;

  backend: RateLimitConfigBackend;
  enforcementLayer: RateLimitConfigEnforcementLayer;

  @minLength(1)
  @maxLength(128)
  redisUrlEnv?: string;

  @minLength(1)
  @maxLength(128)
  keyHmacEnv: string;
}

@id("RateLimitPolicyConfigV1")
model RateLimitPolicyConfigV1 {
  @minLength(1)
  @maxLength(128)
  @pattern("^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
  policyId: string;

  clientVisible: boolean;
  algorithm: RateLimitConfigAlgorithm;
  identityScope: RateLimitConfigIdentityScope;

  @minValue(1)
  @maxValue(1000000000)
  capacity: uint64;

  @minValue(0)
  @maxValue(2678400000)
  windowMs: uint64;

  @minValue(0)
  @maxValue(1000000000)
  refillTokens: uint64;

  @minValue(0)
  @maxValue(2678400000)
  refillIntervalMs: uint64;

  @minValue(1)
  @maxValue(1000000000)
  requestCost: uint64;

  enforcementMode: RateLimitConfigEnforcementMode;
  consistencyMode: RateLimitConfigConsistencyMode;
  backendFailureMode: RateLimitConfigBackendFailureMode;
  denyCacheMode: RateLimitConfigDenyCacheMode;

  @minValue(0)
  @maxValue(10000)
  denyCacheCapacity: uint32;

  @minValue(0)
  @maxValue(1000000000)
  maxOvershoot: uint64;

  @minValue(1)
  @maxValue(3600000)
  maxBlockTtlMs: uint64;

  @minLength(2)
  @maxLength(32)
  @pattern("^v[1-9][0-9]*$")
  keyVersion: string;

  @minValue(1)
  @maxValue(9007199254740991)
  policyVersion: uint64;
}

@id("RateLimitConfigV1")
model RateLimitConfigV1 {
  schemaVersion: "ores.rate-limit.config.v1";
  layout: RateLimitRepositoryLayout;

  @minLength(1)
  @maxLength(128)
  @pattern("^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
  defaultPolicyId: string;

  client?: RateLimitClientConfigV1;
  server?: RateLimitServerConfigV1;
  policies: RateLimitPolicyConfigV1[];
}
