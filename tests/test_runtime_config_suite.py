from __future__ import annotations

import os
import re
import tomllib
import unittest

PRODUCT = os.environ.get("RUNTIME_CONFIG_PRODUCT", "flags-2-env-test")
ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
POLICY_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
KEY_VERSION = re.compile(r"^v[1-9][0-9]*$")
SECRET_ENV_MARKERS = (
    "DATABASE_URL",
    "NATS_URL",
    "REDIS_URL",
    "HMAC",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
)

AUTHORITY_PINS = {
    "middleware": ("ORESoftware/ores-middleware", "0ba59b36777345989788f8cd4687c10735546c3d"),
    "rate_limit": ("ores-rate-limit/ores-rl-interfaces", "241353d0f5269450690d9646be03db2aba59a2ae"),
    "lru": ("ores-redis-lru-cache/ores-lru-redis-interfaces", "4474d240b38a4fe1dd24f01dcd2e9ab7a4c34b27"),
    "shared_auth": ("shared-auth/shared-auth-interfaces", "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"),
    "fanwaave": ("fanwaave/fanwaave-interfaces", "e27695091a5b8276543a6f435156a25043f297a9"),
}
TJSV_PINS = {
    "middleware": "4473504c4c9d2831d825919f70c03994d8ce01d2",
    "rate_limit": "2281843126ab644607b11cf8281d84f382d68dfc",
    "lru": "2281843126ab644607b11cf8281d84f382d68dfc",
    "fanwaave": "4a5d049218adc2740d4cf78f612caf7f38f6f64c",
}


def loads(text: str) -> dict:
    return tomllib.loads(text)


def safe_repo_path(value: str) -> bool:
    if value == ".":
        return True
    if not value or value.startswith("/") or value.endswith("/") or "\\" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def require_env_name(value: str) -> None:
    if not isinstance(value, str) or not ENV_KEY.fullmatch(value):
        raise ValueError("expected environment-variable name")


def validate_cli(cfg: dict) -> set[str]:
    if cfg.get("env", {}).get("load") is not False:
        raise ValueError("test profile must disable dotenv loading")
    if cfg.get("parse", {}).get("allow_unknown") is not False:
        raise ValueError("unknown CLI options must fail closed")
    envs: set[str] = set()
    for spec in cfg.get("flags", {}).values():
        env = spec.get("env")
        require_env_name(env)
        if any(marker in env for marker in SECRET_ENV_MARKERS):
            raise ValueError("secret-bearing environment key exposed as CLI flag")
        if env in envs:
            raise ValueError("duplicate CLI environment key")
        envs.add(env)
    return envs


def validate_middleware(cfg: dict) -> None:
    allowed_root = {"schema_version", "repository_mode", "default_target", "allow_overlapping_roots", "targets", "env"}
    if set(cfg) - allowed_root:
        raise ValueError("unknown middleware root key")
    if cfg.get("schema_version") != 1:
        raise ValueError("middleware schema version")
    mode = cfg.get("repository_mode")
    if mode not in {"server-only", "client-only", "hybrid"}:
        raise ValueError("middleware repository mode")
    targets = cfg.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("middleware targets required")
    names: set[str] = set()
    roots_by_target: list[tuple[str, str]] = []
    roles: set[str] = set()
    for target in targets:
        allowed = {"name", "role", "roots", "enabled", "middleware", "stack_config", "propagate_headers"}
        if set(target) - allowed:
            raise ValueError("unknown middleware target key")
        name = target.get("name")
        role = target.get("role")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("middleware target identity")
        names.add(name)
        if role not in {"client", "server"}:
            raise ValueError("middleware target role")
        roles.add(role)
        roots = target.get("roots")
        if not isinstance(roots, list) or not roots:
            raise ValueError("middleware target roots")
        for root in roots:
            if not safe_repo_path(root):
                raise ValueError("unsafe middleware root")
            roots_by_target.append((name, root))
        mw = target.get("middleware")
        if mw == "stack":
            if role != "server" or not safe_repo_path(target.get("stack_config", "")) or target.get("stack_config") == ".":
                raise ValueError("unsafe server middleware stack")
        elif mw == "propagation-only":
            headers = target.get("propagate_headers")
            if role != "client" or not isinstance(headers, list) or not headers or len(headers) != len(set(headers)):
                raise ValueError("unsafe client propagation config")
            if any(not isinstance(h, str) or h != h.lower() for h in headers):
                raise ValueError("noncanonical propagation header")
        elif mw != "disabled":
            raise ValueError("middleware mode")
    if mode == "server-only" and roles != {"server"}:
        raise ValueError("server-only middleware role leak")
    if mode == "client-only" and roles != {"client"}:
        raise ValueError("client-only middleware role leak")
    if mode == "hybrid" and roles != {"client", "server"}:
        raise ValueError("hybrid middleware roles")
    overlaps = len(roots_by_target) != len({root for _, root in roots_by_target})
    if overlaps and not cfg.get("allow_overlapping_roots", False):
        raise ValueError("ambiguous middleware root overlap")
    default = cfg.get("default_target")
    if default is not None and default not in names:
        raise ValueError("unknown default middleware target")


def validate_rate_limit(cfg: dict) -> None:
    allowed_root = {"schemaVersion", "layout", "defaultPolicyId", "client", "server", "policies"}
    if set(cfg) - allowed_root:
        raise ValueError("unknown rate-limit root key")
    if cfg.get("schemaVersion") != "ores.rate-limit.config.v1":
        raise ValueError("rate-limit schema version")
    layout = cfg.get("layout")
    client = cfg.get("client")
    server = cfg.get("server")
    if layout == "client-only":
        if client is None or server is not None:
            raise ValueError("client-only rate-limit role leak")
    elif layout == "server-only":
        if server is None or client is not None:
            raise ValueError("server-only rate-limit role leak")
    elif layout == "combined":
        if client is None or server is None:
            raise ValueError("combined rate-limit roles")
    else:
        raise ValueError("rate-limit layout")
    if client is not None and not safe_repo_path(client.get("root", "")):
        raise ValueError("unsafe client root")
    if server is not None:
        if not safe_repo_path(server.get("root", "")):
            raise ValueError("unsafe server root")
        require_env_name(server.get("keyHmacEnv"))
        backend = server.get("backend")
        redis_env = server.get("redisUrlEnv")
        if backend == "redis":
            require_env_name(redis_env)
        elif backend == "local":
            if redis_env is not None:
                raise ValueError("local backend may not carry Redis metadata")
        else:
            raise ValueError("rate-limit backend")
        if server.get("enforcementLayer") not in {"edge", "load-balancer", "service", "authentication", "data-store"}:
            raise ValueError("rate-limit enforcement layer")
    policies = cfg.get("policies")
    if not isinstance(policies, list) or not 1 <= len(policies) <= 1024:
        raise ValueError("rate-limit policies")
    ids: set[str] = set()
    for policy in policies:
        pid = policy.get("policyId")
        if not isinstance(pid, str) or not POLICY_ID.fullmatch(pid) or pid in ids:
            raise ValueError("rate-limit policy id")
        ids.add(pid)
        capacity = policy.get("capacity")
        request_cost = policy.get("requestCost")
        overshoot = policy.get("maxOvershoot")
        if not isinstance(capacity, int) or not 1 <= capacity <= 1_000_000_000:
            raise ValueError("rate-limit capacity")
        if not isinstance(request_cost, int) or not 1 <= request_cost <= capacity:
            raise ValueError("rate-limit request cost")
        if not isinstance(overshoot, int) or not 0 <= overshoot <= capacity:
            raise ValueError("rate-limit overshoot")
        deny_mode = policy.get("denyCacheMode")
        if deny_mode not in {"local-denials", "redis-denial-fanout", "redis-strict-blocks"}:
            raise ValueError("rate-limit deny cache mode")
        if str(deny_mode).startswith("redis-") and (server is None or server.get("backend") != "redis"):
            raise ValueError("Redis denial cache requires Redis backend")
        if policy.get("enforcementMode") not in {"enforce", "observe-only", "disabled"}:
            raise ValueError("rate-limit enforcement mode")
        if policy.get("consistencyMode") not in {"strict", "bounded", "advisory"}:
            raise ValueError("rate-limit consistency")
        if policy.get("backendFailureMode") not in {"fail-open", "fail-closed", "local-fallback"}:
            raise ValueError("rate-limit backend failure mode")
        if policy.get("algorithm") == "token-bucket":
            if policy.get("windowMs") != 0 or policy.get("refillTokens", 0) <= 0 or policy.get("refillIntervalMs", 0) <= 0:
                raise ValueError("token-bucket parameters")
        elif policy.get("algorithm") in {"fixed-window", "sliding-window", "gcra"}:
            if policy.get("windowMs", 0) <= 0 or policy.get("refillTokens") != 0 or policy.get("refillIntervalMs") != 0:
                raise ValueError("windowed algorithm parameters")
        else:
            raise ValueError("rate-limit algorithm")
        if policy.get("consistencyMode") == "strict":
            if server is None or server.get("backend") != "redis" or policy.get("backendFailureMode") != "fail-closed" or overshoot != 0:
                raise ValueError("strict rate limit requires Redis/fail-closed/zero overshoot")
        if not KEY_VERSION.fullmatch(str(policy.get("keyVersion", ""))):
            raise ValueError("rate-limit key version")
        version = policy.get("policyVersion")
        if not isinstance(version, int) or not 1 <= version <= 9_007_199_254_740_991:
            raise ValueError("rate-limit policy version")
    default = cfg.get("defaultPolicyId")
    if default not in ids:
        raise ValueError("missing default rate-limit policy")
    if client is not None and client.get("exposePolicyMetadata"):
        selected = next(p for p in policies if p["policyId"] == default)
        if not selected.get("clientVisible"):
            raise ValueError("client-visible default policy required")


def validate_lru(cfg: dict) -> None:
    allowed_root = {"protocol", "namespace", "roles", "redis", "defaults", "roleOverrides", "caches"}
    if set(cfg) - allowed_root:
        raise ValueError("unknown LRU root key")
    if cfg.get("protocol") != "ores.lru-config.v1":
        raise ValueError("LRU protocol")
    roles = cfg.get("roles")
    if not isinstance(roles, list) or not 1 <= len(roles) <= 2 or len(roles) != len(set(roles)) or set(roles) - {"client", "server"}:
        raise ValueError("LRU repository roles")
    redis = cfg.get("redis")
    if roles == ["client"] and redis is not None:
        raise ValueError("client-only LRU config may not expose Redis")
    if redis is not None:
        require_env_name(redis.get("urlEnv"))
        if not 1_000 <= redis.get("reconcileIntervalMs", 0) <= 180_000:
            raise ValueError("LRU reconciliation interval")
        lo = redis.get("reconnectMinMs", 0)
        hi = redis.get("reconnectMaxMs", 0)
        if not 100 <= lo <= 30_000 or not 1_000 <= hi <= 300_000 or lo > hi:
            raise ValueError("LRU reconnect bounds")
    defaults = cfg.get("defaults", {})
    if not 1 <= defaults.get("capacity", 0) <= 1_000_000:
        raise ValueError("LRU capacity")
    if defaults.get("syncMode") not in {"local_only", "read_only", "write_through", "bidirectional"}:
        raise ValueError("LRU sync mode")
    if defaults.get("overflowMode") not in {"evict_lru", "reject_and_reconcile"}:
        raise ValueError("LRU overflow mode")
    overrides: dict[str, dict] = {}
    for item in cfg.get("roleOverrides", []):
        role = item.get("role")
        if role not in roles or role in overrides:
            raise ValueError("LRU role override")
        overrides[role] = item
    identities: set[tuple[str, str]] = set()
    for cache in cfg.get("caches", []):
        role = cache.get("role")
        name = cache.get("name")
        identity = (role, name)
        if role not in roles or not isinstance(name, str) or not name or identity in identities:
            raise ValueError("LRU cache identity")
        identities.add(identity)
        effective = dict(defaults)
        effective.update(overrides.get(role, {}))
        effective.update(cache)
        sync_mode = effective.get("syncMode")
        if role == "client" and sync_mode != "local_only":
            raise ValueError("client cache must remain local-only")
        if role == "server" and sync_mode != "local_only" and redis is None:
            raise ValueError("server backend cache requires Redis metadata")


def validate_shared_auth(cfg: dict, present_names: set[str]) -> None:
    if {".shared-auth.toml", ".auth-shared.toml"} <= present_names:
        raise ValueError("dual Shared Auth aliases are ambiguous")
    allowed_root = {"schema_version", "compatibility", "factors", "pages", "styling"}
    if set(cfg) - allowed_root:
        raise ValueError("unknown Shared Auth root key")
    if cfg.get("schema_version") != 1:
        raise ValueError("Shared Auth schema version")
    compatibility = cfg.get("compatibility", {})
    if compatibility.get("repository") != "https://github.com/shared-auth/shared-auth-interfaces":
        raise ValueError("Shared Auth authority repository")
    commit = compatibility.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Shared Auth immutable revision")


def validate_fanwaave(cfg: dict, cli_envs: set[str]) -> None:
    allowed_root = {"version", "mode", "strict", "flags2env", "env", "client", "server"}
    if set(cfg) - allowed_root:
        raise ValueError("unknown Fanwaave root key")
    if cfg.get("version") != 1 or cfg.get("strict") is not True:
        raise ValueError("Fanwaave version/strict mode")
    flags = cfg.get("flags2env", {})
    if flags.get("contract") != ".cli-flags.toml" or flags.get("require_audit") is not True or flags.get("precedence") != "argv-over-env":
        raise ValueError("Fanwaave flags-2-env contract")
    mode = cfg.get("mode")
    client_enabled = cfg.get("client", {}).get("enabled") is True
    server_enabled = cfg.get("server", {}).get("enabled") is True
    if mode == "client" and (not client_enabled or server_enabled):
        raise ValueError("Fanwaave client mode")
    if mode == "server" and (not server_enabled or client_enabled):
        raise ValueError("Fanwaave server mode")
    if mode == "hybrid" and (not client_enabled or not server_enabled):
        raise ValueError("Fanwaave hybrid mode")
    if mode not in {"client", "server", "hybrid"}:
        raise ValueError("Fanwaave mode")
    names: set[str] = set()
    keys: set[str] = set()
    for binding in cfg.get("env", []):
        name = binding.get("name")
        key = binding.get("key")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) or name in names:
            raise ValueError("Fanwaave binding name")
        require_env_name(key)
        if key in keys:
            raise ValueError("Fanwaave duplicate env key")
        names.add(name)
        keys.add(key)
        if binding.get("secret") is True:
            if "default" in binding:
                raise ValueError("Fanwaave secret default")
            if key in cli_envs:
                raise ValueError("Fanwaave secret exposed through argv")


SERVER_MW = '''
schema_version = 1
repository_mode = "server-only"
[[targets]]
name = "server"
role = "server"
roots = ["."]
middleware = "disabled"
'''
CLIENT_MW = '''
schema_version = 1
repository_mode = "client-only"
default_target = "client"
[[targets]]
name = "client"
role = "client"
roots = ["."]
middleware = "propagation-only"
propagate_headers = ["traceparent", "tracestate", "baggage", "x-request-id"]
'''
HYBRID_MW = '''
schema_version = 1
repository_mode = "hybrid"
allow_overlapping_roots = true
[[targets]]
name = "server"
role = "server"
roots = ["."]
middleware = "disabled"
[[targets]]
name = "client"
role = "client"
roots = ["."]
middleware = "propagation-only"
propagate_headers = ["traceparent", "x-request-id"]
'''

RL_POLICY = '''
[[policies]]
policyId = "default"
clientVisible = true
algorithm = "token-bucket"
identityScope = "anonymous-ip"
capacity = 120
windowMs = 0
refillTokens = 120
refillIntervalMs = 60000
requestCost = 1
enforcementMode = "observe-only"
consistencyMode = "advisory"
backendFailureMode = "fail-open"
denyCacheMode = "local-denials"
denyCacheCapacity = 1024
maxOvershoot = 120
maxBlockTtlMs = 60000
keyVersion = "v1"
policyVersion = 1
'''
SERVER_RL = '''
schemaVersion = "ores.rate-limit.config.v1"
layout = "server-only"
defaultPolicyId = "default"
[server]
root = "."
backend = "local"
enforcementLayer = "service"
keyHmacEnv = "ORES_RL_HMAC_KEY"
''' + RL_POLICY
CLIENT_RL = '''
schemaVersion = "ores.rate-limit.config.v1"
layout = "client-only"
defaultPolicyId = "default"
[client]
root = "."
exposePolicyMetadata = true
''' + RL_POLICY
HYBRID_RL = '''
schemaVersion = "ores.rate-limit.config.v1"
layout = "combined"
defaultPolicyId = "default"
[client]
root = "."
exposePolicyMetadata = true
[server]
root = "."
backend = "local"
enforcementLayer = "service"
keyHmacEnv = "ORES_RL_HMAC_KEY"
''' + RL_POLICY

SERVER_LRU = '''
protocol = "ores.lru-config.v1"
namespace = "test-product"
roles = ["server"]
[redis]
urlEnv = "REDIS_URL"
keyPrefix = "ores:lru:test"
pubsubChannel = "ores:lru:test:events"
reconcileIntervalMs = 180000
reconnectMinMs = 1000
reconnectMaxMs = 30000
[defaults]
capacity = 1024
syncMode = "read_only"
overflowMode = "reject_and_reconcile"
failOpenOnStartup = false
[[caches]]
name = "runtime-env"
role = "server"
'''
CLIENT_LRU = '''
protocol = "ores.lru-config.v1"
namespace = "test-product"
roles = ["client"]
[defaults]
capacity = 256
syncMode = "local_only"
overflowMode = "evict_lru"
failOpenOnStartup = false
[[caches]]
name = "runtime-env"
role = "client"
'''
HYBRID_LRU = '''
protocol = "ores.lru-config.v1"
namespace = "test-product"
roles = ["client", "server"]
[redis]
urlEnv = "REDIS_URL"
keyPrefix = "ores:lru:test"
pubsubChannel = "ores:lru:test:events"
reconcileIntervalMs = 180000
reconnectMinMs = 1000
reconnectMaxMs = 30000
[defaults]
capacity = 1024
syncMode = "local_only"
overflowMode = "evict_lru"
failOpenOnStartup = false
[[roleOverrides]]
role = "server"
syncMode = "read_only"
overflowMode = "reject_and_reconcile"
[[caches]]
name = "runtime-env"
role = "client"
capacity = 256
syncMode = "local_only"
[[caches]]
name = "runtime-env"
role = "server"
capacity = 1024
syncMode = "read_only"
overflowMode = "reject_and_reconcile"
'''

SHARED_AUTH = '''
schema_version = 1
[compatibility]
repository = "https://github.com/shared-auth/shared-auth-interfaces"
commit = "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"
[factors.two_factor]
required = false
methods = ["totp", "passkey", "security-key"]
[factors.three_factor]
enabled = false
methods = ["totp", "passkey", "security-key"]
[pages]
show = ["sign-in", "challenge", "recovery", "error", "signed-out"]
[styling]
theme = "system"
brand_name = "Test Product"
accent_color = "#4F46E5"
'''

PUBLIC_CLI = '''
[env]
load = false
[parse]
allow_unknown = false
[flags.api_base_url]
env = "FANWAAVE_API_BASE_URL"
aliases = ["api-base-url"]
type = "string"
[flags.tenant_id]
env = "FANWAAVE_TENANT_ID"
aliases = ["tenant-id"]
type = "string"
[flags.bind_addr]
env = "FANWAAVE_BIND_ADDR"
aliases = ["bind-addr"]
type = "string"
'''

FANWAAVE_HYBRID = '''
version = 1
mode = "hybrid"
strict = true
[flags2env]
contract = ".cli-flags.toml"
require_audit = true
precedence = "argv-over-env"
[client]
enabled = true
api_base_url_binding = "api_base_url"
tenant_id_binding = "tenant_id"
auth_token_binding = "auth_token"
[server]
enabled = true
bind_addr_binding = "bind_addr"
database_url_binding = "database_url"
[[env]]
name = "api_base_url"
key = "FANWAAVE_API_BASE_URL"
kind = "url"
required = true
secret = false
default = "https://api.example.test"
[[env]]
name = "tenant_id"
key = "FANWAAVE_TENANT_ID"
kind = "string"
required = true
secret = false
[[env]]
name = "auth_token"
key = "FANWAAVE_AUTH_TOKEN"
kind = "string"
required = true
secret = true
[[env]]
name = "bind_addr"
key = "FANWAAVE_BIND_ADDR"
kind = "string"
required = false
secret = false
default = "0.0.0.0:8080"
[[env]]
name = "database_url"
key = "DATABASE_URL"
kind = "url"
required = true
secret = true
'''


class RuntimeConfigSuite(unittest.TestCase):
    def test_authority_and_validator_pins_are_immutable(self) -> None:
        for repo, sha in AUTHORITY_PINS.values():
            self.assertRegex(sha, r"^[0-9a-f]{40}$", repo)
        for name, sha in TJSV_PINS.items():
            self.assertRegex(sha, r"^[0-9a-f]{40}$", name)

    def test_valid_server_client_and_same_root_hybrid_profiles(self) -> None:
        cli_envs = validate_cli(loads(PUBLIC_CLI))
        for mw in (SERVER_MW, CLIENT_MW, HYBRID_MW):
            validate_middleware(loads(mw))
        for rl in (SERVER_RL, CLIENT_RL, HYBRID_RL):
            validate_rate_limit(loads(rl))
        for lru in (SERVER_LRU, CLIENT_LRU, HYBRID_LRU):
            validate_lru(loads(lru))
        validate_shared_auth(loads(SHARED_AUTH), {".auth-shared.toml"})
        validate_fanwaave(loads(FANWAAVE_HYBRID), cli_envs)

    def test_rate_limit_disabled_deny_cache_is_rejected(self) -> None:
        bad = loads(SERVER_RL.replace('denyCacheMode = "local-denials"', 'denyCacheMode = "disabled"'))
        with self.assertRaisesRegex(ValueError, "deny cache mode"):
            validate_rate_limit(bad)

    def test_rate_limit_strict_local_is_rejected(self) -> None:
        bad = loads(SERVER_RL.replace('consistencyMode = "advisory"', 'consistencyMode = "strict"').replace('backendFailureMode = "fail-open"', 'backendFailureMode = "fail-closed"').replace('maxOvershoot = 120', 'maxOvershoot = 0'))
        with self.assertRaisesRegex(ValueError, "strict rate limit"):
            validate_rate_limit(bad)

    def test_rate_limit_root_traversal_is_rejected(self) -> None:
        bad = loads(CLIENT_RL.replace('root = "."', 'root = "../client"'))
        with self.assertRaisesRegex(ValueError, "unsafe client root"):
            validate_rate_limit(bad)

    def test_redis_literal_is_rejected_everywhere(self) -> None:
        bad_lru = loads(SERVER_LRU.replace('urlEnv = "REDIS_URL"', 'urlEnv = "redis://user:pass@cache"'))
        with self.assertRaisesRegex(ValueError, "environment-variable name"):
            validate_lru(bad_lru)
        redis_rl = SERVER_RL.replace('backend = "local"', 'backend = "redis"').replace('keyHmacEnv = "ORES_RL_HMAC_KEY"', 'redisUrlEnv = "redis://user:pass@cache"\nkeyHmacEnv = "ORES_RL_HMAC_KEY"')
        with self.assertRaisesRegex(ValueError, "environment-variable name"):
            validate_rate_limit(loads(redis_rl))

    def test_client_lru_may_not_receive_redis_transport(self) -> None:
        bad = loads(CLIENT_LRU + '\n[redis]\nurlEnv = "REDIS_URL"\nkeyPrefix = "x"\npubsubChannel = "x"\nreconcileIntervalMs = 180000\nreconnectMinMs = 1000\nreconnectMaxMs = 30000\n')
        with self.assertRaisesRegex(ValueError, "client-only LRU"):
            validate_lru(bad)

    def test_shared_auth_dual_aliases_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "dual Shared Auth aliases"):
            validate_shared_auth(loads(SHARED_AUTH), {".shared-auth.toml", ".auth-shared.toml"})

    def test_secret_cli_flags_are_rejected(self) -> None:
        bad = loads(PUBLIC_CLI + '\n[flags.database]\nenv = "DATABASE_URL"\naliases = ["database-url"]\ntype = "string"\n')
        with self.assertRaisesRegex(ValueError, "secret-bearing"):
            validate_cli(bad)

    def test_fanwaave_secret_defaults_are_rejected(self) -> None:
        bad = loads(FANWAAVE_HYBRID.replace('key = "DATABASE_URL"\nkind = "url"\nrequired = true\nsecret = true', 'key = "DATABASE_URL"\nkind = "url"\nrequired = true\nsecret = true\ndefault = "postgres://user:pass@db"'))
        with self.assertRaisesRegex(ValueError, "secret default"):
            validate_fanwaave(bad, validate_cli(loads(PUBLIC_CLI)))

    def test_fanwaave_secret_cannot_be_argv_surface(self) -> None:
        cli = loads(PUBLIC_CLI + '\n[flags.auth_token]\nenv = "FANWAAVE_AUTH_TOKEN"\naliases = ["auth-token"]\ntype = "string"\n')
        with self.assertRaisesRegex(ValueError, "secret-bearing"):
            validate_cli(cli)

    def test_hybrid_overlap_requires_explicit_opt_in(self) -> None:
        bad = loads(HYBRID_MW.replace('allow_overlapping_roots = true\n', ''))
        with self.assertRaisesRegex(ValueError, "ambiguous middleware root overlap"):
            validate_middleware(bad)

    def test_unknown_fields_fail_closed(self) -> None:
        bad = loads(SERVER_MW + '\nshadow_parser = true\n')
        with self.assertRaisesRegex(ValueError, "unknown middleware root key"):
            validate_middleware(bad)


if __name__ == "__main__":
    print(f"runtime-config-suite product={PRODUCT}")
    unittest.main(verbosity=2)
