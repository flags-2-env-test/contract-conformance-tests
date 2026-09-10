from __future__ import annotations

import re
import tomllib
import unittest

ENV = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
SECRET_MARKERS = ("DATABASE_URL", "NATS_URL", "REDIS_URL", "HMAC", "TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "ACCESS_KEY")
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


def t(text: str) -> dict:
    return tomllib.loads(text)


def safe_path(value: object) -> bool:
    if value == ".":
        return True
    if not isinstance(value, str) or not value or value.startswith("/") or value.endswith("/") or "\\" in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def env_name(value: object) -> None:
    if not isinstance(value, str) or not ENV.fullmatch(value):
        raise ValueError("env-name")


def cli_envs(cfg: dict) -> set[str]:
    if cfg.get("env", {}).get("load") is not False or cfg.get("parse", {}).get("allow_unknown") is not False:
        raise ValueError("cli-fail-closed")
    seen: set[str] = set()
    for flag in cfg.get("flags", {}).values():
        key = flag.get("env")
        env_name(key)
        if any(marker in key for marker in SECRET_MARKERS):
            raise ValueError("secret-cli")
        if key in seen:
            raise ValueError("duplicate-cli-env")
        seen.add(key)
    return seen


def middleware(cfg: dict) -> None:
    allowed = {"schema_version", "repository_mode", "default_target", "allow_overlapping_roots", "targets", "env"}
    if set(cfg) - allowed:
        raise ValueError("unknown-middleware-root")
    if cfg.get("schema_version") != 1:
        raise ValueError("middleware-version")
    mode = cfg.get("repository_mode")
    targets = cfg.get("targets", [])
    roles: set[str] = set()
    roots: list[str] = []
    names: set[str] = set()
    for target in targets:
        if set(target) - {"name", "role", "roots", "enabled", "middleware", "stack_config", "propagate_headers"}:
            raise ValueError("unknown-middleware-target")
        name, role = target.get("name"), target.get("role")
        if not isinstance(name, str) or not name or name in names or role not in {"client", "server"}:
            raise ValueError("middleware-target")
        names.add(name); roles.add(role)
        target_roots = target.get("roots", [])
        if not target_roots or any(not safe_path(root) for root in target_roots):
            raise ValueError("middleware-root")
        roots.extend(target_roots)
        mw = target.get("middleware")
        if mw == "stack":
            if role != "server" or not safe_path(target.get("stack_config")) or target.get("stack_config") == ".":
                raise ValueError("middleware-stack")
        elif mw == "propagation-only":
            headers = target.get("propagate_headers", [])
            if role != "client" or not headers or len(headers) != len(set(headers)) or any(h != h.lower() for h in headers):
                raise ValueError("middleware-propagation")
        elif mw != "disabled":
            raise ValueError("middleware-mode")
    expected = {"server-only": {"server"}, "client-only": {"client"}, "hybrid": {"client", "server"}}
    if mode not in expected or roles != expected[mode]:
        raise ValueError("middleware-role-leak")
    if len(roots) != len(set(roots)) and cfg.get("allow_overlapping_roots") is not True:
        raise ValueError("middleware-overlap")
    if cfg.get("default_target") is not None and cfg["default_target"] not in names:
        raise ValueError("middleware-default")


def rate_limit(cfg: dict) -> None:
    if set(cfg) - {"schemaVersion", "layout", "defaultPolicyId", "client", "server", "policies"}:
        raise ValueError("unknown-rate-limit-root")
    if cfg.get("schemaVersion") != "ores.rate-limit.config.v1":
        raise ValueError("rate-limit-version")
    layout, client, server = cfg.get("layout"), cfg.get("client"), cfg.get("server")
    if layout == "client-only" and (client is None or server is not None): raise ValueError("rate-role-leak")
    if layout == "server-only" and (server is None or client is not None): raise ValueError("rate-role-leak")
    if layout == "combined" and (client is None or server is None): raise ValueError("rate-role-leak")
    if layout not in {"client-only", "server-only", "combined"}: raise ValueError("rate-layout")
    if client is not None and not safe_path(client.get("root")): raise ValueError("rate-client-root")
    if server is not None:
        if not safe_path(server.get("root")): raise ValueError("rate-server-root")
        env_name(server.get("keyHmacEnv"))
        if server.get("backend") == "redis": env_name(server.get("redisUrlEnv"))
        elif server.get("backend") == "local" and server.get("redisUrlEnv") is not None: raise ValueError("rate-local-redis")
        elif server.get("backend") not in {"local", "redis"}: raise ValueError("rate-backend")
    policies = cfg.get("policies", [])
    ids: set[str] = set()
    for p in policies:
        pid = p.get("policyId")
        if not isinstance(pid, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", pid) or pid in ids: raise ValueError("rate-policy-id")
        ids.add(pid)
        cap, cost, overshoot = p.get("capacity"), p.get("requestCost"), p.get("maxOvershoot")
        if not isinstance(cap, int) or not 1 <= cap <= 1_000_000_000: raise ValueError("rate-capacity")
        if not isinstance(cost, int) or not 1 <= cost <= cap: raise ValueError("rate-cost")
        if not isinstance(overshoot, int) or not 0 <= overshoot <= cap: raise ValueError("rate-overshoot")
        deny = p.get("denyCacheMode")
        if deny not in {"local-denials", "redis-denial-fanout", "redis-strict-blocks"}: raise ValueError("rate-deny-cache")
        if str(deny).startswith("redis-") and (server is None or server.get("backend") != "redis"): raise ValueError("rate-deny-backend")
        algo = p.get("algorithm")
        if algo == "token-bucket" and (p.get("windowMs") != 0 or p.get("refillTokens", 0) <= 0 or p.get("refillIntervalMs", 0) <= 0): raise ValueError("rate-token-bucket")
        if algo in {"fixed-window", "sliding-window", "gcra"} and (p.get("windowMs", 0) <= 0 or p.get("refillTokens") != 0 or p.get("refillIntervalMs") != 0): raise ValueError("rate-windowed")
        if algo not in {"token-bucket", "fixed-window", "sliding-window", "gcra"}: raise ValueError("rate-algorithm")
        if p.get("consistencyMode") == "strict" and (server is None or server.get("backend") != "redis" or p.get("backendFailureMode") != "fail-closed" or overshoot != 0): raise ValueError("rate-strict")
        if not re.fullmatch(r"v[1-9][0-9]*", str(p.get("keyVersion", ""))): raise ValueError("rate-key-version")
    default = cfg.get("defaultPolicyId")
    if not policies or default not in ids: raise ValueError("rate-default")
    if client is not None and client.get("exposePolicyMetadata") and not next(p for p in policies if p["policyId"] == default).get("clientVisible"): raise ValueError("rate-client-default")


def lru(cfg: dict) -> None:
    if set(cfg) - {"protocol", "namespace", "roles", "redis", "defaults", "roleOverrides", "caches"}: raise ValueError("unknown-lru-root")
    roles = cfg.get("roles", [])
    if cfg.get("protocol") != "ores.lru-config.v1" or not 1 <= len(roles) <= 2 or len(roles) != len(set(roles)) or set(roles) - {"client", "server"}: raise ValueError("lru-roles")
    redis = cfg.get("redis")
    if roles == ["client"] and redis is not None: raise ValueError("lru-client-redis")
    if redis is not None:
        env_name(redis.get("urlEnv"))
        lo, hi = redis.get("reconnectMinMs", 0), redis.get("reconnectMaxMs", 0)
        if not 100 <= lo <= 30_000 or not 1_000 <= hi <= 300_000 or lo > hi or not 1_000 <= redis.get("reconcileIntervalMs", 0) <= 180_000: raise ValueError("lru-bounds")
    defaults = cfg.get("defaults", {})
    if not 1 <= defaults.get("capacity", 0) <= 1_000_000: raise ValueError("lru-capacity")
    overrides = {item.get("role"): item for item in cfg.get("roleOverrides", [])}
    if len(overrides) != len(cfg.get("roleOverrides", [])) or set(overrides) - set(roles): raise ValueError("lru-overrides")
    seen: set[tuple[str, str]] = set()
    for cache in cfg.get("caches", []):
        role, name = cache.get("role"), cache.get("name")
        identity = (role, name)
        if role not in roles or not isinstance(name, str) or not name or identity in seen: raise ValueError("lru-cache-id")
        seen.add(identity)
        effective = dict(defaults); effective.update(overrides.get(role, {})); effective.update(cache)
        mode = effective.get("syncMode")
        if role == "client" and mode != "local_only": raise ValueError("lru-client-mode")
        if role == "server" and mode != "local_only" and redis is None: raise ValueError("lru-server-redis")


def shared_auth(cfg: dict, names: set[str]) -> None:
    if {".shared-auth.toml", ".auth-shared.toml"} <= names: raise ValueError("shared-auth-alias-collision")
    if cfg.get("schema_version") != 1: raise ValueError("shared-auth-version")
    compat = cfg.get("compatibility", {})
    if compat.get("repository") != "https://github.com/shared-auth/shared-auth-interfaces" or not re.fullmatch(r"[0-9a-f]{40}", str(compat.get("commit", ""))): raise ValueError("shared-auth-provenance")


def fanwaave(cfg: dict, exposed_cli_envs: set[str]) -> None:
    if cfg.get("version") != 1 or cfg.get("strict") is not True: raise ValueError("fanwaave-version")
    f2e = cfg.get("flags2env", {})
    if f2e != {"contract": ".cli-flags.toml", "require_audit": True, "precedence": "argv-over-env"}: raise ValueError("fanwaave-flags2env")
    mode = cfg.get("mode"); client = cfg.get("client", {}).get("enabled") is True; server = cfg.get("server", {}).get("enabled") is True
    if mode == "client" and (not client or server): raise ValueError("fanwaave-role")
    if mode == "server" and (not server or client): raise ValueError("fanwaave-role")
    if mode == "hybrid" and (not client or not server): raise ValueError("fanwaave-role")
    if mode not in {"client", "server", "hybrid"}: raise ValueError("fanwaave-role")
    names: set[str] = set(); keys: set[str] = set()
    for binding in cfg.get("env", []):
        name, key = binding.get("name"), binding.get("key")
        env_name(key)
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) or name in names or key in keys: raise ValueError("fanwaave-binding")
        names.add(name); keys.add(key)
        if binding.get("secret") is True and ("default" in binding or key in exposed_cli_envs): raise ValueError("fanwaave-secret")


MW_SERVER='''schema_version=1\nrepository_mode="server-only"\n[[targets]]\nname="server"\nrole="server"\nroots=["."]\nmiddleware="disabled"\n'''
MW_CLIENT='''schema_version=1\nrepository_mode="client-only"\ndefault_target="client"\n[[targets]]\nname="client"\nrole="client"\nroots=["."]\nmiddleware="propagation-only"\npropagate_headers=["traceparent","x-request-id"]\n'''
MW_HYBRID='''schema_version=1\nrepository_mode="hybrid"\nallow_overlapping_roots=true\n[[targets]]\nname="server"\nrole="server"\nroots=["."]\nmiddleware="disabled"\n[[targets]]\nname="client"\nrole="client"\nroots=["."]\nmiddleware="propagation-only"\npropagate_headers=["traceparent","x-request-id"]\n'''
POLICY='''[[policies]]\npolicyId="default"\nclientVisible=true\nalgorithm="token-bucket"\nidentityScope="anonymous-ip"\ncapacity=120\nwindowMs=0\nrefillTokens=120\nrefillIntervalMs=60000\nrequestCost=1\nenforcementMode="observe-only"\nconsistencyMode="advisory"\nbackendFailureMode="fail-open"\ndenyCacheMode="local-denials"\ndenyCacheCapacity=1024\nmaxOvershoot=120\nmaxBlockTtlMs=60000\nkeyVersion="v1"\npolicyVersion=1\n'''
RL_SERVER='''schemaVersion="ores.rate-limit.config.v1"\nlayout="server-only"\ndefaultPolicyId="default"\n[server]\nroot="."\nbackend="local"\nenforcementLayer="service"\nkeyHmacEnv="ORES_RL_HMAC_KEY"\n'''+POLICY
RL_CLIENT='''schemaVersion="ores.rate-limit.config.v1"\nlayout="client-only"\ndefaultPolicyId="default"\n[client]\nroot="."\nexposePolicyMetadata=true\n'''+POLICY
RL_HYBRID='''schemaVersion="ores.rate-limit.config.v1"\nlayout="combined"\ndefaultPolicyId="default"\n[client]\nroot="."\nexposePolicyMetadata=true\n[server]\nroot="."\nbackend="local"\nenforcementLayer="service"\nkeyHmacEnv="ORES_RL_HMAC_KEY"\n'''+POLICY
LRU_SERVER='''protocol="ores.lru-config.v1"\nnamespace="test"\nroles=["server"]\n[redis]\nurlEnv="REDIS_URL"\nkeyPrefix="ores:lru:test"\npubsubChannel="ores:lru:test:events"\nreconcileIntervalMs=180000\nreconnectMinMs=1000\nreconnectMaxMs=30000\n[defaults]\ncapacity=1024\nsyncMode="read_only"\noverflowMode="reject_and_reconcile"\nfailOpenOnStartup=false\n[[caches]]\nname="runtime-env"\nrole="server"\n'''
LRU_CLIENT='''protocol="ores.lru-config.v1"\nnamespace="test"\nroles=["client"]\n[defaults]\ncapacity=256\nsyncMode="local_only"\noverflowMode="evict_lru"\nfailOpenOnStartup=false\n[[caches]]\nname="runtime-env"\nrole="client"\n'''
LRU_HYBRID='''protocol="ores.lru-config.v1"\nnamespace="test"\nroles=["client","server"]\n[redis]\nurlEnv="REDIS_URL"\nkeyPrefix="ores:lru:test"\npubsubChannel="ores:lru:test:events"\nreconcileIntervalMs=180000\nreconnectMinMs=1000\nreconnectMaxMs=30000\n[defaults]\ncapacity=1024\nsyncMode="local_only"\noverflowMode="evict_lru"\nfailOpenOnStartup=false\n[[roleOverrides]]\nrole="server"\nsyncMode="read_only"\noverflowMode="reject_and_reconcile"\n[[caches]]\nname="runtime-env"\nrole="client"\ncapacity=256\nsyncMode="local_only"\n[[caches]]\nname="runtime-env"\nrole="server"\nsyncMode="read_only"\n'''
SHARED='''schema_version=1\n[compatibility]\nrepository="https://github.com/shared-auth/shared-auth-interfaces"\ncommit="52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"\n'''
CLI='''[env]\nload=false\n[parse]\nallow_unknown=false\n[flags.api]\nenv="FANWAAVE_API_BASE_URL"\ntype="string"\n[flags.bind]\nenv="FANWAAVE_BIND_ADDR"\ntype="string"\n'''
FAN='''version=1\nmode="hybrid"\nstrict=true\n[flags2env]\ncontract=".cli-flags.toml"\nrequire_audit=true\nprecedence="argv-over-env"\n[client]\nenabled=true\n[server]\nenabled=true\n[[env]]\nname="api"\nkey="FANWAAVE_API_BASE_URL"\nkind="url"\nrequired=true\nsecret=false\n[[env]]\nname="token"\nkey="FANWAAVE_AUTH_TOKEN"\nkind="string"\nrequired=true\nsecret=true\n[[env]]\nname="database"\nkey="DATABASE_URL"\nkind="url"\nrequired=true\nsecret=true\n'''


class RuntimeConfigSuite(unittest.TestCase):
    def test_pins_are_immutable(self):
        for repo, sha in AUTHORITY_PINS.values(): self.assertRegex(sha, r"^[0-9a-f]{40}$", repo)
        for name, sha in TJSV_PINS.items(): self.assertRegex(sha, r"^[0-9a-f]{40}$", name)

    def test_valid_role_matrix(self):
        for raw in (MW_SERVER, MW_CLIENT, MW_HYBRID): middleware(t(raw))
        for raw in (RL_SERVER, RL_CLIENT, RL_HYBRID): rate_limit(t(raw))
        for raw in (LRU_SERVER, LRU_CLIENT, LRU_HYBRID): lru(t(raw))
        shared_auth(t(SHARED), {".auth-shared.toml"})
        fanwaave(t(FAN), cli_envs(t(CLI)))

    def test_invalid_deny_cache_template_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "rate-deny-cache"): rate_limit(t(RL_SERVER.replace('denyCacheMode="local-denials"','denyCacheMode="disabled"')))

    def test_strict_local_rate_limit_is_rejected(self):
        bad=RL_SERVER.replace('consistencyMode="advisory"','consistencyMode="strict"').replace('backendFailureMode="fail-open"','backendFailureMode="fail-closed"').replace('maxOvershoot=120','maxOvershoot=0')
        with self.assertRaisesRegex(ValueError, "rate-strict"): rate_limit(t(bad))

    def test_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "rate-client-root"): rate_limit(t(RL_CLIENT.replace('root="."','root="../client"')))

    def test_literal_redis_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "env-name"): lru(t(LRU_SERVER.replace('urlEnv="REDIS_URL"','urlEnv="redis://user:pass@cache"')))

    def test_client_redis_leak_is_rejected(self):
        bad=LRU_CLIENT+'\n[redis]\nurlEnv="REDIS_URL"\nkeyPrefix="x"\npubsubChannel="x"\nreconcileIntervalMs=180000\nreconnectMinMs=1000\nreconnectMaxMs=30000\n'
        with self.assertRaisesRegex(ValueError, "lru-client-redis"): lru(t(bad))

    def test_dual_shared_auth_alias_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "alias-collision"): shared_auth(t(SHARED), {".shared-auth.toml", ".auth-shared.toml"})

    def test_secret_cli_surface_is_rejected(self):
        bad=CLI+'\n[flags.database]\nenv="DATABASE_URL"\ntype="string"\n'
        with self.assertRaisesRegex(ValueError, "secret-cli"): cli_envs(t(bad))

    def test_fanwaave_secret_default_is_rejected(self):
        bad=FAN.replace('key="DATABASE_URL"\nkind="url"\nrequired=true\nsecret=true','key="DATABASE_URL"\nkind="url"\nrequired=true\nsecret=true\ndefault="postgres://user:pass@db"')
        with self.assertRaisesRegex(ValueError, "fanwaave-secret"): fanwaave(t(bad), cli_envs(t(CLI)))

    def test_same_root_hybrid_requires_explicit_overlap(self):
        with self.assertRaisesRegex(ValueError, "middleware-overlap"): middleware(t(MW_HYBRID.replace('allow_overlapping_roots=true\n','')))

    def test_unknown_fields_fail_closed(self):
        bad=MW_SERVER.replace('repository_mode="server-only"','repository_mode="server-only"\nshadow_parser=true')
        with self.assertRaisesRegex(ValueError, "unknown-middleware-root"): middleware(t(bad))


if __name__ == "__main__": unittest.main(verbosity=2)
