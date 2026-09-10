#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any, Callable

ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
BINDING_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
ROOT_FILES = (
    ".cli-flags.toml",
    ".ores-mw.toml",
    ".ores-rl.toml",
    ".ores-lru.toml",
    ".shared-auth.toml",
)
SHARED_AUTH_REPOSITORY = "https://github.com/shared-auth/shared-auth-interfaces"
SHARED_AUTH_COMMIT = "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"
SNAPSHOT_BLOBS = {
    "upstream-snapshots/rate-limit/main.tsp": "906cc7c080aa3b30ca042854433bdec88d6ba487",
    "upstream-snapshots/rate-limit/authored.schema.json": "778623a48694eaa5270ce3617e8f203a25c879ef",
    "upstream-snapshots/rate-limit/mapping.json": "d0cdfcc3b57a8bda25eddc99d88d31b618c6f7cc",
    "upstream-snapshots/lru/main.tsp": "6b9d232ca1b89096ddfcd617b2670b52a3ac2f37",
    "upstream-snapshots/lru/authored.schema.json": "547fbb0763656c70b0fe23ac57b5dc2e62ac93ee",
    "upstream-snapshots/shared-auth/main.tsp": "4fa968339bf99e255fecf75ddbdbde6e1e309cdd",
    "upstream-snapshots/shared-auth/authored.schema.json": "bed2e582e458e7023118ac5b3af583d2c0767e3e",
}


class ValidationError(ValueError):
    pass


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValidationError(message)


def bounded_toml(path: Path) -> dict[str, Any]:
    need(path.is_file() and not path.is_symlink(), f"regular root file required: {path.name}")
    data = path.read_bytes()
    need(len(data) <= 256 * 1024, f"oversized TOML: {path.name}")
    try:
        value = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"invalid TOML: {path.name}") from exc
    need(isinstance(value, dict), f"object TOML required: {path.name}")
    return value


def git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def validate_snapshots(harness_root: Path) -> dict[str, str]:
    actual: dict[str, str] = {}
    for relative, expected in SNAPSHOT_BLOBS.items():
        path = harness_root / relative
        need(path.is_file() and not path.is_symlink(), f"snapshot missing: {relative}")
        received = git_blob_sha(path)
        need(received == expected, f"snapshot identity drift: {relative}")
        actual[relative] = received
    return actual


def validate_cli(value: dict[str, Any]) -> set[str]:
    need(value.get("parse", {}).get("allow_unknown") is False, "CLI unknown flags must fail closed")
    flags = value.get("flags", {})
    need(isinstance(flags, dict), "CLI flags table required")
    envs: set[str] = set()
    for name, spec in flags.items():
        need(isinstance(spec, dict), f"CLI flag object required: {name}")
        key = spec.get("env")
        if key is None:
            continue
        need(isinstance(key, str) and ENV_KEY.fullmatch(key) is not None, f"invalid CLI env key: {name}")
        need(key not in envs, f"duplicate CLI env key: {key}")
        envs.add(key)
    return envs


def _root_parts(value: str) -> tuple[str, ...]:
    return () if value == "." else tuple(value.split("/"))


def _overlap(a: str, b: str) -> bool:
    left, right = _root_parts(a), _root_parts(b)
    width = min(len(left), len(right))
    return left[:width] == right[:width]


def validate_middleware(value: dict[str, Any], cli_envs: set[str]) -> set[str]:
    allowed = {
        "schema_version", "repository_mode", "allow_overlapping_roots",
        "default_target", "flags2env", "env", "targets",
    }
    need(not (set(value) - allowed), "unknown middleware top-level key")
    need(value.get("schema_version") == 1, "middleware schema version")
    mode = value.get("repository_mode")
    need(mode in {"server-only", "client-only", "hybrid"}, "middleware repository mode")
    envs = value.get("env", [])
    need(isinstance(envs, list) and len(envs) <= 128, "middleware env inventory")
    if envs:
        flags = value.get("flags2env")
        need(isinstance(flags, dict), "flags2env block required with env declarations")
        need(flags == {
            "contract": ".cli-flags.toml",
            "require_audit": True,
            "precedence": "argv-over-env",
        }, "noncanonical flags2env contract")
    names: set[str] = set()
    keys: set[str] = set()
    secrets: set[str] = set()
    for entry in envs:
        need(isinstance(entry, dict), "middleware env entry")
        name, key = entry.get("name"), entry.get("key")
        need(isinstance(name, str) and BINDING_NAME.fullmatch(name) is not None, "invalid middleware binding name")
        need(isinstance(key, str) and ENV_KEY.fullmatch(key) is not None, "invalid middleware env key")
        need(name not in names and key not in keys, "duplicate middleware env identity")
        names.add(name)
        keys.add(key)
        need(entry.get("kind") in {"string", "bool", "integer", "double", "json", "url"}, "invalid middleware env kind")
        need(type(entry.get("required")) is bool and type(entry.get("secret")) is bool, "middleware env booleans")
        if entry["secret"]:
            need("default" not in entry, "secret middleware binding may not have a default")
            need(key not in cli_envs, "secret middleware binding may not be exposed as a CLI flag")
            secrets.add(key)
    targets = value.get("targets")
    need(isinstance(targets, list) and targets, "middleware target required")
    enabled = [entry for entry in targets if entry.get("enabled", True)]
    need(enabled, "enabled middleware target required")
    roles = {entry.get("role") for entry in enabled}
    expected = {"server"} if mode == "server-only" else {"client"} if mode == "client-only" else {"server", "client"}
    need(roles == expected, "middleware repository/role mismatch")
    allow_overlap = value.get("allow_overlapping_roots", False)
    need(type(allow_overlap) is bool, "middleware overlap toggle")
    all_roots: list[tuple[str, str]] = []
    for entry in enabled:
        role = entry.get("role")
        middleware = entry.get("middleware")
        roots = entry.get("roots")
        need(role in {"server", "client"}, "middleware target role")
        need(middleware in {"stack", "propagation-only", "disabled"}, "middleware target mode")
        need(isinstance(roots, list) and roots and all(isinstance(v, str) and v for v in roots), "middleware roots")
        if middleware == "stack":
            need(role == "server" and isinstance(entry.get("stack_config"), str), "server stack requirements")
        elif middleware == "propagation-only":
            headers = entry.get("propagate_headers")
            need(isinstance(headers, list) and headers, "client propagation headers required")
        for root in roots:
            need(root == "." or (not root.startswith("/") and ".." not in root.split("/") and "\\" not in root), "unsafe middleware root")
            all_roots.append((entry.get("name", ""), root))
    for index, (left_name, left) in enumerate(all_roots):
        for right_name, right in all_roots[index + 1:]:
            if left_name != right_name and _overlap(left, right):
                need(allow_overlap, "overlapping middleware roots require explicit opt-in")
    default = value.get("default_target")
    if default is not None:
        need(any(entry.get("name") == default and entry.get("enabled", True) for entry in targets), "middleware default target")
    return secrets


def validate_rate_limit(value: dict[str, Any]) -> tuple[str, str]:
    need(value.get("schemaVersion") == "ores.rate-limit.config.v1", "rate-limit schema")
    need(value.get("layout") == "server-only", "test rate-limit layout must be server-only")
    server = value.get("server")
    need(isinstance(server, dict), "rate-limit server block")
    need(server.get("root") == "." and server.get("backend") == "redis" and server.get("enforcementLayer") == "service", "rate-limit server profile")
    redis_env, hmac_env = server.get("redisUrlEnv"), server.get("keyHmacEnv")
    need(isinstance(redis_env, str) and ENV_KEY.fullmatch(redis_env) is not None, "rate-limit Redis env name")
    need(isinstance(hmac_env, str) and ENV_KEY.fullmatch(hmac_env) is not None, "rate-limit HMAC env name")
    policies = value.get("policies")
    need(isinstance(policies, list) and policies, "rate-limit policies")
    ids = [policy.get("policyId") for policy in policies]
    need(len(ids) == len(set(ids)) and value.get("defaultPolicyId") in ids, "rate-limit default policy identity")
    for policy in policies:
        need(policy.get("algorithm") == "token-bucket", "test rate-limit algorithm")
        need(policy.get("capacity", 0) > 0 and policy.get("requestCost", 0) > 0, "rate-limit capacity/cost")
        need(policy.get("refillTokens", 0) > 0 and policy.get("refillIntervalMs", 0) > 0, "rate-limit refill")
        need(policy.get("windowMs") == 0, "token-bucket window must be zero in hardened profile")
        need(policy.get("enforcementMode") == "enforce", "rate-limit must enforce")
        need(policy.get("consistencyMode") == "strict", "rate-limit must be strict")
        need(policy.get("backendFailureMode") == "fail-closed", "rate-limit must fail closed")
        need(policy.get("denyCacheMode") == "redis-strict-blocks", "rate-limit denial fanout")
        need(policy.get("maxOvershoot") == 0, "rate-limit overshoot must be zero")
        need(policy.get("maxBlockTtlMs", 0) > 0 and policy.get("policyVersion", 0) >= 1, "rate-limit version/TTL")
    return redis_env, hmac_env


def _resolve_lru(value: dict[str, Any], role: str, cache: dict[str, Any]) -> dict[str, Any]:
    result = dict(value["defaults"])
    for override in value.get("roleOverrides", []):
        if override.get("role") == role:
            result.update({k: v for k, v in override.items() if k != "role"})
    result.update({k: v for k, v in cache.items() if k not in {"name", "role"}})
    return result


def validate_lru(value: dict[str, Any]) -> str | None:
    need(value.get("protocol") == "ores.lru-config.v1", "LRU protocol")
    roles = value.get("roles")
    need(isinstance(roles, list) and 1 <= len(roles) <= 2 and len(roles) == len(set(roles)), "LRU roles")
    need(set(roles) <= {"client", "server"}, "LRU role value")
    defaults = value.get("defaults")
    need(isinstance(defaults, dict), "LRU defaults")
    need(1 <= defaults.get("capacity", 0) <= 1_000_000, "LRU capacity")
    need(defaults.get("failOpenOnStartup") is False, "LRU startup must fail closed")
    redis = value.get("redis")
    if redis is not None:
        need("server" in roles, "client-only LRU must not receive Redis config")
        url_env = redis.get("urlEnv")
        need(isinstance(url_env, str) and ENV_KEY.fullmatch(url_env) is not None, "LRU Redis env name")
        need(1000 <= redis.get("reconcileIntervalMs", 0) <= 180000, "LRU reconciliation bound")
        need(100 <= redis.get("reconnectMinMs", 0) <= 30000, "LRU reconnect minimum")
        need(1000 <= redis.get("reconnectMaxMs", 0) <= 300000, "LRU reconnect maximum")
        need(redis["reconnectMinMs"] <= redis["reconnectMaxMs"], "LRU reconnect ordering")
    overrides = value.get("roleOverrides", [])
    override_roles = [entry.get("role") for entry in overrides]
    need(len(override_roles) == len(set(override_roles)), "duplicate LRU role override")
    need(set(override_roles) <= set(roles), "LRU override undeclared role")
    caches = value.get("caches")
    need(isinstance(caches, list) and caches, "LRU caches")
    seen: set[tuple[str, str]] = set()
    for cache in caches:
        role, name = cache.get("role"), cache.get("name")
        need(role in roles and isinstance(name, str) and name, "LRU cache identity")
        identity = (role, name)
        need(identity not in seen, "duplicate LRU cache identity")
        seen.add(identity)
        effective = _resolve_lru(value, role, cache)
        need(1 <= effective.get("capacity", 0) <= 1_000_000, "resolved LRU capacity")
        need(effective.get("failOpenOnStartup") is False, "resolved LRU startup must fail closed")
        if role == "client":
            need(effective.get("syncMode") == "local_only", "client LRU must remain local_only")
        elif effective.get("syncMode") != "local_only":
            need(redis is not None, "remote server LRU requires Redis")
    return redis.get("urlEnv") if isinstance(redis, dict) else None


def validate_shared_auth(value: dict[str, Any], alias_present: bool) -> None:
    need(not alias_present, "canonical and legacy Shared Auth filenames may not coexist")
    need(value.get("schema_version") == 1, "Shared Auth schema version")
    compatibility = value.get("compatibility")
    need(isinstance(compatibility, dict), "Shared Auth compatibility")
    need(compatibility.get("repository") == SHARED_AUTH_REPOSITORY, "Shared Auth repository provenance")
    need(compatibility.get("commit") == SHARED_AUTH_COMMIT and "range" not in compatibility, "Shared Auth exact revision provenance")


def expect_reject(label: str, operation: Callable[[], Any]) -> str:
    try:
        operation()
    except ValidationError:
        return label
    raise ValidationError(f"adversarial case unexpectedly accepted: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--receipt", default=".toml-config-evidence/receipt.json")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    harness_root = Path(__file__).resolve().parents[1]

    values = {name: bounded_toml(repo_root / name) for name in ROOT_FILES}
    cli_envs = validate_cli(values[".cli-flags.toml"])
    middleware_secrets = validate_middleware(values[".ores-mw.toml"], cli_envs)
    rl_redis, rl_hmac = validate_rate_limit(values[".ores-rl.toml"])
    lru_redis = validate_lru(values[".ores-lru.toml"])
    validate_shared_auth(values[".shared-auth.toml"], (repo_root / ".auth-shared.toml").exists())

    need(rl_redis == lru_redis == "REDIS_URL", "Redis env reference must converge")
    need(rl_hmac == "ORES_RL_HMAC_KEY", "rate-limit HMAC env reference")
    need({"REDIS_URL", "ORES_RL_HMAC_KEY"} <= middleware_secrets, "middleware secret inventory must cover shared runtime env keys")
    need(not ({"REDIS_URL", "ORES_RL_HMAC_KEY"} & cli_envs), "secret runtime env keys may not become CLI flags")

    adversarial: list[str] = []

    bad_mw = copy.deepcopy(values[".ores-mw.toml"])
    bad_mw["env"][0]["default"] = "synthetic-never-a-real-secret"
    adversarial.append(expect_reject("middleware-secret-default", lambda: validate_middleware(bad_mw, cli_envs)))

    bad_cli = set(cli_envs)
    bad_cli.add("REDIS_URL")
    adversarial.append(expect_reject("middleware-secret-cli-exposure", lambda: validate_middleware(values[".ores-mw.toml"], bad_cli)))

    hybrid_mw = copy.deepcopy(values[".ores-mw.toml"])
    hybrid_mw["repository_mode"] = "hybrid"
    hybrid_mw["allow_overlapping_roots"] = True
    hybrid_mw["default_target"] = "server"
    hybrid_mw["targets"] = [
        {"name": "server", "role": "server", "roots": ["."], "middleware": "disabled"},
        {"name": "client", "role": "client", "roots": ["."], "middleware": "propagation-only", "propagate_headers": ["traceparent", "x-request-id"]},
    ]
    validate_middleware(hybrid_mw, cli_envs)
    bad_hybrid_mw = copy.deepcopy(hybrid_mw)
    bad_hybrid_mw["allow_overlapping_roots"] = False
    adversarial.append(expect_reject("middleware-hybrid-overlap-without-opt-in", lambda: validate_middleware(bad_hybrid_mw, cli_envs)))

    bad_rl = copy.deepcopy(values[".ores-rl.toml"])
    bad_rl["policies"][0]["backendFailureMode"] = "fail-open"
    adversarial.append(expect_reject("rate-limit-fail-open", lambda: validate_rate_limit(bad_rl)))
    bad_rl = copy.deepcopy(values[".ores-rl.toml"])
    bad_rl["policies"][0]["maxOvershoot"] = 1
    adversarial.append(expect_reject("rate-limit-positive-overshoot", lambda: validate_rate_limit(bad_rl)))

    hybrid_lru = copy.deepcopy(values[".ores-lru.toml"])
    hybrid_lru["roles"] = ["client", "server"]
    hybrid_lru["defaults"]["syncMode"] = "local_only"
    hybrid_lru["roleOverrides"] = [{"role": "server", "syncMode": "read_only", "overflowMode": "reject_and_reconcile"}]
    hybrid_lru["caches"] = [
        {"name": "runtime-env", "role": "client", "capacity": 64, "syncMode": "local_only"},
        {"name": "runtime-env", "role": "server", "capacity": 128, "syncMode": "read_only"},
    ]
    validate_lru(hybrid_lru)
    bad_lru = copy.deepcopy(hybrid_lru)
    bad_lru["caches"].append(copy.deepcopy(bad_lru["caches"][1]))
    adversarial.append(expect_reject("lru-duplicate-role-cache", lambda: validate_lru(bad_lru)))
    bad_lru = copy.deepcopy(hybrid_lru)
    bad_lru["caches"][0]["syncMode"] = "read_only"
    adversarial.append(expect_reject("lru-client-remote-sync", lambda: validate_lru(bad_lru)))

    adversarial.append(expect_reject("shared-auth-dual-filename", lambda: validate_shared_auth(values[".shared-auth.toml"], True)))

    snapshots = validate_snapshots(harness_root)
    file_digests = {
        name: hashlib.sha256((repo_root / name).read_bytes()).hexdigest()
        for name in ROOT_FILES
    }
    receipt = {
        "schema": "ores.toml-config-convergence.receipt/v1",
        "status": "passed",
        "files": file_digests,
        "snapshotGitBlobs": snapshots,
        "contracts": {
            "middleware": "0ba59b36777345989788f8cd4687c10735546c3d",
            "rateLimit": "241353d0f5269450690d9646be03db2aba59a2ae",
            "lru": "4474d240b38a4fe1dd24f01dcd2e9ab7a4c34b27",
            "sharedAuth": SHARED_AUTH_COMMIT,
            "tjsv": "4473504c4c9d2831d825919f70c03994d8ce01d2",
        },
        "adversarialCases": adversarial,
        "adversarialCount": len(adversarial),
        "hybridMiddlewareAccepted": True,
        "hybridLruAccepted": True,
    }
    destination = repo_root / args.receipt
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "adversarialCount": len(adversarial), "receipt": str(destination.relative_to(repo_root))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
