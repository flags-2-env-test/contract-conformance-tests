#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from verify_toml_config_convergence import (
    BINDING_NAME,
    ENV_KEY,
    ValidationError,
    _overlap,
    bounded_toml,
    expect_reject,
    need,
    validate_cli,
    validate_lru,
    validate_middleware,
    validate_shared_auth,
    validate_snapshots,
)

AUTH_CANONICAL = ".shared-auth.toml"
AUTH_ALIAS = ".auth-shared.toml"
STATIC_FILES = (
    ".cli-flags.toml",
    ".ores-mw.toml",
    ".ores-rl.toml",
    ".ores-lru.toml",
    ".fanwaave-cfg.toml",
    ".ores-rpc.toml",
)
RPC_BINDING = re.compile(r"^[a-z][A-Za-z0-9]{0,63}$")
RPC_TARGET = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


def validate_rate_limit(value: dict[str, Any]) -> tuple[str | None, str | None]:
    allowed = {"schemaVersion", "layout", "defaultPolicyId", "client", "server", "policies"}
    need(not (set(value) - allowed), "unknown rate-limit top-level key")
    need(value.get("schemaVersion") == "ores.rate-limit.config.v1", "rate-limit schema")
    layout = value.get("layout")
    need(layout in {"client-only", "server-only", "combined"}, "rate-limit layout")
    client, server = value.get("client"), value.get("server")
    if layout == "client-only":
        need(isinstance(client, dict) and server is None, "client-only rate-limit role projection")
    elif layout == "server-only":
        need(isinstance(server, dict) and client is None, "server-only rate-limit role projection")
    else:
        need(isinstance(client, dict) and isinstance(server, dict), "combined rate-limit role projection")
    if client is not None:
        need(client.get("root") == ".", "test rate-limit client root")
        need(type(client.get("exposePolicyMetadata")) is bool, "rate-limit client metadata toggle")
    redis_env: str | None = None
    hmac_env: str | None = None
    if server is not None:
        need(server.get("root") == ".", "test rate-limit server root")
        need(server.get("backend") in {"local", "redis"}, "rate-limit backend")
        need(server.get("enforcementLayer") in {"edge", "load-balancer", "service", "authentication", "data-store"}, "rate-limit enforcement layer")
        hmac_env = server.get("keyHmacEnv")
        need(isinstance(hmac_env, str) and ENV_KEY.fullmatch(hmac_env) is not None, "rate-limit HMAC env name")
        redis_env = server.get("redisUrlEnv")
        if server.get("backend") == "redis":
            need(isinstance(redis_env, str) and ENV_KEY.fullmatch(redis_env) is not None, "rate-limit Redis env name")
        else:
            need(redis_env is None, "local rate-limit backend may not declare Redis")
    policies = value.get("policies")
    need(isinstance(policies, list) and policies, "rate-limit policies")
    ids: list[str] = []
    for policy in policies:
        pid = policy.get("policyId")
        need(isinstance(pid, str) and RPC_TARGET.fullmatch(pid) is not None, "rate-limit policy id")
        ids.append(pid)
        need(policy.get("algorithm") in {"token-bucket", "fixed-window", "sliding-window", "gcra"}, "rate-limit algorithm")
        need(isinstance(policy.get("capacity"), int) and policy["capacity"] > 0, "rate-limit capacity")
        need(isinstance(policy.get("requestCost"), int) and 0 < policy["requestCost"] <= policy["capacity"], "rate-limit request cost")
        need(isinstance(policy.get("maxOvershoot"), int) and 0 <= policy["maxOvershoot"] <= policy["capacity"], "rate-limit overshoot")
        if policy["algorithm"] == "token-bucket":
            need(policy.get("windowMs") == 0, "token-bucket window must be zero")
            need(policy.get("refillTokens", 0) > 0 and policy.get("refillIntervalMs", 0) > 0, "token-bucket refill")
        else:
            need(policy.get("windowMs", 0) > 0, "windowed rate-limit window")
        deny_mode = policy.get("denyCacheMode")
        need(deny_mode in {"local-denials", "redis-denial-fanout", "redis-strict-blocks"}, "rate-limit deny cache mode")
        if str(deny_mode).startswith("redis-"):
            need(isinstance(server, dict) and server.get("backend") == "redis", "Redis denial cache requires Redis server backend")
        if policy.get("consistencyMode") == "strict":
            need(isinstance(server, dict) and server.get("backend") == "redis", "strict rate-limit requires Redis server")
            need(policy.get("backendFailureMode") == "fail-closed", "strict rate-limit must fail closed")
            need(policy.get("maxOvershoot") == 0, "strict rate-limit overshoot must be zero")
        need(policy.get("maxBlockTtlMs", 0) > 0 and policy.get("policyVersion", 0) >= 1, "rate-limit version/TTL")
    need(len(ids) == len(set(ids)), "duplicate rate-limit policy id")
    need(value.get("defaultPolicyId") in ids, "rate-limit default policy identity")
    return redis_env, hmac_env


def validate_fanwaave(value: dict[str, Any], cli_envs: set[str]) -> set[str]:
    allowed = {"version", "mode", "strict", "flags2env", "env", "client", "server"}
    need(not (set(value) - allowed), "unknown Fanwaave top-level key")
    need(value.get("version") == 1 and value.get("strict") is True, "Fanwaave version/strict mode")
    mode = value.get("mode")
    need(mode in {"client", "server", "hybrid"}, "Fanwaave mode")
    need(value.get("flags2env") == {
        "contract": ".cli-flags.toml",
        "require_audit": True,
        "precedence": "argv-over-env",
    }, "Fanwaave must use canonical flags-2-env contract")
    env = value.get("env")
    need(isinstance(env, list) and len(env) <= 128, "Fanwaave env inventory")
    names: set[str] = set()
    keys: set[str] = set()
    secrets: set[str] = set()
    for binding in env:
        need(isinstance(binding, dict), "Fanwaave env binding")
        name, key = binding.get("name"), binding.get("key")
        need(isinstance(name, str) and BINDING_NAME.fullmatch(name) is not None, "Fanwaave binding name")
        need(isinstance(key, str) and ENV_KEY.fullmatch(key) is not None, "Fanwaave env key")
        need(name not in names and key not in keys, "duplicate Fanwaave env identity")
        names.add(name); keys.add(key)
        need(binding.get("kind") in {"string", "bool", "integer", "double", "json", "url"}, "Fanwaave env kind")
        need(type(binding.get("required")) is bool and type(binding.get("secret")) is bool, "Fanwaave env policy booleans")
        if binding["secret"]:
            need("default" not in binding, "Fanwaave secret binding may not have a default")
            need(key not in cli_envs, "Fanwaave secret binding may not be exposed as CLI")
            secrets.add(key)
        elif "default" in binding:
            need(isinstance(binding["default"], str), "Fanwaave default must be a string")
    client, server = value.get("client"), value.get("server")
    client_enabled = isinstance(client, dict) and client.get("enabled") is True
    server_enabled = isinstance(server, dict) and server.get("enabled") is True
    expected = {
        "client": (True, False),
        "server": (False, True),
        "hybrid": (True, True),
    }[mode]
    need((client_enabled, server_enabled) == expected, "Fanwaave mode/role mismatch")
    for section in (client, server):
        if not isinstance(section, dict):
            continue
        for key, ref in section.items():
            if key.endswith("_binding"):
                need(isinstance(ref, str) and ref in names, f"unresolved Fanwaave binding: {key}")
    return secrets


def safe_root(root: Any) -> bool:
    return isinstance(root, str) and bool(root) and (
        root == "." or (not root.startswith("/") and "\\" not in root and ".." not in root.split("/"))
    )


def validate_rpc(value: dict[str, Any], cli_envs: set[str]) -> set[str]:
    allowed = {"schemaVersion", "repositoryMode", "strict", "flagsContract", "defaultTarget", "allowOverlappingRoots", "env", "targets"}
    need(not (set(value) - allowed), "unknown RPC top-level key")
    need(value.get("schemaVersion") == "ores.rpc.config.v1" and value.get("strict") is True, "RPC schema/strict mode")
    mode = value.get("repositoryMode")
    need(mode in {"server-only", "client-only", "hybrid"}, "RPC repository mode")
    flags_contract = value.get("flagsContract")
    if flags_contract is not None:
        need(flags_contract == ".cli-flags.toml", "RPC must use canonical flags-2-env contract")
    env = value.get("env", [])
    need(isinstance(env, list) and len(env) <= 128, "RPC env inventory")
    names: set[str] = set(); keys: set[str] = set(); secrets: set[str] = set()
    for binding in env:
        need(isinstance(binding, dict), "RPC env binding")
        name, key = binding.get("name"), binding.get("env")
        need(isinstance(name, str) and RPC_BINDING.fullmatch(name) is not None, "RPC env binding name")
        need(isinstance(key, str) and ENV_KEY.fullmatch(key) is not None, "RPC env key")
        need(name not in names and key not in keys, "duplicate RPC env identity")
        names.add(name); keys.add(key)
        need(binding.get("valueType") in {"string", "integer", "boolean"}, "RPC env value type")
        need(type(binding.get("required")) is bool and type(binding.get("secret")) is bool and type(binding.get("allowArgv")) is bool, "RPC env policy booleans")
        if binding["secret"]:
            need(binding["allowArgv"] is False, "RPC secret env may not be argv-exposed")
            need(key not in cli_envs, "RPC secret env may not be a CLI flag")
            secrets.add(key)
        elif binding["allowArgv"]:
            need(flags_contract == ".cli-flags.toml", "argv-enabled RPC env requires flags contract")
            need(key in cli_envs, "argv-enabled RPC env must exist in .cli-flags.toml")
    targets = value.get("targets")
    need(isinstance(targets, list) and targets, "RPC target required")
    roles = {target.get("role") for target in targets}
    expected = {"server-only": {"server"}, "client-only": {"client"}, "hybrid": {"server", "client"}}[mode]
    need(roles == expected, "RPC repository/role mismatch")
    overlap_allowed = value.get("allowOverlappingRoots", False)
    need(type(overlap_allowed) is bool, "RPC overlap toggle")
    roots: list[tuple[str, str]] = []
    target_names: set[str] = set()
    for target in targets:
        need(isinstance(target, dict), "RPC target")
        target_name = target.get("name")
        need(isinstance(target_name, str) and RPC_TARGET.fullmatch(target_name) is not None and target_name not in target_names, "RPC target identity")
        target_names.add(target_name)
        role = target.get("role")
        target_roots = target.get("roots")
        need(role in {"server", "client"}, "RPC target role")
        need(isinstance(target_roots, list) and target_roots and all(safe_root(root) for root in target_roots), "RPC target roots")
        need(target.get("rpcVersion") in {"v1", "v2"}, "RPC version")
        transports = target.get("transports")
        need(isinstance(transports, list) and transports and set(transports) <= {"http", "tcp", "websocket", "nats"}, "RPC transports")
        framing = target.get("framing")
        need(framing in {"json", "ndjson", "length-prefixed", "frame"}, "RPC framing")
        if target["rpcVersion"] == "v2":
            need(framing == "frame" and "nats" not in transports, "RPC v2 framing/transport policy")
        if "tcp" in transports:
            need(framing in {"length-prefixed", "frame"}, "TCP RPC requires framed transport")
        endpoint = target.get("endpointEnv")
        if endpoint is not None:
            need(isinstance(endpoint, str) and ENV_KEY.fullmatch(endpoint) is not None, "RPC endpoint env")
        for root in target_roots:
            roots.append((target_name, root))
    for index, (left_name, left_root) in enumerate(roots):
        for right_name, right_root in roots[index + 1:]:
            if left_name != right_name and _overlap(left_root, right_root):
                need(overlap_allowed, "overlapping RPC roots require explicit opt-in")
    default = value.get("defaultTarget")
    if default is not None:
        need(default in target_names, "RPC default target")
    return secrets


def select_shared_auth(repo_root: Path) -> tuple[str, dict[str, Any]]:
    canonical = repo_root / AUTH_CANONICAL
    alias = repo_root / AUTH_ALIAS
    need(canonical.exists() != alias.exists(), "exactly one Shared Auth project config filename is required")
    name = AUTH_CANONICAL if canonical.exists() else AUTH_ALIAS
    value = bounded_toml(repo_root / name)
    validate_shared_auth(value, False)
    return name, value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--receipt", default=".toml-config-evidence/receipt.json")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    harness_root = Path(__file__).resolve().parents[1]

    values = {name: bounded_toml(repo_root / name) for name in STATIC_FILES}
    auth_name, auth_value = select_shared_auth(repo_root)
    cli_envs = validate_cli(values[".cli-flags.toml"])
    mw_secrets = validate_middleware(values[".ores-mw.toml"], cli_envs)
    rl_redis, rl_hmac = validate_rate_limit(values[".ores-rl.toml"])
    lru_redis = validate_lru(values[".ores-lru.toml"])
    fanwaave_secrets = validate_fanwaave(values[".fanwaave-cfg.toml"], cli_envs)
    rpc_secrets = validate_rpc(values[".ores-rpc.toml"], cli_envs)
    validate_shared_auth(auth_value, False)

    need(rl_redis == lru_redis == "REDIS_URL", "Redis env reference must converge")
    need(rl_hmac == "ORES_RL_HMAC_KEY", "rate-limit HMAC env reference must converge")
    need({"REDIS_URL", "ORES_RL_HMAC_KEY"} <= mw_secrets, "middleware secret inventory must cover rate-limit/LRU runtime keys")
    need({"REDIS_URL", "ORES_RL_HMAC_KEY"} <= fanwaave_secrets, "Fanwaave env inventory must preserve shared secret boundaries")
    need("ORES_RPC_AUTH_TOKEN" in rpc_secrets, "RPC secret env boundary")
    all_secrets = mw_secrets | fanwaave_secrets | rpc_secrets | {rl_hmac or ""}
    need(not (all_secrets & cli_envs), "secret env keys may not become CLI flags")

    adversarial: list[str] = []

    bad_mw = copy.deepcopy(values[".ores-mw.toml"]); bad_mw["env"][0]["default"] = "synthetic-not-a-secret"
    adversarial.append(expect_reject("middleware-secret-default", lambda: validate_middleware(bad_mw, cli_envs)))
    bad_cli = set(cli_envs); bad_cli.add("REDIS_URL")
    adversarial.append(expect_reject("middleware-secret-cli-exposure", lambda: validate_middleware(values[".ores-mw.toml"], bad_cli)))

    hybrid_mw = copy.deepcopy(values[".ores-mw.toml"])
    hybrid_mw["repository_mode"] = "hybrid"; hybrid_mw["allow_overlapping_roots"] = True; hybrid_mw["default_target"] = "server"
    hybrid_mw["targets"] = [
        {"name": "server", "role": "server", "roots": ["."], "middleware": "disabled"},
        {"name": "client", "role": "client", "roots": ["."], "middleware": "propagation-only", "propagate_headers": ["traceparent", "x-request-id"]},
    ]
    validate_middleware(hybrid_mw, cli_envs)
    bad_hybrid_mw = copy.deepcopy(hybrid_mw); bad_hybrid_mw["allow_overlapping_roots"] = False
    adversarial.append(expect_reject("middleware-hybrid-overlap-without-opt-in", lambda: validate_middleware(bad_hybrid_mw, cli_envs)))

    bad_rl = copy.deepcopy(values[".ores-rl.toml"]); bad_rl["policies"][0]["backendFailureMode"] = "fail-open"
    adversarial.append(expect_reject("rate-limit-fail-open", lambda: validate_rate_limit(bad_rl)))
    bad_rl = copy.deepcopy(values[".ores-rl.toml"]); bad_rl["policies"][0]["maxOvershoot"] = 1
    adversarial.append(expect_reject("rate-limit-positive-overshoot", lambda: validate_rate_limit(bad_rl)))
    hybrid_rl = copy.deepcopy(values[".ores-rl.toml"]); hybrid_rl["layout"] = "combined"; hybrid_rl["client"] = {"root": ".", "exposePolicyMetadata": False}
    validate_rate_limit(hybrid_rl)

    hybrid_lru = copy.deepcopy(values[".ores-lru.toml"])
    hybrid_lru["roles"] = ["client", "server"]; hybrid_lru["defaults"]["syncMode"] = "local_only"
    hybrid_lru["roleOverrides"] = [{"role": "server", "syncMode": "read_only", "overflowMode": "reject_and_reconcile"}]
    hybrid_lru["caches"] = [
        {"name": "runtime-env", "role": "client", "capacity": 64, "syncMode": "local_only"},
        {"name": "runtime-env", "role": "server", "capacity": 128, "syncMode": "read_only"},
    ]
    validate_lru(hybrid_lru)
    bad_lru = copy.deepcopy(hybrid_lru); bad_lru["caches"].append(copy.deepcopy(bad_lru["caches"][1]))
    adversarial.append(expect_reject("lru-duplicate-role-cache", lambda: validate_lru(bad_lru)))
    bad_lru = copy.deepcopy(hybrid_lru); bad_lru["caches"][0]["syncMode"] = "read_only"
    adversarial.append(expect_reject("lru-client-remote-sync", lambda: validate_lru(bad_lru)))

    bad_fan = copy.deepcopy(values[".fanwaave-cfg.toml"])
    next(binding for binding in bad_fan["env"] if binding["secret"])["default"] = "synthetic-not-a-secret"
    adversarial.append(expect_reject("fanwaave-secret-default", lambda: validate_fanwaave(bad_fan, cli_envs)))
    bad_fan_cli = set(cli_envs); bad_fan_cli.add("FANWAAVE_AUTH_TOKEN")
    adversarial.append(expect_reject("fanwaave-secret-cli-exposure", lambda: validate_fanwaave(values[".fanwaave-cfg.toml"], bad_fan_cli)))
    hybrid_fan = copy.deepcopy(values[".fanwaave-cfg.toml"]); hybrid_fan["mode"] = "hybrid"
    hybrid_fan["client"] = {"enabled": True, "api_base_url_binding": "api_base_url", "auth_token_binding": "auth_token"}
    validate_fanwaave(hybrid_fan, cli_envs)
    bad_fan = copy.deepcopy(hybrid_fan); bad_fan["server"]["enabled"] = False
    adversarial.append(expect_reject("fanwaave-hybrid-role-mismatch", lambda: validate_fanwaave(bad_fan, cli_envs)))

    bad_rpc = copy.deepcopy(values[".ores-rpc.toml"])
    next(binding for binding in bad_rpc["env"] if binding["secret"])["allowArgv"] = True
    adversarial.append(expect_reject("rpc-secret-argv-exposure", lambda: validate_rpc(bad_rpc, cli_envs)))
    hybrid_rpc = copy.deepcopy(values[".ores-rpc.toml"]); hybrid_rpc["repositoryMode"] = "hybrid"; hybrid_rpc["allowOverlappingRoots"] = True
    hybrid_rpc["targets"].append({
        "name": "client", "role": "client", "roots": ["."], "rpcVersion": "v1",
        "transports": ["http"], "framing": "json", "propagateHeaders": ["traceparent", "x-request-id"],
    })
    validate_rpc(hybrid_rpc, cli_envs)
    bad_rpc = copy.deepcopy(hybrid_rpc); bad_rpc["allowOverlappingRoots"] = False
    adversarial.append(expect_reject("rpc-hybrid-overlap-without-opt-in", lambda: validate_rpc(bad_rpc, cli_envs)))

    adversarial.append(expect_reject("shared-auth-dual-filename", lambda: validate_shared_auth(auth_value, True)))

    snapshots = validate_snapshots(harness_root)
    config_names = list(STATIC_FILES) + [auth_name]
    file_digests = {name: hashlib.sha256((repo_root / name).read_bytes()).hexdigest() for name in config_names}
    receipt = {
        "schema": "ores.toml-config-family.receipt/v2",
        "status": "passed",
        "files": file_digests,
        "sharedAuthFilename": auth_name,
        "snapshotGitBlobs": snapshots,
        "contracts": {
            "middleware": "0ba59b36777345989788f8cd4687c10735546c3d",
            "rateLimit": "241353d0f5269450690d9646be03db2aba59a2ae",
            "lru": "4474d240b38a4fe1dd24f01dcd2e9ab7a4c34b27",
            "sharedAuth": "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9",
            "fanwaave": "e27695091a5b8276543a6f435156a25043f297a9",
            "fanwaaveFlags2EnvRuntime": "ef00c1995e35e067ec58291fc6678b109e3692d7",
            "rpc": "12127a82ff1c0c34096faaf6df1a2a8484ea2feb",
            "tjsv": "7241f8e52dcc4518c72f0fdb5152d6cf66c86656",
        },
        "adversarialCases": adversarial,
        "adversarialCount": len(adversarial),
        "sameRootHybridAccepted": {
            "middleware": True,
            "rateLimit": True,
            "lru": True,
            "fanwaave": True,
            "rpc": True,
        },
    }
    destination = repo_root / args.receipt
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "adversarialCount": len(adversarial), "receipt": str(destination.relative_to(repo_root)), "sharedAuthFilename": auth_name}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        raise SystemExit(f"TOML config family validation failed: {exc}") from exc
