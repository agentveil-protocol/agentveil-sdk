"""Minimal CLI for the experimental MCP proxy.

P3 adds stdio pass-through transport. It still does not implement policy
classification, AVP Runtime Gate calls, approval UI, or enforcement.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable, TextIO

from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import DelegationInvalid, verify_delegation
from agentveil_mcp_proxy.policy import (
    PROXY_CONFIG_SCHEMA_VERSION,
    PolicyConfig,
    ProxyConfig,
    ProxyConfigError,
    builtin_policy_pack,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough, PassthroughError


DEFAULT_BASE_URL = "https://agentveil.dev"
DEFAULT_AGENT_NAME = "agentveil-mcp-proxy"
DEFAULT_CONTROL_GRANT_TTL_DAYS = 30
DEFAULT_ALLOWED_CATEGORIES = ("mcp_proxy",)
AGENTVEIL_DEV_SIGNER_DIDS = (
    "did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3",
    "did:key:z6Mkjw22249tpNN4LJGLyq1oGSq1Skh3ks94fiMrgi4oqveo",
)


class ProxyCliError(RuntimeError):
    """CLI-safe error with an explicit process exit code."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class ProxyPaths:
    """Filesystem locations for one proxy home."""

    home: Path
    agents_dir: Path
    proxy_dir: Path
    config_path: Path

    def identity_path(self, agent_name: str) -> Path:
        return self.agents_dir / f"{agent_name}.json"

    def control_grant_path(self, agent_name: str) -> Path:
        return self.proxy_dir / f"{agent_name}.control-grant.json"


@dataclass(frozen=True)
class InitResult:
    """Result of `agentveil-mcp-proxy init`."""

    agent_name: str
    agent_did: str
    identity_path: Path
    config_path: Path
    control_grant_path: Path
    control_grant_expires_at: str


def default_home() -> Path:
    """Return the proxy home, respecting AVP_HOME for tests/advanced use."""

    return Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()


def proxy_paths(home: Path | None = None, config_path: Path | None = None) -> ProxyPaths:
    """Return standard proxy paths under the given home."""

    root = (home or default_home()).expanduser()
    proxy_dir = root / "mcp-proxy"
    return ProxyPaths(
        home=root,
        agents_dir=root / "agents",
        proxy_dir=proxy_dir,
        config_path=(config_path.expanduser() if config_path else proxy_dir / "config.json"),
    )


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        raise ProxyCliError(f"cannot secure directory permissions for {path}")


def _secure_write_json(path: Path, data: dict[str, Any], *, force: bool = False) -> None:
    """Write JSON with owner-only file permissions and no accidental overwrite."""

    _mkdir_private(path.parent)
    if path.exists() and not force:
        raise ProxyCliError(f"{path} already exists; pass --force to overwrite")

    if force:
        tmp_path = path.with_name(f".{path.name}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(tmp_path, flags, 0o600), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
        return

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(path, 0o600)


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise ProxyCliError(f"{label} not found at {path}", exit_code=1) from exc
    except json.JSONDecodeError as exc:
        raise ProxyCliError(f"{label} is not valid JSON: {path}", exit_code=1) from exc
    if not isinstance(data, dict):
        raise ProxyCliError(f"{label} must be a JSON object: {path}", exit_code=1)
    return data


def _owner_only(path: Path) -> bool:
    try:
        return (path.stat().st_mode & 0o777) == 0o600
    except FileNotFoundError:
        return False


def trusted_signers_for_base_url(base_url: str) -> tuple[str, ...]:
    """Return SDK-bundled trusted signer DID(s) for known AVP environments."""

    if base_url.rstrip("/") == DEFAULT_BASE_URL:
        return AGENTVEIL_DEV_SIGNER_DIDS
    return ()


def _create_identity_payload(*, base_url: str, agent_name: str) -> tuple[dict[str, Any], AVPAgent]:
    signing_key = SigningKey.generate()
    agent = AVPAgent(base_url, bytes(signing_key), name=agent_name)
    payload = {
        "name": agent_name,
        "did": agent.did,
        "public_key_hex": agent.public_key_hex,
        "registered": False,
        "verified": False,
        "base_url": base_url.rstrip("/"),
        "private_key_hex": agent.private_key_hex,
        "encrypted": False,
    }
    return payload, agent


def _policy_to_dict(policy: PolicyConfig) -> dict[str, Any]:
    rules = []
    for rule in policy.rules:
        match = {}
        if rule.match.server:
            match["server"] = list(rule.match.server)
        if rule.match.tool:
            match["tool"] = list(rule.match.tool)
        if rule.match.action:
            match["action"] = list(rule.match.action)
        if rule.match.risk_class:
            match["risk_class"] = [risk.value for risk in rule.match.risk_class]
        item: dict[str, Any] = {
            "id": rule.id,
            "source": rule.source,
            "decision": rule.decision.value,
            "match": match,
        }
        if rule.risk_class is not None:
            item["risk_class"] = rule.risk_class.value
        if rule.intentional_override:
            item["intentional_override"] = True
        if rule.reason:
            item["reason"] = rule.reason
        rules.append(item)
    return {
        "id": policy.id,
        "policy_schema_version": policy.policy_schema_version,
        "default_decision": policy.default_decision.value,
        "default_risk_class": policy.default_risk_class.value,
        "rules": rules,
    }


def _build_config_payload(
    *,
    base_url: str,
    agent_name: str,
    trusted_signer_dids: Iterable[str],
    policy_pack: str,
) -> dict[str, Any]:
    policy = builtin_policy_pack(policy_pack)
    payload = {
        "proxy_config_schema_version": PROXY_CONFIG_SCHEMA_VERSION,
        "avp": {
            "base_url": base_url.rstrip("/"),
            "agent_name": agent_name,
            "trusted_signer_dids": list(trusted_signer_dids),
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {
            "approval_timeout_seconds": 300,
            "on_timeout": "deny",
        },
        "policy": _policy_to_dict(policy),
        "downstream": {},
    }
    ProxyConfig.from_dict(payload)
    return payload


def init_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    base_url: str = DEFAULT_BASE_URL,
    agent_name: str = DEFAULT_AGENT_NAME,
    trusted_signer_dids: Iterable[str] | None = None,
    policy_pack: str = "default",
    ttl_days: int = DEFAULT_CONTROL_GRANT_TTL_DAYS,
    allowed_categories: Iterable[str] = DEFAULT_ALLOWED_CATEGORIES,
    force: bool = False,
) -> InitResult:
    """Create a local proxy identity, config, and control grant."""

    if ttl_days <= 0:
        raise ProxyCliError("--ttl-days must be positive")
    categories = tuple(category for category in allowed_categories if category)
    if not categories:
        raise ProxyCliError("at least one allowed category is required")

    paths = proxy_paths(home, config_path)
    identity_path = paths.identity_path(agent_name)
    grant_path = paths.control_grant_path(agent_name)
    if not force:
        for path in (identity_path, paths.config_path, grant_path):
            if path.exists():
                raise ProxyCliError(f"{path} already exists; pass --force to overwrite")

    signers = tuple(trusted_signer_dids or trusted_signers_for_base_url(base_url))
    if not signers:
        raise ProxyCliError(
            "no trusted signer DID configured; pass --trusted-signer-did for this AVP base URL",
        )

    _mkdir_private(paths.agents_dir)
    _mkdir_private(paths.proxy_dir)

    identity_payload, agent = _create_identity_payload(base_url=base_url, agent_name=agent_name)
    control_grant = agent.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=list(categories),
        valid_for=timedelta(days=ttl_days),
        purpose="Local MCP proxy control grant",
    )
    verified_grant = verify_delegation(control_grant)
    expires_at = str(verified_grant["valid_until"])

    config_payload = _build_config_payload(
        base_url=base_url,
        agent_name=agent_name,
        trusted_signer_dids=signers,
        policy_pack=policy_pack,
    )

    _secure_write_json(identity_path, identity_payload, force=force)
    _secure_write_json(grant_path, control_grant, force=force)
    _secure_write_json(paths.config_path, config_payload, force=force)

    return InitResult(
        agent_name=agent_name,
        agent_did=agent.did,
        identity_path=identity_path,
        config_path=paths.config_path,
        control_grant_path=grant_path,
        control_grant_expires_at=expires_at,
    )


def load_proxy_config(path: Path) -> ProxyConfig:
    """Load and validate proxy config from JSON."""

    data = _read_json(path, "proxy config")
    try:
        return ProxyConfig.from_dict(data)
    except ProxyConfigError as exc:
        raise ProxyCliError(f"proxy config invalid: {exc}", exit_code=1) from exc


def doctor_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
) -> int:
    """Validate local proxy files without starting transport."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    try:
        config = load_proxy_config(paths.config_path)
        identity_path = paths.identity_path(config.avp.agent_name)
        grant_path = paths.control_grant_path(config.avp.agent_name)
        identity = _read_json(identity_path, "agent identity")
        grant = _read_json(grant_path, "control grant")

        failures = []
        if not config.avp.trusted_signer_dids:
            failures.append("trusted signer DID set is empty")
        if not _owner_only(identity_path):
            failures.append(f"agent identity permissions must be 0600: {identity_path}")
        if not _owner_only(grant_path):
            failures.append(f"control grant permissions must be 0600: {grant_path}")
        if identity.get("did") is None:
            failures.append("agent identity missing DID")
        try:
            verified = verify_delegation(grant)
            if identity.get("did") and verified.get("issuer") != identity["did"]:
                failures.append("control grant issuer does not match proxy identity")
            if identity.get("did") and verified.get("subject") != identity["did"]:
                failures.append("control grant subject does not match proxy identity")
        except DelegationInvalid as exc:
            failures.append(f"control grant invalid: {exc}")

        if failures:
            for failure in failures:
                print(f"FAIL: {failure}", file=out)
            return 1

        print(f"OK: config {paths.config_path}", file=out)
        print(f"OK: identity {identity_path}", file=out)
        print(f"OK: control grant {grant_path}", file=out)
        print(f"OK: trusted signers {len(config.avp.trusted_signer_dids)}", file=out)
        return 0
    except ProxyCliError as exc:
        print(f"FAIL: {exc}", file=out)
        return 1


def run_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    client_in: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Validate readiness and run stdio MCP pass-through."""

    out = out or sys.stdout
    client_in = client_in or sys.stdin
    err = err or sys.stderr
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    doctor_out = io.StringIO()
    health = doctor_proxy(home=paths.home, config_path=paths.config_path, out=doctor_out)
    if health != 0:
        err.write(doctor_out.getvalue())
        err.flush()
        return health
    try:
        downstream = DownstreamConfig.from_proxy_config(config)
        return McpPassthrough(downstream).run_stdio(client_in, out)
    except PassthroughError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc


def run_proxy_stub(**kwargs: Any) -> int:
    """Backward-compatible wrapper for the P2 name."""

    return run_proxy(**kwargs)


def _add_common_path_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home", type=Path, default=None, help="AVP home directory (default: ~/.avp)")
    parser.add_argument("--config", type=Path, default=None, help="Proxy config JSON path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentveil-mcp-proxy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create local proxy identity, config, and control grant")
    _add_common_path_args(init)
    init.add_argument("--base-url", default=DEFAULT_BASE_URL)
    init.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    init.add_argument("--trusted-signer-did", action="append", default=None)
    init.add_argument("--policy-pack", default="default", choices=["default", "github", "filesystem", "shell"])
    init.add_argument("--ttl-days", type=int, default=DEFAULT_CONTROL_GRANT_TTL_DAYS)
    init.add_argument("--allowed-category", action="append", default=None)
    init.add_argument("--force", action="store_true")

    doctor = subparsers.add_parser("doctor", help="Validate local proxy config and files")
    _add_common_path_args(doctor)

    run = subparsers.add_parser("run", help="Run stdio MCP passthrough")
    _add_common_path_args(run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = init_proxy(
                home=args.home,
                config_path=args.config,
                base_url=args.base_url,
                agent_name=args.agent_name,
                trusted_signer_dids=args.trusted_signer_did,
                policy_pack=args.policy_pack,
                ttl_days=args.ttl_days,
                allowed_categories=args.allowed_category or DEFAULT_ALLOWED_CATEGORIES,
                force=args.force,
            )
            print(f"Created MCP proxy identity: {result.agent_did}")
            print(f"Identity: {result.identity_path}")
            print(f"Config: {result.config_path}")
            print(f"Control grant: {result.control_grant_path}")
            print(f"Control grant expires: {result.control_grant_expires_at}")
            return 0
        if args.command == "doctor":
            return doctor_proxy(home=args.home, config_path=args.config)
        if args.command == "run":
            return run_proxy(home=args.home, config_path=args.config)
    except ProxyCliError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
