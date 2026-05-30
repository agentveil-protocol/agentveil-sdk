"""Minimal CLI for the MCP proxy.

The CLI creates encrypted local proxy identities by default, manages the
control grant used by Runtime Gate, and runs stdio passthrough for configured
downstream MCP servers. Approval-required calls can route through the local
approval surface and durable evidence store. Runtime Gate calls use an
in-memory circuit breaker for sustained backend failures.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import getpass
import io
import json
import math
import os
from pathlib import Path
import signal
import sys
import threading
import time
from typing import Any, Iterable, Mapping, TextIO

from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import DelegationInvalid, verify_delegation
from agentveil.exceptions import AVPError, AVPNotFoundError, AVPValidationError
from agentveil_mcp_proxy.approval import (
    ApprovalManager,
    ApprovalServer,
    HeadlessPolicy,
    HeadlessPolicyError,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceError,
    ApprovalEvidenceStore,
    EvidenceExportError,
    EvidenceVerificationError,
    export_evidence_bundle,
    parse_utc_timestamp,
    verify_evidence_bundle_file,
)
from agentveil_mcp_proxy.evidence.proof import _fsync_parent_directory
from agentveil_mcp_proxy.identity import (
    IdentityDecryptError,
    IdentityError,
    IdentityInvalidError,
    IdentityPassphraseRequired,
    PASSPHRASE_ENV,
    PLAINTEXT_WARNING,
    encrypted_identity_payload,
    load_agent_from_identity,
    plaintext_identity_payload,
)
from agentveil_mcp_proxy.policy import (
    PROXY_CONFIG_SCHEMA_VERSION,
    PolicyConfig,
    ProxyConfig,
    ProxyConfigError,
    builtin_policy_pack,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough, PassthroughError
from agentveil_mcp_proxy.runtime_gate import RuntimeGateClient


DEFAULT_BASE_URL = "https://agentveil.dev"
DEFAULT_AGENT_NAME = "agentveil-mcp-proxy"
DEFAULT_CONTROL_GRANT_TTL_DAYS = 30
CONTROL_GRANT_EXPIRY_WARNING_DAYS = 7
REISSUE_GRANT_FORCE_THRESHOLD_SECONDS = 24 * 60 * 60
MIN_IDENTITY_PASSPHRASE_LENGTH = 12
DEFAULT_ALLOWED_CATEGORIES = ("mcp_proxy",)
DEFAULT_EVIDENCE_VACUUM_MAX_AGE_DAYS = 90
DEFAULT_EVENTS_LIMIT = 20
QUICKSTART_FILESYSTEM_MODULE = "agentveil_mcp_proxy.quickstart_filesystem"
SMOKE_INITIALIZE_ID = "avp-smoke-initialize"
SMOKE_TOOLS_LIST_ID = "avp-smoke-tools-list"
AGENTVEIL_DEV_SIGNER_DIDS = (
    "did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3",
    "did:key:z6Mkjw22249tpNN4LJGLyq1oGSq1Skh3ks94fiMrgi4oqveo",
)


class ProxyCliError(RuntimeError):
    """CLI-safe error with an explicit process exit code."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


class _RunProxySignalExit(Exception):
    """Internal control-flow marker for graceful signal-driven shutdown."""


def _install_run_proxy_signal_handlers(client_in: TextIO) -> dict[signal.Signals, Any]:
    """Install temporary SIGTERM/SIGINT handlers for the active run_proxy call."""

    if threading.current_thread() is not threading.main_thread():
        return {}

    previous: dict[signal.Signals, Any] = {}

    def _shutdown_handler(signum: int, _frame: Any) -> None:
        try:
            client_in.close()
        except Exception:
            pass
        raise _RunProxySignalExit(signum)

    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, _shutdown_handler)
        except (ValueError, OSError, RuntimeError):
            previous.pop(signum, None)
    return previous


def _restore_signal_handlers(previous: Mapping[signal.Signals, Any]) -> None:
    """Restore process-level signal handlers changed for run_proxy."""

    for signum, handler in previous.items():
        try:
            signal.signal(signum, handler)
        except (ValueError, OSError, RuntimeError):
            continue


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


@dataclass(frozen=True)
class ReissueGrantResult:
    """Result of `agentveil-mcp-proxy reissue-grant`."""

    agent_name: str
    agent_did: str
    control_grant_path: Path
    control_grant_expires_at: str


@dataclass(frozen=True)
class ConfigureDownstreamResult:
    """Result of `agentveil-mcp-proxy configure-downstream`."""

    config_path: Path
    downstream_name: str
    downstream_command: str
    downstream_args: tuple[str, ...]


@dataclass(frozen=True)
class SmokeResult:
    """Result of a downstream MCP smoke check."""

    downstream_name: str
    tool_count: int


def _print_json(payload: Mapping[str, Any], out: TextIO | None = None) -> None:
    print(json.dumps(dict(payload), sort_keys=True), file=out or sys.stdout)


def _downstream_info(config: ProxyConfig) -> dict[str, Any]:
    """Return a stable, machine-readable downstream summary."""

    if not config.downstream:
        return {"configured": False}
    try:
        downstream = DownstreamConfig.from_proxy_config(config)
    except PassthroughError as exc:
        return {
            "configured": False,
            "error": str(exc),
        }
    return {
        "configured": True,
        "name": downstream.name,
        "command": downstream.command,
        "args": list(downstream.args),
        "response_timeout_seconds": downstream.response_timeout_seconds,
    }


def _evidence_count(paths: ProxyPaths) -> int:
    evidence_path = paths.proxy_dir / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with ApprovalEvidenceStore(evidence_path) as store:
        return len(store.list_records())


def _downstream_info_if_available(config_path: Path) -> dict[str, Any] | None:
    try:
        return _downstream_info(load_proxy_config(config_path))
    except ProxyCliError:
        return None


def _event_record_dict(record: Any) -> dict[str, Any]:
    return {
        "timestamp": _event_timestamp(record.created_at),
        "server": record.downstream_server,
        "tool": record.tool_name,
        "risk_class": record.risk_class,
        "status": record.status,
        "policy_rule": record.policy_rule_id,
        "receipt": _receipt_status(record),
        "record_id": record.request_id,
    }


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
        try:
            with os.fdopen(os.open(tmp_path, flags, 0o600), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
            _fsync_parent_directory(path)
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        return

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(path, 0o600)
    _fsync_parent_directory(path)


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


def _require_owner_only_passphrase_file(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ProxyCliError(f"passphrase file unavailable: {path}", exit_code=1) from exc
    if mode & 0o077:
        raise ProxyCliError(
            "passphrase file permissions must be owner-only (0o600 or 0o400)"
        )


def _read_passphrase_file(path: Path) -> str:
    expanded = path.expanduser()
    _require_owner_only_passphrase_file(expanded)
    try:
        value = expanded.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ProxyCliError(f"passphrase file unavailable: {path}", exit_code=1) from exc
    if not value:
        raise ProxyCliError("passphrase file is empty")
    return value


def _validate_passphrase_strength(value: str) -> str:
    if len(value) < MIN_IDENTITY_PASSPHRASE_LENGTH:
        raise ProxyCliError(
            f"passphrase must be at least {MIN_IDENTITY_PASSPHRASE_LENGTH} characters"
        )
    return value


def _explicit_passphrase(
    *,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
) -> str | None:
    if passphrase is not None and passphrase_file is not None:
        raise ProxyCliError("--passphrase and --passphrase-file cannot be combined")
    if passphrase is not None:
        if not passphrase:
            raise ProxyCliError("passphrase must not be empty")
        return passphrase
    if passphrase_file is not None:
        return _read_passphrase_file(passphrase_file)
    env_value = os.environ.get(PASSPHRASE_ENV)
    if env_value is not None:
        if not env_value:
            raise ProxyCliError(f"{PASSPHRASE_ENV} must not be empty")
        return env_value
    return None


def _resolve_new_identity_passphrase(
    *,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    plaintext: bool = False,
) -> str | None:
    if plaintext:
        if passphrase is not None or passphrase_file is not None:
            raise ProxyCliError("--plaintext cannot be combined with passphrase options")
        return None

    resolved = _explicit_passphrase(passphrase=passphrase, passphrase_file=passphrase_file)
    if resolved is not None:
        return _validate_passphrase_strength(resolved)

    if sys.stdin.isatty():
        first = getpass.getpass("MCP proxy identity passphrase: ")
        if not first:
            raise ProxyCliError("passphrase must not be empty")
        second = getpass.getpass("Confirm MCP proxy identity passphrase: ")
        if first != second:
            raise ProxyCliError("passphrases do not match")
        return _validate_passphrase_strength(first)

    raise ProxyCliError(
        "encrypted identity passphrase required; pass --passphrase, "
        "--passphrase-file, set AVP_PROXY_PASSPHRASE, or use --plaintext to opt out",
        exit_code=1,
    )


def _resolve_existing_identity_passphrase(
    identity: Mapping[str, Any],
    *,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
) -> str | None:
    if identity.get("encrypted") is not True:
        return None
    resolved = _explicit_passphrase(passphrase=passphrase, passphrase_file=passphrase_file)
    if resolved is not None:
        return resolved

    if sys.stdin.isatty():
        value = getpass.getpass("MCP proxy identity passphrase: ")
        if not value:
            raise ProxyCliError("passphrase must not be empty", exit_code=1)
        return value

    raise ProxyCliError(
        "encrypted identity passphrase required; pass --passphrase, "
        "--passphrase-file, or set AVP_PROXY_PASSPHRASE",
        exit_code=1,
    )


def _owner_only(path: Path) -> bool:
    if os.name == "nt":
        # Windows profile ACLs, not POSIX mode bits, enforce owner-only access.
        return True
    try:
        return (path.stat().st_mode & 0o777) == 0o600
    except FileNotFoundError:
        return False


def trusted_signers_for_base_url(base_url: str) -> tuple[str, ...]:
    """Return SDK-bundled trusted signer DID(s) for known AVP environments."""

    if base_url.rstrip("/") == DEFAULT_BASE_URL:
        return AGENTVEIL_DEV_SIGNER_DIDS
    return ()


def _create_identity_payload(
    *,
    base_url: str,
    agent_name: str,
    passphrase: str | None,
    plaintext: bool,
) -> tuple[dict[str, Any], AVPAgent]:
    signing_key = SigningKey.generate()
    agent = AVPAgent(base_url, bytes(signing_key), name=agent_name)
    payload = (
        plaintext_identity_payload(agent)
        if plaintext
        else encrypted_identity_payload(agent, passphrase or "")
    )
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
        if rule.approval_scope_expansion:
            item["approval"] = {"scope_expansion": rule.approval_scope_expansion}
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
    downstream_config: Mapping[str, Any] | None = None,
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
            "read": "approval",
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
        "circuit_breaker": {
            "failures_before_open": 5,
            "window_seconds": 60,
            "cooldown_seconds": 30,
            "half_open_test_count": 1,
        },
        "policy": _policy_to_dict(policy),
        "tool_surface": {"mode": "off", "allow": []},
        "downstream": dict(downstream_config or {}),
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
    downstream_config: Mapping[str, Any] | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    plaintext: bool = False,
    err: TextIO | None = None,
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

    identity_passphrase = _resolve_new_identity_passphrase(
        passphrase=passphrase,
        passphrase_file=passphrase_file,
        plaintext=plaintext,
    )
    if plaintext:
        warning_out = err or sys.stderr
        print(PLAINTEXT_WARNING, file=warning_out)

    _mkdir_private(paths.agents_dir)
    _mkdir_private(paths.proxy_dir)

    identity_payload, agent = _create_identity_payload(
        base_url=base_url,
        agent_name=agent_name,
        passphrase=identity_passphrase,
        plaintext=plaintext,
    )
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
        downstream_config=downstream_config,
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


def _parse_env_assignment(value: str) -> tuple[str, str]:
    key, separator, env_value = value.partition("=")
    if not separator or not key:
        raise ProxyCliError("--env entries must use KEY=VALUE")
    if key.startswith("AVP_"):
        raise ProxyCliError("downstream.env cannot set AVP_* variables")
    return key, env_value


def _downstream_config_payload(
    *,
    name: str,
    command: str,
    args: Iterable[str] = (),
    env_entries: Iterable[str] = (),
    env_passthrough: Iterable[str] = (),
    response_timeout_seconds: float | None = None,
) -> dict[str, Any]:
    env = dict(_parse_env_assignment(item) for item in env_entries)
    payload: dict[str, Any] = {
        "name": name,
        "command": command,
        "args": list(args),
    }
    if env:
        payload["env"] = env
    passthrough = list(env_passthrough)
    if passthrough:
        payload["env_passthrough"] = passthrough
    if response_timeout_seconds is not None:
        payload["response_timeout_seconds"] = response_timeout_seconds
    return payload


def quickstart_filesystem_downstream(root: Path) -> dict[str, Any]:
    """Return downstream config for the built-in quickstart filesystem server."""

    sandbox = root.expanduser().resolve()
    sandbox.mkdir(parents=True, exist_ok=True)
    return _downstream_config_payload(
        name="filesystem",
        command=sys.executable,
        args=("-m", QUICKSTART_FILESYSTEM_MODULE, str(sandbox)),
        response_timeout_seconds=5.0,
    )


def _validate_downstream_payload(config_payload: Mapping[str, Any]) -> DownstreamConfig:
    try:
        return DownstreamConfig.from_proxy_config(ProxyConfig.from_dict(config_payload))
    except (ProxyConfigError, PassthroughError) as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc


def configure_downstream(
    *,
    name: str,
    command: str,
    args: Iterable[str] = (),
    env_entries: Iterable[str] = (),
    env_passthrough: Iterable[str] = (),
    response_timeout_seconds: float | None = None,
    home: Path | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> ConfigureDownstreamResult:
    """Write downstream MCP server config into the proxy config file."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config_payload = _read_json(paths.config_path, "proxy config")
    downstream_payload = _downstream_config_payload(
        name=name,
        command=command,
        args=args,
        env_entries=env_entries,
        env_passthrough=env_passthrough,
        response_timeout_seconds=response_timeout_seconds,
    )
    config_payload["downstream"] = downstream_payload
    downstream = _validate_downstream_payload(config_payload)
    _secure_write_json(paths.config_path, config_payload, force=True)
    downstream_info = _downstream_info(ProxyConfig.from_dict(config_payload))
    if output_json:
        _print_json({
            "ok": True,
            "errors": [],
            "warnings": [],
            "config_path": str(paths.config_path),
            "downstream": downstream_info,
            "evidence_count": _evidence_count(paths),
        }, out)
    else:
        print(
            f"OK: downstream {downstream.name} configured in {paths.config_path}",
            file=out,
        )
    return ConfigureDownstreamResult(
        config_path=paths.config_path,
        downstream_name=downstream.name,
        downstream_command=downstream.command,
        downstream_args=downstream.args,
    )


def load_proxy_config(path: Path) -> ProxyConfig:
    """Load and validate proxy config from JSON."""

    data = _read_json(path, "proxy config")
    try:
        return ProxyConfig.from_dict(data)
    except ProxyConfigError as exc:
        raise ProxyCliError(f"proxy config invalid: {exc}", exit_code=1) from exc


def _parse_grant_timestamp(grant: Mapping[str, Any], field: str) -> datetime:
    value = grant.get(field)
    if not isinstance(value, str):
        raise DelegationInvalid(f"{field} must be a string")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise DelegationInvalid(f"{field} is not ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)") from exc


def _format_grant_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _control_grant_ttl_message(grant: Mapping[str, Any]) -> tuple[str, str] | None:
    valid_until = _parse_grant_timestamp(grant, "validUntil")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if valid_until <= now:
        return ("FAIL", f"control grant expired at {_format_grant_timestamp(valid_until)}")
    remaining = (valid_until - now).total_seconds()
    if remaining <= CONTROL_GRANT_EXPIRY_WARNING_DAYS * 24 * 60 * 60:
        days = max(1, math.ceil(remaining / (24 * 60 * 60)))
        return (
            "WARN",
            "control grant expires in "
            f"{days} days at {_format_grant_timestamp(valid_until)}; "
            "run 'agentveil-mcp-proxy reissue-grant'",
        )
    return None


def _verify_delegation_for_reissue(grant: Mapping[str, Any]) -> dict[str, Any]:
    valid_from = _parse_grant_timestamp(grant, "validFrom")
    valid_until = _parse_grant_timestamp(grant, "validUntil")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    verification_time = now
    if verification_time > valid_until:
        verification_time = valid_until - timedelta(seconds=1)
    if verification_time < valid_from:
        verification_time = valid_from
    return verify_delegation(dict(grant), now=verification_time)


def _load_proxy_agent(
    *,
    identity: Mapping[str, Any],
    config: ProxyConfig,
    passphrase: str | None,
    timeout: float | None = None,
) -> Any:
    try:
        return load_agent_from_identity(
            identity,
            base_url=config.avp.base_url,
            agent_name=config.avp.agent_name,
            passphrase=passphrase,
            timeout=timeout,
        )
    except IdentityPassphraseRequired as exc:
        raise ProxyCliError("encrypted identity - passphrase required", exit_code=1) from exc
    except IdentityDecryptError as exc:
        raise ProxyCliError("encrypted identity could not be decrypted", exit_code=1) from exc
    except (IdentityInvalidError, IdentityError) as exc:
        raise ProxyCliError("proxy identity invalid", exit_code=1) from exc


def _check_backend_preflight(
    *,
    identity: Mapping[str, Any],
    config: ProxyConfig,
    passphrase: str | None,
    timeout_seconds: float = 5.0,
) -> str | None:
    """Issue two read-only GETs to verify backend readiness.

    Returns a failure description on the first failure, or ``None`` on
    success. Network and SDK exceptions are sanitized to category +
    sender; raw response bodies are not surfaced. No state is mutated
    on the backend (only ``GET /v1/health`` and
    ``GET /v1/onboarding/{did}``).
    """

    try:
        agent = _load_proxy_agent(
            identity=identity,
            config=config,
            passphrase=passphrase,
            timeout=timeout_seconds,
        )
    except ProxyCliError as exc:
        return f"backend preflight skipped: {exc}"

    base_url = config.avp.base_url
    try:
        agent.health()
    except AVPError as exc:
        return (
            f"backend health check failed at {base_url}: "
            f"status {exc.status_code}"
        )
    except Exception as exc:
        return (
            f"backend unreachable at {base_url}: "
            f"{type(exc).__name__}"
        )

    try:
        agent.get_onboarding_status()
    except AVPNotFoundError:
        did = identity.get("did")
        return (
            f"agent {did} is not registered with backend at {base_url}; "
            "run `agentveil-mcp-proxy register` to register this identity"
        )
    except AVPError as exc:
        return (
            "backend onboarding status check failed: "
            f"status {exc.status_code}"
        )
    except Exception as exc:
        return (
            "backend onboarding status unreachable: "
            f"{type(exc).__name__}"
        )

    return None


def _smoke_input() -> str:
    initialize = {
        "jsonrpc": "2.0",
        "id": SMOKE_INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "agentveil-mcp-proxy-smoke",
                "version": "0",
            },
        },
    }
    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    tools_list = {
        "jsonrpc": "2.0",
        "id": SMOKE_TOOLS_LIST_ID,
        "method": "tools/list",
        "params": {},
    }
    return "\n".join(json.dumps(item, separators=(",", ":")) for item in (
        initialize,
        initialized,
        tools_list,
    )) + "\n"


def _parse_smoke_responses(raw_output: str) -> dict[str, Mapping[str, Any]]:
    responses: dict[str, Mapping[str, Any]] = {}
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProxyCliError("downstream smoke returned invalid JSON-RPC", exit_code=1) from exc
        if not isinstance(message, Mapping):
            raise ProxyCliError("downstream smoke returned non-object JSON-RPC", exit_code=1)
        request_id = message.get("id")
        if request_id in {SMOKE_INITIALIZE_ID, SMOKE_TOOLS_LIST_ID}:
            responses[str(request_id)] = message
    return responses


def _tool_count_from_smoke_response(response: Mapping[str, Any]) -> int:
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise ProxyCliError("downstream tools/list response missing result", exit_code=1)
    tools = result.get("tools", [])
    if not isinstance(tools, list):
        raise ProxyCliError("downstream tools/list result.tools must be a list", exit_code=1)
    return len(tools)


def run_downstream_smoke(config: ProxyConfig) -> SmokeResult:
    """Launch downstream and verify MCP initialize + tools/list responses."""

    try:
        downstream = DownstreamConfig.from_proxy_config(config)
    except PassthroughError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc
    passthrough = McpPassthrough(downstream)
    client_out = io.StringIO()
    try:
        code = passthrough.run_stdio(io.StringIO(_smoke_input()), client_out)
    except PassthroughError as exc:
        raise ProxyCliError(f"downstream smoke failed: {exc}", exit_code=1) from exc
    if code != 0:
        raise ProxyCliError("downstream smoke failed", exit_code=1)
    responses = _parse_smoke_responses(client_out.getvalue())
    initialize_response = responses.get(SMOKE_INITIALIZE_ID)
    if initialize_response is None:
        raise ProxyCliError("downstream smoke missing initialize response", exit_code=1)
    if "error" in initialize_response:
        raise ProxyCliError("downstream initialize returned an error", exit_code=1)
    tools_response = responses.get(SMOKE_TOOLS_LIST_ID)
    if tools_response is None:
        raise ProxyCliError("downstream smoke missing tools/list response", exit_code=1)
    if "error" in tools_response:
        raise ProxyCliError("downstream tools/list returned an error", exit_code=1)
    return SmokeResult(
        downstream_name=downstream.name,
        tool_count=_tool_count_from_smoke_response(tools_response),
    )


def smoke_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> SmokeResult:
    """Run the local downstream MCP smoke check and print an operator summary."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    result = run_downstream_smoke(config)
    downstream = _downstream_info(config)
    downstream["tool_count"] = result.tool_count
    if output_json:
        _print_json({
            "ok": True,
            "errors": [],
            "warnings": [],
            "downstream": downstream,
            "evidence_count": _evidence_count(paths),
        }, out)
    else:
        print(
            f"OK: downstream {result.downstream_name} answered initialize/tools/list "
            f"({result.tool_count} tools)",
            file=out,
        )
    return result


def doctor_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    out: TextIO | None = None,
    check_backend: bool = False,
    full: bool = False,
    output_json: bool = False,
) -> int:
    """Validate local proxy files without starting transport.

    When ``check_backend`` is True, also issue two read-only GET
    requests against the configured backend (``/v1/health`` and
    ``/v1/onboarding/{did}``) to confirm reachability and that the
    proxy agent identity is registered. No backend state is mutated.
    Skipped if any local check already failed.
    """

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    backend_ok = False
    downstream_smoke: SmokeResult | None = None
    downstream: dict[str, Any] = {"configured": False}
    try:
        config = load_proxy_config(paths.config_path)
        downstream = _downstream_info(config)
        identity_path = paths.identity_path(config.avp.agent_name)
        grant_path = paths.control_grant_path(config.avp.agent_name)
        identity = _read_json(identity_path, "agent identity")
        grant = _read_json(grant_path, "control grant")

        failures = []
        warnings = []
        if not config.avp.trusted_signer_dids:
            failures.append("trusted signer DID set is empty")
        if not _owner_only(identity_path):
            failures.append(f"agent identity permissions must be 0600: {identity_path}")
        if not _owner_only(grant_path):
            failures.append(f"control grant permissions must be 0600: {grant_path}")
        if identity.get("did") is None:
            failures.append("agent identity missing DID")
        if config.downstream and downstream.get("error"):
            failures.append(f"downstream config invalid: {downstream['error']}")
        if not config.downstream:
            warnings.append(
                "downstream is not configured; run 'agentveil-mcp-proxy downstream set'"
            )
        identity_passphrase = None
        try:
            identity_passphrase = _resolve_existing_identity_passphrase(
                identity,
                passphrase=passphrase,
                passphrase_file=passphrase_file,
            )
            agent = _load_proxy_agent(
                identity=identity,
                config=config,
                passphrase=identity_passphrase,
            )
            if identity.get("did") and getattr(agent, "did", None) != identity["did"]:
                failures.append("agent identity DID mismatch")
        except ProxyCliError as exc:
            failures.append(str(exc))
        try:
            verified = verify_delegation(grant)
            if identity.get("did") and verified.get("issuer") != identity["did"]:
                failures.append("control grant issuer does not match proxy identity")
            if identity.get("did") and verified.get("subject") != identity["did"]:
                failures.append("control grant subject does not match proxy identity")
            ttl_message = _control_grant_ttl_message(grant)
            if ttl_message is not None:
                level, message = ttl_message
                if level == "FAIL":
                    failures.append(message)
                else:
                    warnings.append(message)
        except DelegationInvalid as exc:
            try:
                ttl_message = _control_grant_ttl_message(grant)
            except DelegationInvalid:
                ttl_message = None
            if ttl_message is not None and ttl_message[0] == "FAIL":
                failures.append(ttl_message[1])
            else:
                failures.append(f"control grant invalid: {exc}")

        if check_backend and not failures:
            backend_failure = _check_backend_preflight(
                identity=identity,
                config=config,
                passphrase=identity_passphrase,
            )
            if backend_failure is not None:
                failures.append(backend_failure)
            else:
                backend_ok = True

        if full and not failures:
            try:
                downstream_smoke = run_downstream_smoke(config)
            except ProxyCliError as exc:
                failures.append(str(exc))

        if failures:
            if output_json:
                _print_json({
                    "ok": False,
                    "errors": failures,
                    "warnings": warnings,
                    "downstream": downstream,
                    "backend": {"checked": check_backend, "ok": backend_ok},
                    "evidence_count": _evidence_count(paths),
                }, out)
            else:
                for failure in failures:
                    print(f"FAIL: {failure}", file=out)
            return 1

        if downstream_smoke is not None:
            downstream["tool_count"] = downstream_smoke.tool_count
            downstream["smoke_ok"] = True
        if output_json:
            _print_json({
                "ok": True,
                "errors": [],
                "warnings": warnings,
                "downstream": downstream,
                "backend": {"checked": check_backend, "ok": backend_ok},
                "evidence_count": _evidence_count(paths),
                "config_path": str(paths.config_path),
                "identity_path": str(identity_path),
                "control_grant_path": str(grant_path),
                "trusted_signer_count": len(config.avp.trusted_signer_dids),
            }, out)
        else:
            print(f"OK: config {paths.config_path}", file=out)
            print(f"OK: identity {identity_path}", file=out)
            print(f"OK: control grant {grant_path}", file=out)
            print(f"OK: trusted signers {len(config.avp.trusted_signer_dids)}", file=out)
            print(
                "OK: circuit breaker thresholds "
                f"({config.circuit_breaker.failures_before_open} failures, "
                f"{config.circuit_breaker.window_seconds}s window, "
                f"{config.circuit_breaker.cooldown_seconds}s cooldown)",
                file=out,
            )
            if downstream.get("configured"):
                print(f"OK: downstream {downstream['name']} configured", file=out)
            if backend_ok:
                print(
                    f"OK: backend reachable at {config.avp.base_url}, agent registered",
                    file=out,
                )
            if downstream_smoke is not None:
                print(
                    f"OK: downstream {downstream_smoke.downstream_name} answered "
                    f"initialize/tools/list ({downstream_smoke.tool_count} tools)",
                    file=out,
                )
            for warning in warnings:
                print(f"WARN: {warning}", file=out)
        return 0
    except ProxyCliError as exc:
        if output_json:
            _print_json({
                "ok": False,
                "errors": [str(exc)],
                "warnings": [],
                "downstream": downstream,
                "backend": {"checked": check_backend, "ok": False},
                "evidence_count": _evidence_count(paths),
            }, out)
        else:
            print(f"FAIL: {exc}", file=out)
        return 1


def _rewrite_proxy_identity_after_register(
    *,
    identity_path: Path,
    agent: Any,
    passphrase: str | None,
) -> None:
    """Persist updated registration status in the proxy's identity format.

    ``AVPAgent.register(...)`` calls ``self.save()`` which writes a
    different file layout to the same path as the proxy identity. We
    block that save during ``register_proxy`` and rewrite here using
    the proxy's own helpers so the file format and encryption are
    preserved.
    """

    if passphrase is None:
        payload = plaintext_identity_payload(agent)
    else:
        payload = encrypted_identity_payload(agent, passphrase)
    _secure_write_json(identity_path, payload, force=True)


def register_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Register the existing proxy identity with the configured backend.

    Reuses the same identity file ``init`` created (preserving the DID
    and the encrypted-at-rest format), calls the SDK's
    ``AVPAgent.register()`` against the same ``base_url`` from the
    proxy config, and rewrites the identity file with
    ``registered: true``. Backend network errors are sanitized to
    category + status code; private key material and raw response
    bodies are never printed.
    """

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    identity_path = paths.identity_path(config.avp.agent_name)
    identity = _read_json(identity_path, "agent identity")
    identity_passphrase = _resolve_existing_identity_passphrase(
        identity,
        passphrase=passphrase,
        passphrase_file=passphrase_file,
    )
    agent = _load_proxy_agent(
        identity=identity,
        config=config,
        passphrase=identity_passphrase,
    )
    base_url = config.avp.base_url

    def emit_json(
        *,
        ok: bool,
        registered: bool,
        errors: Iterable[str] = (),
        warnings: Iterable[str] = (),
    ) -> None:
        _print_json({
            "ok": ok,
            "errors": list(errors),
            "warnings": list(warnings),
            "agent_did": agent.did,
            "base_url": base_url,
            "registered": registered,
        }, out)

    # ``AVPAgent.register`` calls ``self.save()`` internally which would
    # rewrite ~/.avp/agents/<name>.json in the SDK's plaintext format
    # and DOWNGRADE the proxy's encrypted identity. Replace with a
    # no-op on this instance; we rewrite the file ourselves below using
    # the proxy's own payload helpers.
    agent.save = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    try:
        agent.register()
    except AVPValidationError as exc:
        if getattr(exc, "status_code", 0) == 409:
            # ``AVPAgent.register`` raises 409 before it gets to set its
            # ``_is_registered`` / ``_is_verified`` flags, so the loaded
            # agent's in-memory state still reads False. The backend has
            # already accepted this DID, so reflect that locally before
            # writing the identity file; otherwise the rewritten file
            # would say ``registered: false`` while the CLI told the user
            # the identity is already registered.
            if hasattr(agent, "_is_registered"):
                agent._is_registered = True
            if hasattr(agent, "_is_verified"):
                agent._is_verified = True
            _rewrite_proxy_identity_after_register(
                identity_path=identity_path,
                agent=agent,
                passphrase=identity_passphrase,
            )
            if output_json:
                emit_json(
                    ok=True,
                    registered=True,
                    warnings=("agent already registered",),
                )
            else:
                print(
                    f"OK: agent {agent.did} already registered at {base_url}",
                    file=out,
                )
            return 0
        message = f"registration rejected at {base_url}: status {exc.status_code}"
        if output_json:
            emit_json(ok=False, registered=False, errors=(message,))
        else:
            print(f"FAIL: {message}", file=out)
        return 1
    except AVPError as exc:
        message = f"registration failed at {base_url}: status {exc.status_code}"
        if output_json:
            emit_json(ok=False, registered=False, errors=(message,))
        else:
            print(f"FAIL: {message}", file=out)
        return 1
    except Exception as exc:
        message = f"backend unreachable at {base_url}: {type(exc).__name__}"
        if output_json:
            emit_json(ok=False, registered=False, errors=(message,))
        else:
            print(f"FAIL: {message}", file=out)
        return 1

    _rewrite_proxy_identity_after_register(
        identity_path=identity_path,
        agent=agent,
        passphrase=identity_passphrase,
    )
    if output_json:
        emit_json(ok=True, registered=True)
    else:
        print(
            f"OK: agent {agent.did} registered at {base_url}",
            file=out,
        )
    return 0


def _grant_scope_for_reissue(scope: Any) -> tuple[list[str], dict[str, Any] | None]:
    if not isinstance(scope, list):
        raise ProxyCliError("control grant scope invalid", exit_code=1)
    categories = [
        entry.get("value")
        for entry in scope
        if isinstance(entry, dict) and entry.get("predicate") == "allowed_category"
    ]
    if not categories or any(not isinstance(category, str) or not category for category in categories):
        raise ProxyCliError("control grant allowed categories unavailable", exit_code=1)
    max_spend_entries = [
        entry for entry in scope if isinstance(entry, dict) and entry.get("predicate") == "max_spend"
    ]
    if len(max_spend_entries) > 1:
        raise ProxyCliError("control grant max_spend scope unsupported", exit_code=1)
    max_spend = None
    if max_spend_entries:
        entry = max_spend_entries[0]
        max_spend = {
            "currency": entry.get("currency"),
            "amount": entry.get("amount"),
        }
    return categories, max_spend


def reissue_grant(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    ttl_days: int = DEFAULT_CONTROL_GRANT_TTL_DAYS,
    force: bool = False,
    auto: bool = False,
    out: TextIO | None = None,
) -> ReissueGrantResult:
    """Issue a fresh control grant from the local proxy identity."""

    if ttl_days <= 0:
        raise ProxyCliError("--ttl-days must be positive")
    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    identity_path = paths.identity_path(config.avp.agent_name)
    grant_path = paths.control_grant_path(config.avp.agent_name)
    identity = _read_json(identity_path, "agent identity")
    grant = _read_json(grant_path, "control grant")
    identity_passphrase = _resolve_existing_identity_passphrase(
        identity,
        passphrase=passphrase,
        passphrase_file=passphrase_file,
    )
    agent = _load_proxy_agent(
        identity=identity,
        config=config,
        passphrase=identity_passphrase,
    )
    try:
        verified = _verify_delegation_for_reissue(grant)
    except DelegationInvalid as exc:
        raise ProxyCliError(f"control grant invalid: {exc}", exit_code=1) from exc

    if verified.get("issuer") != agent.did or verified.get("subject") != agent.did:
        raise ProxyCliError("control grant does not match proxy identity", exit_code=1)

    valid_until = _parse_grant_timestamp(grant, "validUntil")
    remaining = (valid_until - datetime.now(timezone.utc).replace(microsecond=0)).total_seconds()
    if remaining > REISSUE_GRANT_FORCE_THRESHOLD_SECONDS and not force:
        raise ProxyCliError(
            "control grant has more than 24 hours remaining; pass --force to reissue now",
            exit_code=1,
        )

    categories, max_spend = _grant_scope_for_reissue(verified.get("scope"))
    new_grant = agent.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=categories,
        valid_for=timedelta(days=ttl_days),
        max_spend=max_spend,
        purpose=str(verified.get("purpose") or "Local MCP proxy control grant"),
    )
    new_verified = verify_delegation(new_grant)
    _secure_write_json(grant_path, new_grant, force=True)
    expires_at = _format_grant_timestamp(new_verified["valid_until"])
    if auto:
        print(json.dumps({
            "status": "reissued",
            "control_grant": str(grant_path),
            "expires_at": expires_at,
        }, sort_keys=True), file=out)
    else:
        print(f"Control grant reissued: {grant_path}", file=out)
        print(f"Control grant expires: {expires_at}", file=out)
    return ReissueGrantResult(
        agent_name=config.avp.agent_name,
        agent_did=agent.did,
        control_grant_path=grant_path,
        control_grant_expires_at=expires_at,
    )


def _receipt_fetcher_for_export(
    *,
    identity: Mapping[str, Any],
    config: ProxyConfig,
    passphrase: str | None,
    passphrase_file: Path | None,
) -> Any | None:
    if (
        identity.get("encrypted") is True
        and passphrase is None
        and passphrase_file is None
        and os.environ.get(PASSPHRASE_ENV) is None
    ):
        return None
    try:
        identity_passphrase = _resolve_existing_identity_passphrase(
            identity,
            passphrase=passphrase,
            passphrase_file=passphrase_file,
        )
        agent = _load_proxy_agent(
            identity=identity,
            config=config,
            passphrase=identity_passphrase,
            timeout=2.0,
        )
    except ProxyCliError:
        return None
    return agent.get_decision_receipt


def export_evidence(
    *,
    output_path: Path,
    home: Path | None = None,
    config_path: Path | None = None,
    since: str | None = None,
    until: str | None = None,
    request_ids: Iterable[str] | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    out: TextIO | None = None,
) -> dict[str, Any]:
    """Export local evidence records as an offline verification bundle."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    identity = _read_json(paths.identity_path(config.avp.agent_name), "agent identity")
    since_timestamp = None if since is None else parse_utc_timestamp(since)
    until_timestamp = None if until is None else parse_utc_timestamp(until)
    receipt_fetcher = _receipt_fetcher_for_export(
        identity=identity,
        config=config,
        passphrase=passphrase,
        passphrase_file=passphrase_file,
    )
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        bundle = export_evidence_bundle(
            store,
            output_path,
            proxy_identity_did=identity.get("did") if isinstance(identity.get("did"), str) else None,
            trusted_signer_dids=config.avp.trusted_signer_dids,
            client_id=config.avp.agent_name,
            since_timestamp=since_timestamp,
            until_timestamp=until_timestamp,
            request_ids=request_ids,
            receipt_fetcher=receipt_fetcher,
        )
    print(
        "Evidence exported: "
        f"{output_path} ({len(bundle['records'])} records, "
        f"{len(bundle['signed_receipts'])} signed receipts)",
        file=out,
    )
    unverified = int(bundle.get("unverified_receipt_count", 0))
    if unverified:
        print(
            "WARN: "
            f"{unverified} records have decision_audit_id but no matching signed receipt in bundle "
            "(fetch failed or digest mismatch)",
            file=out,
        )
    return bundle


def verify_evidence(
    *,
    bundle_path: Path,
    output_format: str = "human",
    trusted_signer_dids: Iterable[str] | None = None,
    out: TextIO | None = None,
) -> int:
    """Verify an evidence bundle offline (strict, proof-grade).

    Strict verification trusts ONLY the externally pinned ``--trusted-signer-did``
    set; it never falls back to the signer list embedded in the bundle. A bundle
    that carries signed receipts fails closed unless at least one external signer
    DID is supplied, and a referenced-but-missing signed receipt is a hard
    failure rather than a warning.
    """

    out = out or sys.stdout
    explicit_trusted_signers = tuple(trusted_signer_dids or ())
    try:
        result = verify_evidence_bundle_file(
            bundle_path,
            trusted_signer_dids=explicit_trusted_signers,
            strict=True,
        )
    except EvidenceVerificationError as exc:
        if output_format == "json":
            print(
                json.dumps({"status": "invalid", "error": str(exc)}, sort_keys=True),
                file=out,
            )
        else:
            print(f"FAIL: {exc}", file=out)
        return 1
    warnings = list(result.warnings)
    if output_format == "json":
        print(json.dumps({
            "status": "ok",
            "record_count": result.record_count,
            "signed_receipt_count": result.signed_receipt_count,
            "unverified_receipt_count": result.unverified_receipt_count,
            "warnings": warnings,
            "chain_root_hash": result.chain_root_hash,
        }, sort_keys=True), file=out)
    else:
        print(
            "OK: bundle integrity verified, "
            f"{result.record_count} records, {result.signed_receipt_count} signed receipts",
            file=out,
        )
        for warning in warnings:
            print(f"WARN: {warning}", file=out)
    return 0


def _event_timestamp(value: int) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_token(value: Any) -> str:
    if value is None:
        return "-"
    rendered = str(value).replace("\r", " ").replace("\n", " ").strip()
    return rendered[:120] if rendered else "-"


def _receipt_status(record: Any) -> str:
    if record.decision_receipt_sha256:
        return "present"
    if record.decision_audit_id:
        return "missing"
    return "none"


def _format_event_record(record: Any) -> str:
    return (
        f"{_event_timestamp(record.created_at)} "
        f"server={_event_token(record.downstream_server)} "
        f"tool={_event_token(record.tool_name)} "
        f"risk={_event_token(record.risk_class)} "
        f"status={_event_token(record.status)} "
        f"rule={_event_token(record.policy_rule_id)} "
        f"receipt={_receipt_status(record)} "
        f"id={_event_token(record.request_id)}"
    )


def list_events(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    limit: int = DEFAULT_EVENTS_LIMIT,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print a privacy-safe view of recent local evidence records."""

    if limit <= 0:
        raise ProxyCliError("--limit must be positive")
    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        records = store.list_records()
    selected = records[-limit:]
    if output_json:
        _print_json({
            "ok": True,
            "errors": [],
            "warnings": [],
            "downstream": _downstream_info_if_available(paths.config_path),
            "evidence_count": len(records),
            "events": [_event_record_dict(record) for record in selected],
        }, out)
        return len(selected)
    if not selected:
        print("No evidence records", file=out)
        return 0
    for record in selected:
        print(_format_event_record(record), file=out)
    return len(selected)


def tail_events(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    limit: int = DEFAULT_EVENTS_LIMIT,
    follow: bool = False,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print recent evidence records and optionally follow new records."""

    if limit <= 0:
        raise ProxyCliError("--limit must be positive")
    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    printed: set[str] = set()

    def print_new_records(*, initial: bool) -> int:
        with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
            records = store.list_records()
        selected = records[-limit:] if initial else [
            record for record in records if record.request_id not in printed
        ]
        if output_json and not follow:
            _print_json({
                "ok": True,
                "errors": [],
                "warnings": [],
                "downstream": _downstream_info_if_available(paths.config_path),
                "evidence_count": len(records),
                "events": [_event_record_dict(record) for record in selected],
            }, out)
            return len(selected)
        for record in selected:
            if output_json:
                print(json.dumps(_event_record_dict(record), sort_keys=True), file=out)
            else:
                print(_format_event_record(record), file=out)
            printed.add(record.request_id)
        if hasattr(out, "flush"):
            out.flush()
        return len(selected)

    count = print_new_records(initial=True)
    if not follow:
        if count == 0 and not output_json:
            print("No evidence records", file=out)
        return count
    try:
        while True:
            time.sleep(1.0)
            count += print_new_records(initial=False)
    except KeyboardInterrupt:
        return count


def evidence_summary(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> dict[str, Any]:
    """Print aggregate local evidence counts without raw payload details."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        records = store.list_records()
    by_status: dict[str, int] = {}
    receipt_present = 0
    receipt_missing = 0
    for record in records:
        by_status[record.status] = by_status.get(record.status, 0) + 1
        if record.decision_receipt_sha256:
            receipt_present += 1
        elif record.decision_audit_id:
            receipt_missing += 1
    latest = max((record.created_at for record in records), default=None)
    summary = {
        "ok": True,
        "errors": [],
        "warnings": [],
        "downstream": _downstream_info_if_available(paths.config_path),
        "record_count": len(records),
        "evidence_count": len(records),
        "by_status": by_status,
        "receipt_present_count": receipt_present,
        "receipt_missing_count": receipt_missing,
        "latest_record_at": None if latest is None else _event_timestamp(latest),
    }
    print(json.dumps(summary, sort_keys=True), file=out)
    return summary


def vacuum_events(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    max_age_days: int = DEFAULT_EVIDENCE_VACUUM_MAX_AGE_DAYS,
    before: str | None = None,
    out: TextIO | None = None,
) -> int:
    """Prune old terminal evidence records and rebuild the local chain."""

    if max_age_days <= 0:
        raise ProxyCliError("--max-age-days must be positive")
    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    if before is None:
        cutoff = int(datetime.now(timezone.utc).timestamp()) - max_age_days * 24 * 60 * 60
    else:
        cutoff = parse_utc_timestamp(before)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        deleted = store.vacuum_terminal_records(before_timestamp=cutoff)
    print(f"Evidence vacuum deleted {deleted} terminal records", file=out)
    return deleted


def run_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    out: TextIO | None = None,
    client_in: TextIO | None = None,
    err: TextIO | None = None,
    headless: bool = False,
    auto_deny: bool = False,
    headless_policy_path: Path | None = None,
) -> int:
    """Validate readiness and run stdio MCP pass-through."""

    out = out or sys.stdout
    client_in = client_in or sys.stdin
    err = err or sys.stderr
    if auto_deny and not headless:
        raise ProxyCliError(
            "--auto-deny requires --headless; standalone auto-deny conflicts with interactive UI assumption",
            exit_code=2,
        )
    paths = proxy_paths(home, config_path)
    config = load_proxy_config(paths.config_path)
    identity_path = paths.identity_path(config.avp.agent_name)
    identity = _read_json(identity_path, "agent identity")
    identity_passphrase = _resolve_existing_identity_passphrase(
        identity,
        passphrase=passphrase,
        passphrase_file=passphrase_file,
    )
    _load_proxy_agent(identity=identity, config=config, passphrase=identity_passphrase)
    doctor_out = io.StringIO()
    health = doctor_proxy(
        home=paths.home,
        config_path=paths.config_path,
        passphrase=identity_passphrase,
        out=doctor_out,
    )
    if health != 0:
        message = doctor_out.getvalue().strip() or "proxy readiness check failed"
        raise ProxyCliError(message, exit_code=health)
    try:
        downstream = DownstreamConfig.from_proxy_config(config)
        classifier = ToolCallClassifier(config, server_name=downstream.name)
        control_grant_path = paths.control_grant_path(config.avp.agent_name)
        headless_policy = None
        if headless_policy_path is not None:
            try:
                headless_policy = HeadlessPolicy.from_file(headless_policy_path)
            except HeadlessPolicyError as exc:
                raise ProxyCliError(str(exc), exit_code=1) from exc
        evidence_store = ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite")
        approval_server = ApprovalServer()
        approval_server.start()
        approval_manager = ApprovalManager(
            evidence_store=evidence_store,
            approval_server=approval_server,
            config=config,
            client_id=f"{downstream.name}:pid:{os.getpid()}",
            headless=headless,
            auto_deny=auto_deny,
            headless_policy=headless_policy,
            cli_out=err,
            wait_for_decision=False,
        )
        runtime_gate_factory = lambda: RuntimeGateClient.from_files(
            identity_path=identity_path,
            control_grant_path=control_grant_path,
            config=config,
            agent_cls=AVPAgent,
            passphrase=identity_passphrase,
        )
        passthrough = McpPassthrough(
            downstream,
            classifier=classifier,
            runtime_gate_factory=runtime_gate_factory,
            approval_manager=approval_manager,
        )
        previous_handlers = _install_run_proxy_signal_handlers(client_in)
        try:
            return passthrough.run_stdio(client_in, out)
        except _RunProxySignalExit:
            return 0
        finally:
            _restore_signal_handlers(previous_handlers)
            approval_server.stop()
            evidence_store.close()
    except PassthroughError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc


def run_proxy_stub(**kwargs: Any) -> int:
    """Backward-compatible wrapper for the P2 name."""

    return run_proxy(**kwargs)


def _add_common_path_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home", type=Path, default=None, help="AVP home directory (default: ~/.avp)")
    parser.add_argument("--config", type=Path, default=None, help="Proxy config JSON path")


def _add_passphrase_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--passphrase", default=None, help="MCP proxy identity passphrase")
    parser.add_argument("--passphrase-file", type=Path, default=None, help="Read passphrase from file")


def _add_json_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit JSON output")


def _add_downstream_set_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Downstream MCP server name")
    parser.add_argument(
        "--command",
        dest="downstream_command",
        required=True,
        help="Downstream MCP server command",
    )
    parser.add_argument("--arg", action="append", default=None, help="Downstream MCP server arg")
    parser.add_argument("--env", action="append", default=None, help="Downstream env KEY=VALUE")
    parser.add_argument(
        "--env-passthrough",
        action="append",
        default=None,
        help="Environment variable name to forward to downstream",
    )
    parser.add_argument(
        "--response-timeout-seconds",
        type=float,
        default=None,
        help="Downstream JSON-RPC response timeout",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentveil-mcp-proxy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create local proxy identity, config, and control grant")
    _add_common_path_args(init)
    init.add_argument("--base-url", default=DEFAULT_BASE_URL)
    init.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    init.add_argument("--trusted-signer-did", action="append", default=None)
    init.add_argument("--policy-pack", default="default", choices=["default", "github", "filesystem", "shell"])
    init.add_argument(
        "--quickstart-filesystem",
        type=Path,
        default=None,
        help="Configure the built-in filesystem quickstart downstream rooted at this path",
    )
    init.add_argument("--downstream-name", default=None, help="Downstream MCP server name")
    init.add_argument("--downstream-command", default=None, help="Downstream MCP server command")
    init.add_argument("--downstream-arg", action="append", default=None, help="Downstream MCP server arg")
    init.add_argument("--ttl-days", type=int, default=DEFAULT_CONTROL_GRANT_TTL_DAYS)
    init.add_argument("--allowed-category", action="append", default=None)
    _add_passphrase_args(init)
    _add_json_arg(init)
    init.add_argument("--plaintext", action="store_true", help="Store the proxy private key unencrypted")
    init.add_argument("--force", action="store_true")

    doctor = subparsers.add_parser("doctor", help="Validate local proxy config and files")
    _add_common_path_args(doctor)
    _add_passphrase_args(doctor)
    _add_json_arg(doctor)
    doctor.add_argument(
        "--check-backend",
        action="store_true",
        help=(
            "Issue read-only GETs to verify the configured backend is "
            "reachable and the proxy agent is registered."
        ),
    )
    doctor.add_argument(
        "--full",
        action="store_true",
        help="Also launch downstream and verify MCP initialize/tools/list",
    )

    run = subparsers.add_parser("run", help="Run stdio MCP passthrough")
    _add_common_path_args(run)
    _add_passphrase_args(run)
    run.add_argument("--headless", action="store_true", help="Disable browser and OS notification attempts")
    run.add_argument("--auto-deny", action="store_true", help="Deny every approval-required action")
    run.add_argument("--headless-policy", type=Path, default=None, help="Headless approval policy JSON path")

    register = subparsers.add_parser(
        "register",
        help="Register the existing proxy identity with the configured backend",
    )
    _add_common_path_args(register)
    _add_passphrase_args(register)
    _add_json_arg(register)

    configure = subparsers.add_parser(
        "configure-downstream",
        help="Write downstream MCP server config into the proxy config",
    )
    _add_common_path_args(configure)
    _add_downstream_set_args(configure)
    _add_json_arg(configure)

    downstream = subparsers.add_parser("downstream", help="Manage downstream MCP server config")
    downstream_subparsers = downstream.add_subparsers(dest="downstream_action", required=True)
    downstream_set = downstream_subparsers.add_parser(
        "set",
        help="Write downstream MCP server config into the proxy config",
    )
    _add_common_path_args(downstream_set)
    _add_downstream_set_args(downstream_set)
    _add_json_arg(downstream_set)

    smoke = subparsers.add_parser("smoke", help="Launch downstream and verify MCP initialize/tools/list")
    _add_common_path_args(smoke)
    _add_json_arg(smoke)

    reissue = subparsers.add_parser("reissue-grant", help="Issue a fresh local control grant")
    _add_common_path_args(reissue)
    _add_passphrase_args(reissue)
    reissue.add_argument("--ttl-days", type=int, default=DEFAULT_CONTROL_GRANT_TTL_DAYS)
    reissue.add_argument("--force", action="store_true")
    reissue.add_argument("--auto", action="store_true")

    export = subparsers.add_parser("export-evidence", help="Export local evidence bundle")
    _add_common_path_args(export)
    _add_passphrase_args(export)
    export.add_argument("output_path", type=Path)
    export.add_argument("--since", default=None, help="Include records at or after UTC timestamp")
    export.add_argument("--until", default=None, help="Include records at or before UTC timestamp")
    export.add_argument("--request-id", action="append", default=None)

    verify = subparsers.add_parser("verify", help="Verify an evidence bundle offline")
    verify.add_argument("bundle_path", type=Path)
    verify.add_argument("--output", choices=["human", "json"], default="human")
    verify.add_argument("--trusted-signer-did", action="append", default=None)

    summary = subparsers.add_parser("evidence-summary", help="Summarize local evidence records")
    _add_common_path_args(summary)
    _add_json_arg(summary)

    events = subparsers.add_parser("events", help="Manage local evidence records")
    _add_common_path_args(events)
    _add_json_arg(events)
    events.add_argument("events_action", nargs="?", choices=["list", "tail", "vacuum"])
    events.add_argument("--limit", type=int, default=DEFAULT_EVENTS_LIMIT)
    events.add_argument("--follow", action="store_true", help="Keep printing new records for events tail")
    events.add_argument("--vacuum", action="store_true", help="Prune old terminal evidence records")
    events.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_EVIDENCE_VACUUM_MAX_AGE_DAYS,
    )
    events.add_argument("--before", default=None, help="Prune terminal records before UTC timestamp")

    return parser


def _normalize_downstream_arg_values(argv: list[str]) -> list[str]:
    """Let downstream arg flags accept values that look like CLI options."""

    normalized: list[str] = []
    value_flags = {"--arg", "--downstream-arg"}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in value_flags and index + 1 < len(argv):
            normalized.append(f"{item}={argv[index + 1]}")
            index += 2
            continue
        normalized.append(item)
        index += 1
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parse_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(_normalize_downstream_arg_values(parse_argv))
    try:
        if args.command == "init":
            downstream_config = None
            policy_pack = args.policy_pack
            if args.quickstart_filesystem is not None:
                if args.downstream_name or args.downstream_command or args.downstream_arg:
                    raise ProxyCliError(
                        "--quickstart-filesystem cannot be combined with downstream options"
                    )
                downstream_config = quickstart_filesystem_downstream(args.quickstart_filesystem)
                if policy_pack == "default":
                    policy_pack = "filesystem"
            elif args.downstream_command is not None:
                downstream_config = _downstream_config_payload(
                    name=args.downstream_name or "downstream",
                    command=args.downstream_command,
                    args=args.downstream_arg or (),
                )
            elif args.downstream_name or args.downstream_arg:
                raise ProxyCliError("--downstream-command is required with downstream options")
            json_warnings = [PLAINTEXT_WARNING] if args.json_output and args.plaintext else []
            result = init_proxy(
                home=args.home,
                config_path=args.config,
                base_url=args.base_url,
                agent_name=args.agent_name,
                trusted_signer_dids=args.trusted_signer_did,
                policy_pack=policy_pack,
                ttl_days=args.ttl_days,
                allowed_categories=args.allowed_category or DEFAULT_ALLOWED_CATEGORIES,
                downstream_config=downstream_config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                plaintext=args.plaintext,
                err=io.StringIO() if args.json_output else sys.stderr,
                force=args.force,
            )
            if args.json_output:
                config = load_proxy_config(result.config_path)
                _print_json({
                    "ok": True,
                    "errors": [],
                    "warnings": json_warnings,
                    "agent_name": result.agent_name,
                    "agent_did": result.agent_did,
                    "identity_path": str(result.identity_path),
                    "config_path": str(result.config_path),
                    "control_grant_path": str(result.control_grant_path),
                    "control_grant_expires_at": result.control_grant_expires_at,
                    "downstream": _downstream_info(config),
                    "evidence_count": _evidence_count(proxy_paths(args.home, args.config)),
                })
            else:
                print(f"Created MCP proxy identity: {result.agent_did}")
                print(f"Identity: {result.identity_path}")
                print(f"Config: {result.config_path}")
                print(f"Control grant: {result.control_grant_path}")
                print(f"Control grant expires: {result.control_grant_expires_at}")
            return 0
        if args.command == "doctor":
            return doctor_proxy(
                home=args.home,
                config_path=args.config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                check_backend=args.check_backend,
                full=args.full,
                output_json=args.json_output,
            )
        if args.command == "run":
            return run_proxy(
                home=args.home,
                config_path=args.config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                headless=args.headless,
                auto_deny=args.auto_deny,
                headless_policy_path=args.headless_policy,
            )
        if args.command == "register":
            return register_proxy(
                home=args.home,
                config_path=args.config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                output_json=args.json_output,
            )
        if args.command in {"configure-downstream", "downstream"}:
            if args.command == "downstream" and args.downstream_action != "set":
                raise ProxyCliError("downstream action must be set")
            configure_downstream(
                name=args.name,
                command=args.downstream_command,
                args=args.arg or (),
                env_entries=args.env or (),
                env_passthrough=args.env_passthrough or (),
                response_timeout_seconds=args.response_timeout_seconds,
                home=args.home,
                config_path=args.config,
                output_json=args.json_output,
            )
            return 0
        if args.command == "smoke":
            smoke_proxy(
                home=args.home,
                config_path=args.config,
                output_json=args.json_output,
            )
            return 0
        if args.command == "reissue-grant":
            reissue_grant(
                home=args.home,
                config_path=args.config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                ttl_days=args.ttl_days,
                force=args.force,
                auto=args.auto,
            )
            return 0
        if args.command == "export-evidence":
            export_evidence(
                output_path=args.output_path,
                home=args.home,
                config_path=args.config,
                since=args.since,
                until=args.until,
                request_ids=args.request_id,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
            )
            return 0
        if args.command == "verify":
            return verify_evidence(
                bundle_path=args.bundle_path,
                output_format=args.output,
                trusted_signer_dids=args.trusted_signer_did,
            )
        if args.command == "evidence-summary":
            evidence_summary(
                home=args.home,
                config_path=args.config,
                output_json=args.json_output,
            )
            return 0
        if args.command == "events":
            action = args.events_action
            if args.vacuum:
                if action not in {None, "vacuum"}:
                    raise ProxyCliError("--vacuum cannot be combined with events list/tail")
                action = "vacuum"
            if action is None:
                action = "list"
            if action == "list":
                list_events(
                    home=args.home,
                    config_path=args.config,
                    limit=args.limit,
                    output_json=args.json_output,
                )
            elif action == "tail":
                tail_events(
                    home=args.home,
                    config_path=args.config,
                    limit=args.limit,
                    follow=args.follow,
                    output_json=args.json_output,
                )
            elif action == "vacuum":
                vacuum_events(
                    home=args.home,
                    config_path=args.config,
                    max_age_days=args.max_age_days,
                    before=args.before,
                )
            else:
                raise ProxyCliError("events action must be list, tail, or vacuum")
            return 0
    except (ProxyCliError, ApprovalEvidenceError, EvidenceExportError, EvidenceVerificationError) as exc:
        if getattr(args, "json_output", False):
            _print_json({
                "ok": False,
                "errors": [str(exc)],
                "warnings": [],
                "downstream": None,
                "evidence_count": None,
            })
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, ProxyCliError) else 1
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
