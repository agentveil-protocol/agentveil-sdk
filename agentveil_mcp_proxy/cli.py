"""Minimal CLI for the MCP proxy.

The CLI creates encrypted local proxy identities by default, manages the
control grant used by Runtime Gate, and runs stdio passthrough for configured
downstream MCP servers. Approval-required calls can route through the local
approval surface and durable evidence store. Circuit breaking remains a future
slice.
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
from typing import Any, Iterable, Mapping, TextIO

from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import DelegationInvalid, verify_delegation
from agentveil_mcp_proxy.approval import (
    ApprovalManager,
    ApprovalServer,
    HeadlessPolicy,
    HeadlessPolicyError,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceStore,
    EvidenceExportError,
    EvidenceVerificationError,
    export_evidence_bundle,
    parse_utc_timestamp,
    verify_evidence_bundle_file,
)
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
DEFAULT_ALLOWED_CATEGORIES = ("mcp_proxy",)
DEFAULT_EVIDENCE_VACUUM_MAX_AGE_DAYS = 90
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


def _read_passphrase_file(path: Path) -> str:
    try:
        value = path.expanduser().read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ProxyCliError(f"passphrase file unavailable: {path}", exit_code=1) from exc
    if not value:
        raise ProxyCliError("passphrase file is empty")
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
        return resolved

    if sys.stdin.isatty():
        first = getpass.getpass("MCP proxy identity passphrase: ")
        if not first:
            raise ProxyCliError("passphrase must not be empty")
        second = getpass.getpass("Confirm MCP proxy identity passphrase: ")
        if first != second:
            raise ProxyCliError("passphrases do not match")
        return first

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


def doctor_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
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
        warnings = []
        if not config.avp.trusted_signer_dids:
            failures.append("trusted signer DID set is empty")
        if not _owner_only(identity_path):
            failures.append(f"agent identity permissions must be 0600: {identity_path}")
        if not _owner_only(grant_path):
            failures.append(f"control grant permissions must be 0600: {grant_path}")
        if identity.get("did") is None:
            failures.append("agent identity missing DID")
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

        if failures:
            for failure in failures:
                print(f"FAIL: {failure}", file=out)
            return 1

        print(f"OK: config {paths.config_path}", file=out)
        print(f"OK: identity {identity_path}", file=out)
        print(f"OK: control grant {grant_path}", file=out)
        print(f"OK: trusted signers {len(config.avp.trusted_signer_dids)}", file=out)
        for warning in warnings:
            print(f"WARN: {warning}", file=out)
        return 0
    except ProxyCliError as exc:
        print(f"FAIL: {exc}", file=out)
        return 1


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
    return bundle


def verify_evidence(
    *,
    bundle_path: Path,
    output_format: str = "human",
    trusted_signer_dids: Iterable[str] | None = None,
    out: TextIO | None = None,
) -> int:
    """Verify an evidence bundle offline."""

    out = out or sys.stdout
    result = verify_evidence_bundle_file(
        bundle_path,
        trusted_signer_dids=trusted_signer_dids,
    )
    if output_format == "json":
        print(json.dumps({
            "status": "ok",
            "record_count": result.record_count,
            "signed_receipt_count": result.signed_receipt_count,
            "chain_root_hash": result.chain_root_hash,
        }, sort_keys=True), file=out)
    else:
        print(
            "OK: bundle integrity verified, "
            f"{result.record_count} records, {result.signed_receipt_count} signed receipts",
            file=out,
        )
    return 0


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
        err.write(doctor_out.getvalue())
        err.flush()
        return health
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
    _add_passphrase_args(init)
    init.add_argument("--plaintext", action="store_true", help="Store the proxy private key unencrypted")
    init.add_argument("--force", action="store_true")

    doctor = subparsers.add_parser("doctor", help="Validate local proxy config and files")
    _add_common_path_args(doctor)
    _add_passphrase_args(doctor)

    run = subparsers.add_parser("run", help="Run stdio MCP passthrough")
    _add_common_path_args(run)
    _add_passphrase_args(run)
    run.add_argument("--headless", action="store_true", help="Disable browser and OS notification attempts")
    run.add_argument("--auto-deny", action="store_true", help="Deny every approval-required action")
    run.add_argument("--headless-policy", type=Path, default=None, help="Headless approval policy JSON path")

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

    events = subparsers.add_parser("events", help="Manage local evidence records")
    _add_common_path_args(events)
    events.add_argument("--vacuum", action="store_true", help="Prune old terminal evidence records")
    events.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_EVIDENCE_VACUUM_MAX_AGE_DAYS,
    )
    events.add_argument("--before", default=None, help="Prune terminal records before UTC timestamp")

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
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                plaintext=args.plaintext,
                err=sys.stderr,
                force=args.force,
            )
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
        if args.command == "events":
            if not args.vacuum:
                raise ProxyCliError("events requires --vacuum", exit_code=2)
            vacuum_events(
                home=args.home,
                config_path=args.config,
                max_age_days=args.max_age_days,
                before=args.before,
            )
            return 0
    except (ProxyCliError, EvidenceExportError, EvidenceVerificationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, ProxyCliError) else 1
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
