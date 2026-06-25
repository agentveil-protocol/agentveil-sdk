"""Minimal CLI for the MCP proxy.

The CLI creates encrypted local proxy identities by default, manages the
control grant used by Runtime Gate, and runs stdio passthrough for configured
downstream MCP servers. Approval-required calls can route through the local
approval surface and durable evidence store. Runtime Gate calls use an
in-memory circuit breaker for sustained backend failures.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
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
from agentveil_mcp_proxy.approval.client import resolve_approval_server
from agentveil_mcp_proxy.approval.persistent import (
    PersistentApprovalCenterError,
    build_manifest_for_server,
    create_persistent_server,
    save_manifest,
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
    ApprovalUiOpenMode,
    PolicyConfig,
    ProxyConfig,
    ProxyConfigError,
    builtin_policy_pack,
)
from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_SETUP_PROFILE,
    build_product_route_downstream_config,
    build_product_route_policy,
    initialize_product_route_profile,
)
from agentveil_mcp_proxy.client_config import (
    CLIENT_TARGETS,
    ClientConfigError,
    DEFAULT_SERVER_NAME,
    assert_proxy_cli_json_is_privacy_safe,
    bounded_path_ref,
    build_run_args,
    format_client_config_json_payload,
    format_client_config_text,
    read_role_preset_from_config,
    render_client_configs,
    resolve_proxy_command,
    sanitize_json_paths,
)
from agentveil_mcp_proxy.client_doctor import (
    ClientDoctorError,
    build_client_doctor_report,
    format_client_doctor_report,
)
from agentveil_mcp_proxy.client_guidance import (
    build_client_guidance_payload,
    build_client_guidance_set_payload,
    format_client_guidance_text,
)
from agentveil_mcp_proxy.client_packs import (
    CLIENT_PACK_IDS,
    ClientPackError,
    build_client_packs_payload,
)
from agentveil_mcp_proxy.client_runtime import (
    ClientRuntimeError,
    build_client_runtime_payload,
    format_client_runtime_payload,
)
from agentveil_mcp_proxy.client_connect import (
    ALL_CLIENTS_TARGET,
    ClientConnectError,
    build_connect_all_payload,
    build_connect_payload,
    build_connect_status_all_payload,
    build_connect_status_payload,
    build_disconnect_all_payload,
    build_disconnect_payload,
    format_connect_payload,
    is_connect_all_target,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough, PassthroughError
from agentveil_mcp_proxy.agent_templates import (
    AGENT_TEMPLATE_NAMES,
    AgentTemplateError,
    build_agent_template_report,
    build_template_commands,
    format_agent_template_text,
)
from agentveil_mcp_proxy.config_wizard import (
    ConfigWizardError,
    assert_setup_output_is_privacy_safe,
    build_safe_config_wizard_result,
    build_wizard_summary,
    derive_setup_status,
    format_safe_config_wizard_output,
    format_setup_error_payload,
    load_mcp_client_document,
    load_tool_inventory_file,
    restore_setup_files,
    run_setup_wizard,
    setup_restore_to_dict,
    setup_status_to_dict,
    validate_mcp_client_document,
)
from agentveil_mcp_proxy.control_surface import (
    ControlSurfaceError,
    build_control_status,
    build_control_timeline,
    format_control_status_human,
    format_control_timeline_human,
)
from agentveil_mcp_proxy.permission_doctor import (
    PermissionDoctorError,
    build_permission_doctor_report,
    format_permission_doctor_report,
)
from agentveil_mcp_proxy.role_doctor import (
    build_role_doctor_report,
    format_role_doctor_report,
)
from agentveil_mcp_proxy.role_presets import (
    ADVANCED_ROLE_SETUP_PROFILE,
    ROLE_PRESET_NAMES,
    RolePresetError,
    apply_env_role_override_to_config,
    apply_role_preset_to_config_payload,
    init_setup_profile,
    resolve_init_role_preset,
    resolve_role_preset,
    user_facing_setup_label,
)
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


def _print_operator_json(payload: Mapping[str, Any], out: TextIO | None = None) -> None:
    assert_proxy_cli_json_is_privacy_safe(payload)
    _print_json(payload, out)


def _artifact_refs(
    *,
    identity_path: Path,
    config_path: Path,
    control_grant_path: Path,
) -> dict[str, dict[str, str | None]]:
    return {
        "identity_ref": bounded_path_ref(identity_path),
        "config_ref": bounded_path_ref(config_path),
        "control_grant_ref": bounded_path_ref(control_grant_path),
    }


def _bound_downstream_payload(downstream: Mapping[str, Any]) -> dict[str, Any]:
    if not downstream.get("configured"):
        return dict(downstream)
    bounded = dict(downstream)
    command = str(bounded.get("command") or "")
    if command:
        ref = bounded_path_ref(command)
        bounded["command"] = ref["basename"] or command
    if "args" in bounded:
        bounded["args"] = sanitize_json_paths(list(bounded.get("args") or []))
    return bounded


def _downstream_info_bounded(config: ProxyConfig) -> dict[str, Any]:
    return _bound_downstream_payload(_downstream_info(config))


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


def _bounded_downstream_info_if_available(config_path: Path) -> dict[str, Any] | None:
    from agentveil_mcp_proxy.evidence.summary import bounded_downstream_info

    try:
        return bounded_downstream_info(load_proxy_config(config_path))
    except ProxyCliError:
        return None


def _stored_passphrase_file(config: ProxyConfig | None) -> Path | None:
    if config is None or not config.identity_passphrase_file:
        return None
    return Path(config.identity_passphrase_file).expanduser()


def _effective_passphrase_file(
    *,
    explicit_passphrase: str | None,
    explicit_passphrase_file: Path | None,
    config: ProxyConfig | None,
) -> Path | None:
    if explicit_passphrase is not None or explicit_passphrase_file is not None:
        return explicit_passphrase_file
    if os.environ.get("AVP_PROXY_PASSPHRASE"):
        return None
    return _stored_passphrase_file(config)


def _event_record_dict(
    record: Any,
    *,
    execution_record_id: str | None = None,
) -> dict[str, Any]:
    from agentveil_mcp_proxy.evidence.observability import event_record_dict

    payload = event_record_dict(record, execution_record_id=execution_record_id)
    payload["timestamp"] = _event_timestamp(record.created_at)
    payload["receipt"] = _receipt_status(record)
    return payload


def _execution_record_ids_by_parent(records: list[Any]) -> dict[str, str]:
    from agentveil_mcp_proxy.evidence.observability import execution_record_id_by_parent

    return execution_record_id_by_parent(records)


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
    role_preset: str,
    setup_profile: str | None = ADVANCED_ROLE_SETUP_PROFILE,
    downstream_config: Mapping[str, Any] | None = None,
    identity_passphrase_file: Path | None = None,
) -> dict[str, Any]:
    policy = (
        build_product_route_policy()
        if policy_pack == "product_route"
        else builtin_policy_pack(policy_pack)
    )
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
            "ui_open_mode": "browser",
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
    if identity_passphrase_file is not None:
        payload["identity_passphrase_file"] = str(identity_passphrase_file.expanduser())
    if setup_profile is not None:
        payload["setup_profile"] = setup_profile
    if setup_profile != PRODUCT_ROUTE_SETUP_PROFILE:
        payload = apply_role_preset_to_config_payload(payload, preset_name=role_preset)
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
    role_preset: str = "implementer",
    setup_profile: str | None = ADVANCED_ROLE_SETUP_PROFILE,
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

    try:
        preset = resolve_role_preset(role_preset)
    except RolePresetError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc

    config_payload = _build_config_payload(
        base_url=base_url,
        agent_name=agent_name,
        trusted_signer_dids=signers,
        policy_pack=policy_pack,
        role_preset=preset.name,
        setup_profile=setup_profile,
        downstream_config=downstream_config,
        identity_passphrase_file=passphrase_file if not plaintext else None,
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
    server_path = Path(__file__).with_name("quickstart_filesystem.py")
    return _downstream_config_payload(
        name="filesystem",
        command=sys.executable,
        args=(str(server_path), str(sandbox)),
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
        config = ProxyConfig.from_dict(data)
    except ProxyConfigError as exc:
        raise ProxyCliError(f"proxy config invalid: {exc}", exit_code=1) from exc
    try:
        return apply_env_role_override_to_config(config)
    except RolePresetError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc


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
    downstream = _downstream_info_bounded(config)
    downstream["tool_count"] = result.tool_count
    if output_json:
        _print_operator_json({
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
        effective_passphrase_file = _effective_passphrase_file(
            explicit_passphrase=passphrase,
            explicit_passphrase_file=passphrase_file,
            config=config,
        )
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
            failures.append(f"agent identity permissions must be 0600: {identity_path.name}")
        if not _owner_only(grant_path):
            failures.append(f"control grant permissions must be 0600: {grant_path.name}")
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
                passphrase_file=effective_passphrase_file,
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
                _print_operator_json({
                    "ok": False,
                    "errors": failures,
                    "warnings": warnings,
                    "downstream": _downstream_info_bounded(config) if config.downstream else downstream,
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
            _print_operator_json({
                "ok": True,
                "errors": [],
                "warnings": warnings,
                "downstream": _bound_downstream_payload(downstream),
                "backend": {"checked": check_backend, "ok": backend_ok},
                "evidence_count": _evidence_count(paths),
                **_artifact_refs(
                    identity_path=identity_path,
                    config_path=paths.config_path,
                    control_grant_path=grant_path,
                ),
                "trusted_signer_count": len(config.avp.trusted_signer_dids),
            }, out)
        else:
            print(f"OK: config {paths.config_path.name}", file=out)
            print(f"OK: identity {identity_path.name}", file=out)
            print(f"OK: control grant {grant_path.name}", file=out)
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


def print_agent_templates(
    *,
    template_id: str | None = None,
    home: Path | None = None,
    sandbox_root: Path | None = None,
    proxy_command: str | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print copy-paste runnable starter commands for review/build/readonly agents."""

    sink = out or sys.stdout
    resolved_command = resolve_proxy_command(proxy_command)
    try:
        if output_json:
            payload = build_agent_template_report(
                template_id=template_id,
                home=home,
                sandbox_root=sandbox_root,
                proxy_command=resolved_command,
            )
            _print_json({"ok": True, **payload}, sink)
            return 0
        if template_id is not None:
            plan = build_template_commands(
                template_id,
                home=home,
                sandbox_root=sandbox_root,
                proxy_command=resolved_command,
            )
            sink.write(format_agent_template_text(plan, proxy_command=resolved_command))
            return 0
        for name in AGENT_TEMPLATE_NAMES:
            plan = build_template_commands(
                name,
                home=home,
                sandbox_root=sandbox_root,
                proxy_command=resolved_command,
            )
            sink.write(format_agent_template_text(plan, proxy_command=resolved_command))
            sink.write("\n")
        return 0
    except AgentTemplateError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc


def print_config_wizard(
    *,
    template_id: str,
    home: Path,
    sandbox_root: Path,
    client_id: str = "cursor",
    server_name: str = DEFAULT_SERVER_NAME,
    proxy_command: str | None = None,
    ensure_initialized: bool = False,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Generate and validate proxy-routed MCP client config for one agent template."""

    sink = out or sys.stdout
    try:
        result = build_safe_config_wizard_result(
            template_id,
            home=home,
            sandbox_root=sandbox_root,
            client_id=client_id,
            server_name=server_name,
            proxy_command=proxy_command,
            ensure_initialized=ensure_initialized,
        )
    except ConfigWizardError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc

    if output_json:
        _print_json({
            "ok": True,
            "dry_run": True,
            "writes_user_config": False,
            "summary": build_wizard_summary(result),
            "clients": result.rendered,
        }, sink)
        return 0

    sink.write(format_safe_config_wizard_output(result))
    return 0


def run_setup_wizard_cli(
    *,
    home: Path,
    inventory_path: Path,
    mode: str = "review",
    overlays: list[str] | None = None,
    client_id: str = "cursor",
    server_name: str = DEFAULT_SERVER_NAME,
    proxy_command: str | None = None,
    agent_name: str = "adaptive-setup",
    trusted_signer_did: str = "did:key:z6MktrustedSigner",
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Run adaptive setup and write proxy/client config with backup."""

    sink = out or sys.stdout
    try:
        inventory = load_tool_inventory_file(inventory_path)
        result = run_setup_wizard(
            home=home,
            inventory=inventory,
            requested_mode=mode,
            overlays=tuple(overlays or ()),
            client_id=client_id,
            server_name=server_name,
            proxy_command=proxy_command,
            agent_name=agent_name,
            trusted_signer_did=trusted_signer_did,
        )
        payload = {
            "ok": result.ok,
            "setup_status": result.setup_status,
            "summary": result.summary,
            "proxy_config_written": result.proxy_config_written,
            "client_config_written": result.client_config_written,
            "backup_refs": [
                {
                    "basename": ref.basename,
                    "hash": f"sha256:{ref.hash}" if ref.hash else "",
                    "created_at": ref.created_at,
                }
                for ref in result.backup_refs
            ],
            "errors": list(result.errors),
        }
        assert_setup_output_is_privacy_safe(payload)
    except ConfigWizardError as exc:
        error_payload = format_setup_error_payload(exc)
        assert_setup_output_is_privacy_safe(error_payload)
        if output_json:
            _print_json(error_payload, sink)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if output_json:
        _print_json(payload, sink)
    else:
        sink.write(f"Setup status: {result.setup_status}\n")
        sink.write(f"Proxy config written: {result.proxy_config_written}\n")
        sink.write(f"Client config written: {result.client_config_written}\n")
        for line in result.summary.get("summary_lines", ()):
            sink.write(f"{line}\n")
        for error in result.errors:
            sink.write(f"ERROR: {error}\n")
    return 0 if result.ok or result.setup_status == "incomplete" else 2


def print_setup_status_cli(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_command: str | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print structured setup status derived from actual config files."""

    sink = out or sys.stdout
    status = derive_setup_status(
        home=home,
        client_id=client_id,
        proxy_command=proxy_command,
        proxy_config_path=config_path,
    )
    payload = setup_status_to_dict(status)
    assert_setup_output_is_privacy_safe(payload)
    if output_json:
        _print_json(payload, sink)
    else:
        for key, value in payload.items():
            sink.write(f"{key}={value}\n")
    return 0


def print_control_status_cli(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_command: str | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print daily control status derived from setup files and evidence."""

    sink = out or sys.stdout
    payload = build_control_status(
        home=home,
        client_id=client_id,
        proxy_config_path=config_path,
        proxy_command=proxy_command,
    )
    if output_json:
        _print_json(payload, sink)
    else:
        sink.write(format_control_status_human(payload))
        sink.write("\n")
    return 0 if payload.get("ok", True) else 2


def print_control_timeline_cli(
    *,
    home: Path,
    config_path: Path | None = None,
    limit: int = 20,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print daily control timeline derived from durable evidence records."""

    sink = out or sys.stdout
    payload = build_control_timeline(
        home=home,
        proxy_config_path=config_path,
        limit=limit,
    )
    if output_json:
        _print_json(payload, sink)
    else:
        sink.write(format_control_timeline_human(payload))
        sink.write("\n")
    return 0


def print_permission_doctor_cli(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_command: str | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print permission doctor setup mode and blast-radius boundaries."""

    sink = out or sys.stdout
    payload = build_permission_doctor_report(
        home=home,
        client_id=client_id,
        proxy_command=proxy_command,
        proxy_config_path=config_path,
    )
    if output_json:
        _print_json(payload, sink)
    else:
        sink.write(format_permission_doctor_report(payload))
        sink.write("\n")
    return 0 if payload.get("ok", True) else 2


def restore_setup_cli(
    *,
    home: Path,
    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    target: str = "all",
    client_id: str = "cursor",
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Restore setup-managed config files from backups."""

    sink = out or sys.stdout
    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    if target not in {"proxy", "client", "all"}:
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        raise ProxyCliError("restore target must be one of: proxy, client, all", exit_code=2)
    result = restore_setup_files(home=home, target=target, client_id=client_id)
    payload = setup_restore_to_dict(result)
    assert_setup_output_is_privacy_safe(payload)
    if output_json:
        _print_json(payload, sink)
    else:
        for target_name in result.restored_targets:
            sink.write(f"restored: {target_name}\n")
        for error in result.errors:
            sink.write(f"ERROR: {error}\n")
    return 0 if result.ok else 2


def validate_config_wizard(
    *,
    input_path: Path,
    proxy_command: str | None = None,
    config_path: Path | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Validate an MCP client config file routes configured tools through the proxy."""

    sink = out or sys.stdout
    try:
        document = load_mcp_client_document(input_path)
        resolved_proxy_command = resolve_proxy_command(proxy_command)
        validation = validate_mcp_client_document(
            document,
            proxy_command=resolved_proxy_command,
            config_path=config_path,
        )
    except ConfigWizardError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc

    if not validation.ok:
        message = "; ".join(validation.issues)
        if output_json:
            _print_json({
                "ok": False,
                "errors": [message],
                "bypass_detected": validation.bypass_detected,
                "guidance": validation.guidance,
            }, sink)
        else:
            print(f"FAIL: {message}", file=sink)
            if validation.guidance:
                print(f"GUIDANCE: {validation.guidance}", file=sink)
        return 2

    payload = {
        "ok": True,
        "bypass_detected": False,
        "proxy_routed": True,
        "input_path": str(input_path.expanduser()),
        "proxy_command": resolved_proxy_command,
    }
    if config_path is not None:
        payload["config_path"] = str(config_path.expanduser())
    if output_json:
        _print_json(payload, sink)
    else:
        print(f"OK: MCP client config routes through {resolved_proxy_command}", file=sink)
    return 0


def explain_role_proxy(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    preset: str | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print bounded role doctor guidance for one preset or the preset set."""

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    selected_preset = preset
    if selected_preset is None:
        selected_preset = read_role_preset_from_config(paths.config_path)
    try:
        report = build_role_doctor_report(preset_name=selected_preset)
    except RolePresetError as exc:
        raise ProxyCliError(str(exc)) from exc
    if output_json:
        _print_json({"ok": True, "role_doctor": report}, out)
    else:
        print(format_role_doctor_report(report), file=out)
    return 0


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

    from agentveil_mcp_proxy.evidence.verify_output import (
        VERIFY_FAILED_UNEXPECTED,
        build_verify_failure_payload,
        build_verify_success_payload,
        bundle_parse_summary,
        classify_verify_error,
        reason_code_for_error,
        render_verify_human,
    )

    out = out or sys.stdout
    explicit_trusted_signers = tuple(
        did for did in (trusted_signer_dids or ()) if isinstance(did, str) and did
    )
    parse_summary = bundle_parse_summary(bundle_path)
    try:
        result = verify_evidence_bundle_file(
            bundle_path,
            trusted_signer_dids=explicit_trusted_signers,
            strict=True,
        )
    except EvidenceVerificationError as exc:
        contract = classify_verify_error(exc)
        payload = build_verify_failure_payload(
            contract=contract,
            parse_summary=parse_summary,
            trusted_signer_dids=explicit_trusted_signers,
            reason_code=reason_code_for_error(exc),
        )
        if output_format == "json":
            print(json.dumps(payload, sort_keys=True), file=out)
        else:
            print(render_verify_human(payload), file=out)
        return 1
    except Exception:
        payload = build_verify_failure_payload(
            contract=VERIFY_FAILED_UNEXPECTED,
            parse_summary=parse_summary,
            trusted_signer_dids=explicit_trusted_signers,
            reason_code="verification_failed",
        )
        if output_format == "json":
            print(json.dumps(payload, sort_keys=True), file=out)
        else:
            print(render_verify_human(payload), file=out)
        return 1
    payload = build_verify_success_payload(
        result=result,
        parse_summary=parse_summary,
        trusted_signer_dids=explicit_trusted_signers,
    )
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True), file=out)
    else:
        print(render_verify_human(payload), file=out)
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


def _format_event_record(
    record: Any,
    *,
    execution_record_id: str | None = None,
) -> str:
    from agentveil_mcp_proxy.evidence.observability import format_event_record

    return format_event_record(
        record,
        receipt_status=_receipt_status(record),
        execution_record_id=execution_record_id,
        timestamp_formatter=_event_timestamp,
        token_formatter=_event_token,
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
    execution_by_parent = _execution_record_ids_by_parent(records)
    if output_json:
        _print_json({
            "ok": True,
            "errors": [],
            "warnings": [],
            "downstream": _bounded_downstream_info_if_available(paths.config_path),
            "evidence_count": len(records),
            "events": [
                _event_record_dict(
                    record,
                    execution_record_id=execution_by_parent.get(record.request_id),
                )
                for record in selected
            ],
        }, out)
        return len(selected)
    if not selected:
        print("No evidence records", file=out)
        return 0
    for record in selected:
        print(
            _format_event_record(
                record,
                execution_record_id=execution_by_parent.get(record.request_id),
            ),
            file=out,
        )
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
        execution_by_parent = _execution_record_ids_by_parent(records)
        if output_json and not follow:
            _print_json({
                "ok": True,
                "errors": [],
                "warnings": [],
                "downstream": _bounded_downstream_info_if_available(paths.config_path),
                "evidence_count": len(records),
                "events": [
                    _event_record_dict(
                        record,
                        execution_record_id=execution_by_parent.get(record.request_id),
                    )
                    for record in selected
                ],
            }, out)
            return len(selected)
        for record in selected:
            execution_record_id = execution_by_parent.get(record.request_id)
            if output_json:
                print(
                    json.dumps(
                        _event_record_dict(
                            record,
                            execution_record_id=execution_record_id,
                        ),
                        sort_keys=True,
                    ),
                    file=out,
                )
            else:
                print(
                    _format_event_record(
                        record,
                        execution_record_id=execution_record_id,
                    ),
                    file=out,
                )
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

    from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceError
    from agentveil_mcp_proxy.evidence.summary import (
        bounded_evidence_summary_error,
        build_evidence_summary,
    )
    import sqlite3

    out = out or sys.stdout
    paths = proxy_paths(home, config_path)
    try:
        with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
            records = store.list_records()
    except (ApprovalEvidenceError, OSError, ValueError, sqlite3.Error):
        summary = bounded_evidence_summary_error(code="evidence_store_unavailable")
        print(json.dumps(summary, sort_keys=True), file=out)
        return summary
    latest = max((record.created_at for record in records), default=None)
    downstream = _bounded_downstream_info_if_available(paths.config_path)
    if downstream is None:
        downstream = {"configured": False}
    summary = build_evidence_summary(
        records,
        downstream=downstream,
        latest_record_at=None if latest is None else _event_timestamp(latest),
    )
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


def serve_approval_center(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    port: int = 0,
    err: TextIO | None = None,
) -> int:
    """Run the stable local Approval Center for any MCP client turn."""

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
    proxy_agent = _load_proxy_agent(
        identity=identity,
        config=config,
        passphrase=identity_passphrase,
    )
    evidence_store = ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite")
    try:
        approval_server = create_persistent_server(
            proxy_dir=paths.proxy_dir,
            evidence_store=evidence_store,
            port=port,
        )
    except PersistentApprovalCenterError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc
    try:
        approval_grant_private_key_seed = bytes.fromhex(proxy_agent.private_key_hex)
    except (AttributeError, TypeError, ValueError):
        approval_grant_private_key_seed = None
    approval_grant_agent_did = getattr(proxy_agent, "did", None)
    if not isinstance(approval_grant_agent_did, str):
        approval_grant_agent_did = None
    downstream_name = DownstreamConfig.from_proxy_config(config).name
    approval_manager = ApprovalManager(
        evidence_store=evidence_store,
        approval_server=approval_server,
        config=config,
        client_id=f"{downstream_name}:approval-center",
        headless=True,
        cli_out=err,
        wait_for_decision=False,
        approval_grant_private_key_seed=approval_grant_private_key_seed,
        approval_grant_agent_did=approval_grant_agent_did,
    )
    _ = approval_manager
    save_manifest(paths.proxy_dir, build_manifest_for_server(approval_server))
    print(
        f"Approval Center: {approval_server.approval_center_url()}",
        file=err,
    )
    stop_event = threading.Event()

    def _request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    previous_handlers: dict[int, Any] | None = None
    if threading.current_thread() is threading.main_thread():
        previous_handlers = {
            signal.SIGINT: signal.signal(signal.SIGINT, _request_stop),
            signal.SIGTERM: signal.signal(signal.SIGTERM, _request_stop),
        }
    try:
        stop_event.wait()
        return 0
    finally:
        if previous_handlers is not None:
            signal.signal(signal.SIGINT, previous_handlers[signal.SIGINT])
            signal.signal(signal.SIGTERM, previous_handlers[signal.SIGTERM])
        approval_server.stop()
        evidence_store.close()


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
    approval_ui_mode: str | None = None,
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
    if approval_ui_mode is not None:
        try:
            ui_mode = ApprovalUiOpenMode(approval_ui_mode)
        except ValueError as exc:
            raise ProxyCliError(
                "approval UI mode must be one of: browser, terminal, none",
                exit_code=2,
            ) from exc
        config = replace(
            config,
            approval=replace(config.approval, ui_open_mode=ui_mode),
        )
    identity_path = paths.identity_path(config.avp.agent_name)
    identity = _read_json(identity_path, "agent identity")
    identity_passphrase = _resolve_existing_identity_passphrase(
        identity,
        passphrase=passphrase,
        passphrase_file=passphrase_file,
    )
    proxy_agent = _load_proxy_agent(
        identity=identity,
        config=config,
        passphrase=identity_passphrase,
    )
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

        def _start_ephemeral_approval_server() -> ApprovalServer:
            server = ApprovalServer()
            server.start()
            return server

        approval_server = resolve_approval_server(
            paths.proxy_dir,
            evidence_store=evidence_store,
            fallback_factory=_start_ephemeral_approval_server,
        )
        try:
            approval_grant_private_key_seed = bytes.fromhex(proxy_agent.private_key_hex)
        except (AttributeError, TypeError, ValueError):
            approval_grant_private_key_seed = None
        approval_grant_agent_did = getattr(proxy_agent, "did", None)
        if not isinstance(approval_grant_agent_did, str):
            approval_grant_agent_did = None
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
            approval_grant_private_key_seed=approval_grant_private_key_seed,
            approval_grant_agent_did=approval_grant_agent_did,
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
            if getattr(approval_server, "owns_server_process", True):
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
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit structured JSON (see command help for privacy vs runnable surfaces)",
    )


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


def print_client_configs(
    *,
    clients: list[str],
    server_name: str = DEFAULT_SERVER_NAME,
    command: str | None = None,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    output_json: bool = False,
    out: TextIO | None = None,
) -> None:
    """Print copy-paste MCP client config without writing desktop config files."""

    sink = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config: ProxyConfig | None = None
    try:
        config = load_proxy_config(paths.config_path)
    except ProxyCliError:
        config = None
    effective_passphrase_file = (
        passphrase_file if passphrase_file is not None else _stored_passphrase_file(config)
    )
    try:
        rendered = render_client_configs(
            clients=clients,
            server_name=server_name,
            command=command,
            home=home,
            config_path=config_path,
            passphrase_file=effective_passphrase_file,
        )
        resolved_command = resolve_proxy_command(command)
        run_args = build_run_args(
            home=home,
            config_path=config_path,
            passphrase_file=effective_passphrase_file,
        )
    except ClientConfigError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc

    if output_json:
        preset = config.role_preset if config is not None else None
        downstream_payload = dict(config.downstream) if config is not None and config.downstream else None
        payload = format_client_config_json_payload(
            rendered,
            command=resolved_command,
            run_args=run_args,
            config_path=config_path,
            home=home,
            role_preset=preset,
            downstream=downstream_payload,
        )
        _print_json(payload, out=sink)
        return

    sink.write(format_client_config_text(rendered))


def print_client_packs_cli(
    *,
    clients: list[str] | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print bounded metadata for client compatibility packs."""

    sink = out or sys.stdout
    try:
        payload = build_client_packs_payload(client_ids=clients)
    except ClientPackError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
        return 0
    lines = ["AgentVeil client compatibility packs", ""]
    for client_id, pack in payload["packs"].items():
        lines.extend([
            f"{pack['display_name']} ({client_id})",
            f"  support_status: {pack['support_status']}",
            f"  config_surface: {pack['config_surface']}",
            f"  guidance: {pack['guidance_summary']}",
            "",
        ])
    sink.write("\n".join(lines))
    return 0


def print_client_guidance_cli(
    *,
    clients: list[str] | None = None,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Print bounded action-routing guidance for one or more client packs."""

    sink = out or sys.stdout
    selected = clients or list(CLIENT_PACK_IDS)
    try:
        if len(selected) == 1:
            payload = build_client_guidance_payload(client_id=selected[0])
            if output_json:
                _print_json(payload, out=sink)
                return 0
            sink.write(format_client_guidance_text(payload))
            return 0
        payload = build_client_guidance_set_payload(client_ids=selected)
    except ClientPackError as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
        return 0
    blocks: list[str] = []
    for client_payload in payload["clients"].values():
        blocks.append(format_client_guidance_text(client_payload))
    sink.write("\n".join(blocks))
    return 0


def run_client_doctor_cli(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    list_only: bool = False,
    out: TextIO | None = None,
    output_json: bool = False,
) -> int:
    """Run optional client-pack health check through generated config + proxy path proof."""

    sink = out or sys.stdout
    paths = proxy_paths(home, config_path)
    config: ProxyConfig | None = None
    try:
        config = load_proxy_config(paths.config_path)
    except ProxyCliError:
        config = None
    effective_passphrase_file = (
        passphrase_file if passphrase_file is not None else _stored_passphrase_file(config)
    )
    try:
        payload = build_client_doctor_report(
            client_id=client_id,
            home=paths.home,
            config_path=paths.config_path,
            passphrase_file=effective_passphrase_file,
            proxy_command=proxy_command,
            list_only=list_only,
        )
    except (ClientDoctorError, ClientPackError) as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
    else:
        sink.write(format_client_doctor_report(payload))
    return 0 if payload.get("ok") else 1


def run_client_run_cli(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    launch: bool = False,
    prompt: str | None = None,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    sink = out or sys.stdout
    home_path = home or Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
    try:
        payload = build_client_runtime_payload(
            client_id=client_id,
            home=home_path,
            config_path=config_path,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
            launch=launch,
            prompt=prompt,
            cwd=Path.cwd(),
        )
    except (ClientRuntimeError, ClientConfigError, ClientPackError) as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
    else:
        sink.write(format_client_runtime_payload(payload))
    return 0


def run_connect_cli(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    sink = out or sys.stdout
    home_path = home or Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
    try:
        if is_connect_all_target(client_id):
            payload = build_connect_all_payload(
                home=home_path,
                config_path=config_path,
                passphrase_file=passphrase_file,
                proxy_command=proxy_command,
                server_name=server_name,
                project_root=project_root,
                write=write,
            )
        else:
            payload = build_connect_payload(
                client_id=client_id,
                home=home_path,
                config_path=config_path,
                passphrase_file=passphrase_file,
                proxy_command=proxy_command,
                server_name=server_name,
                project_root=project_root,
                write=write,
            )
    except (ClientConnectError, ClientConfigError, ClientPackError) as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
    else:
        sink.write(format_connect_payload(payload))
    return 0 if payload.get("ok") else 1


def run_disconnect_cli(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    sink = out or sys.stdout
    home_path = home or Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
    try:
        if is_connect_all_target(client_id):
            payload = build_disconnect_all_payload(
                home=home_path,
                config_path=config_path,
                server_name=server_name,
                project_root=project_root,
                write=write,
            )
        else:
            payload = build_disconnect_payload(
                client_id=client_id,
                home=home_path,
                config_path=config_path,
                server_name=server_name,
                project_root=project_root,
                write=write,
            )
    except (ClientConnectError, ClientConfigError, ClientPackError) as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
    else:
        sink.write(format_connect_payload(payload))
    return 0 if payload.get("ok") else 1


def run_connect_status_cli(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    sink = out or sys.stdout
    home_path = home or Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
    try:
        if is_connect_all_target(client_id):
            payload = build_connect_status_all_payload(
                home=home_path,
                config_path=config_path,
                passphrase_file=passphrase_file,
                proxy_command=proxy_command,
                server_name=server_name,
                project_root=project_root,
            )
        else:
            payload = build_connect_status_payload(
                client_id=client_id,
                home=home_path,
                config_path=config_path,
                passphrase_file=passphrase_file,
                proxy_command=proxy_command,
                server_name=server_name,
                project_root=project_root,
            )
    except (ClientConnectError, ClientConfigError, ClientPackError) as exc:
        raise ProxyCliError(str(exc), exit_code=2) from exc
    if output_json:
        _print_json(payload, out=sink)
    else:
        sink.write(format_connect_payload(payload))
    return 0


def build_parser() -> argparse.ArgumentParser:
    from agentveil_mcp_proxy import __version__ as package_version

    parser = argparse.ArgumentParser(prog="agentveil-mcp-proxy")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {package_version}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser(
        "init",
        # claim-check: allow product label; bounded first-run tests cover this output.
        help="Safe Autopilot first-run: create local identity, config, and control grant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # claim-check: allow product label in init --help epilog; verified by P10C smokes.
        epilog=(
            "Default user path (no --role):\n"
            "  agentveil-mcp-proxy init --quickstart-filesystem ./sandbox\n"
            "  agentveil-mcp-proxy client-config print\n"
            "Advanced: pass --role reviewer|readonly|implementer|build for preset policy packs."
        ),
    )
    _add_common_path_args(init)
    init.add_argument("--base-url", default=DEFAULT_BASE_URL)
    init.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    init.add_argument("--trusted-signer-did", action="append", default=None)
    init.add_argument(
        "--policy-pack",
        default="default",
        choices=["default", "github", "filesystem", "shell", "git", "fetch", "package", "product_route"],
    )
    init.add_argument(
        "--role",
        default=None,
        choices=list(ROLE_PRESET_NAMES),
        # claim-check: allow product label; this describes UX, not a safety guarantee.
        help="Advanced role preset; default first-run uses Safe Autopilot without role selection",
    )
    init.add_argument(
        "--quickstart-filesystem",
        type=Path,
        default=None,
        # claim-check: allow product label; default quickstart path verified by P10C smokes.
        help="Safe Autopilot default: built-in sandboxed filesystem downstream at this path",
    )
    init.add_argument(
        "--product-route-profile",
        type=Path,
        default=None,
        help="Initialize the composite local product route fixtures and downstream at this profile root",
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

    doctor = subparsers.add_parser(
        "doctor",
        help="Validate local proxy setup before connecting your MCP client",
        description="Validate local proxy setup before connecting your MCP client.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # claim-check: allow product label in doctor --help epilog; default quickstart path.
        epilog=(
            # claim-check: allow product label; help text names the default path.
            "Use after `init --quickstart-filesystem` on the default Safe Autopilot path.\n"
            "Add --full to launch the downstream and verify MCP initialize/tools/list."
        ),
    )
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

    approval_center = subparsers.add_parser(
        "approval-center",
        help="Manage the stable local Approval Center",
    )
    approval_center_subparsers = approval_center.add_subparsers(
        dest="approval_center_action",
        required=True,
    )
    approval_center_serve = approval_center_subparsers.add_parser(
        "serve",
        help="Run the stable local Approval Center for any MCP client turn",
    )
    _add_common_path_args(approval_center_serve)
    _add_passphrase_args(approval_center_serve)
    approval_center_serve.add_argument(
        "--port",
        type=int,
        default=0,
        help="Loopback port for the Approval Center (0 = reuse manifest or assign)",
    )

    run = subparsers.add_parser("run", help="Run stdio MCP passthrough")
    _add_common_path_args(run)
    _add_passphrase_args(run)
    run.add_argument("--headless", action="store_true", help="Disable browser and OS notification attempts")
    run.add_argument("--auto-deny", action="store_true", help="Deny every approval-required action")
    run.add_argument("--headless-policy", type=Path, default=None, help="Headless approval policy JSON path")
    run.add_argument(
        "--approval-ui-mode",
        choices=[mode.value for mode in ApprovalUiOpenMode],
        default=None,
        help=(
            "Override approval.ui_open_mode: browser opens the approval center once, "
            "terminal prints URLs only, none prints URLs without browser or OS notifications"
        ),
    )

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

    smoke = subparsers.add_parser(
        "smoke",
        help="Quick check: launch downstream and verify MCP initialize/tools/list",
        description="Quick check: launch downstream and verify MCP initialize/tools/list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run after `init --quickstart-filesystem` and optional `doctor --full` "
            "on the default Safe Autopilot quickstart path."
        ),  # claim-check: allow product label in smoke --help epilog; default quickstart path.
    )
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

    control = subparsers.add_parser(
        "control",
        help="Daily control surface for routed MCP status and evidence timeline",
    )
    control_subparsers = control.add_subparsers(dest="control_action", required=True)
    control_status = control_subparsers.add_parser(
        "status",
        help="Show setup, redirect coverage, and evidence summary",
    )
    _add_common_path_args(control_status)
    control_status.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to inspect for routing status",
    )
    control_status.add_argument(
        "--proxy-command",
        default=None,
        help="Expected proxy executable name/path for routing validation",
    )
    _add_json_arg(control_status)

    control_timeline = control_subparsers.add_parser(
        "timeline",
        help="Show recent approval, deny, and redirect evidence events",
    )
    _add_common_path_args(control_timeline)
    control_timeline.add_argument("--limit", type=int, default=20)
    _add_json_arg(control_timeline)

    permission_doctor = subparsers.add_parser(
        "permission-doctor",
        help="Show setup mode, control boundaries, and redirect coverage",
    )
    _add_common_path_args(permission_doctor)
    permission_doctor.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to inspect for routing status",
    )
    permission_doctor.add_argument(
        "--proxy-command",
        default=None,
        help="Expected proxy executable name/path for routing validation",
    )
    _add_json_arg(permission_doctor)

    client_config = subparsers.add_parser(
        "client-config",
        help="Print runnable MCP client config for desktop agents (dry-run)",
    )
    client_config_subparsers = client_config.add_subparsers(
        dest="client_config_action",
        required=True,
    )
    client_config_print = client_config_subparsers.add_parser(
        "print",
        help="Render runnable local client config JSON (human default)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # claim-check: allow privacy/runnable split wording in client-config --help epilog.
        epilog=(
            "Human output: privacy-bounded header plus runnable local client config JSON "
            "(local paths allowed in JSON).\n"
            "With --json: structured payload separates privacy-bounded summary from "
            "clients.*.local_client_config (copy paste from local_client_config, not summary)."
        ),
    )
    _add_common_path_args(client_config_print)
    client_config_print.add_argument(
        "--client",
        action="append",
        default=None,
        choices=[*sorted(CLIENT_TARGETS), "all"],
        help="Client target to render (repeatable; default: all supported clients)",
    )
    client_config_print.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help="MCP server entry name inside mcpServers",
    )
    client_config_print.add_argument(
        "--proxy-command",
        default=None,
        help="Path to agentveil-mcp-proxy executable (default: resolve from PATH)",
    )
    client_config_print.add_argument(
        "--passphrase-file",
        type=Path,
        default=None,
        help="Include --passphrase-file in run args (file path only; passphrase content is not printed)",
    )
    _add_json_arg(client_config_print)

    client_config_packs = client_config_subparsers.add_parser(
        "packs",
        help="List client compatibility pack metadata",
    )
    client_config_packs.add_argument(
        "--client",
        action="append",
        default=None,
        choices=[*CLIENT_PACK_IDS, "all"],  # claim-check: allow "all" is a selector enum.
        help="Client pack to describe (repeatable; default: all packs)",  # claim-check: allow "all" is a selector enum.
    )
    _add_json_arg(client_config_packs)

    client_config_guidance = client_config_subparsers.add_parser(
        "guidance",
        help="Print bounded action-routing guidance for client packs",
    )
    client_config_guidance.add_argument(
        "--client",
        action="append",
        default=None,
        choices=[*CLIENT_PACK_IDS, "all"],  # claim-check: allow "all" is a selector enum.
        help="Client pack to describe (repeatable; default: all packs)",  # claim-check: allow "all" is a selector enum.
    )
    _add_json_arg(client_config_guidance)

    client_doctor = subparsers.add_parser(
        "client-doctor",
        help="Optional client-pack health check for generated MCP config + proxy path",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Proves generated-config/proxy-path behavior, not provider-native client proof.\n"
            "Use after init and client-config print. Add --list-only for tools/list-only diagnostics."
        ),
    )
    _add_common_path_args(client_doctor)
    client_doctor.add_argument(
        "--client",
        required=True,
        choices=list(CLIENT_PACK_IDS),
        help="Client compatibility pack to check",
    )
    client_doctor.add_argument(
        "--proxy-command",
        default=None,
        help="Expected proxy executable name/path for config rendering",
    )
    client_doctor.add_argument(
        "--passphrase-file",
        type=Path,
        default=None,
        help="Passphrase file for encrypted proxy identity",
    )
    client_doctor.add_argument(
        "--list-only",
        action="store_true",
        help="Verify tools/list only and return bounded list-only diagnostic",
    )
    _add_json_arg(client_doctor)

    connect = subparsers.add_parser(
        "connect",
        help="Preview or write guided MCP client native config connect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            # claim-check: allow "all" below is a CLI target literal, not a coverage claim.
            "Default is dry-run preview. Use --write to apply after backup.\n"
            "Example:\n"
            "  agentveil-mcp-proxy connect cursor\n"
            "  agentveil-mcp-proxy connect cursor --write\n"
            "  agentveil-mcp-proxy connect all\n"  # claim-check: allow "all" is a CLI target literal.
            "  agentveil-mcp-proxy connect all --write\n"  # claim-check: allow "all" is a CLI target literal.
            "  agentveil-mcp-proxy connect status cursor\n"
            "  agentveil-mcp-proxy connect status all"  # claim-check: allow "all" is a CLI target literal.
        ),
    )
    connect.add_argument(
        "client",
        nargs="?",
        choices=[*CLIENT_PACK_IDS, ALL_CLIENTS_TARGET],
        # claim-check: allow "all" below is a CLI target literal, not a coverage claim.
        help="Client to connect (cursor, claude_code, codex, all)",
    )
    _add_common_path_args(connect)
    _add_passphrase_args(connect)
    connect.add_argument(
        "--proxy-command",
        default=None,
        help="Proxy executable for generated client config",
    )
    connect.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help="MCP server entry name inside client config",
    )
    connect.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Project root for client config placement (default: current directory)",
    )
    connect.add_argument(
        "--status",
        action="store_true",
        help="Report whether AgentVeil MCP entry is present in client config",
    )
    connect.add_argument(
        "--write",
        action="store_true",
        help="Write client config after backup (default: dry-run preview only)",
    )
    connect.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicit dry-run preview (default when --write is omitted)",
    )
    _add_json_arg(connect)

    disconnect = subparsers.add_parser(
        "disconnect",
        help="Preview or write removal of the AgentVeil MCP client entry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Default is dry-run preview. Use --write to apply after backup.\n"
            "Example:\n"
            "  agentveil-mcp-proxy disconnect cursor\n"
            "  agentveil-mcp-proxy disconnect cursor --write\n"
            "  agentveil-mcp-proxy disconnect all\n"  # claim-check: allow "all" is a CLI target literal.
            "  agentveil-mcp-proxy disconnect all --write"  # claim-check: allow "all" is a CLI target literal.
        ),
    )
    disconnect.add_argument(
        "client",
        choices=[*CLIENT_PACK_IDS, ALL_CLIENTS_TARGET],
        # claim-check: allow "all" below is a CLI target literal, not a coverage claim.
        help="Client to disconnect (cursor, claude_code, codex, all)",
    )
    _add_common_path_args(disconnect)
    disconnect.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help="MCP server entry name to remove",
    )
    disconnect.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Project root for client config placement (default: current directory)",
    )
    disconnect.add_argument(
        "--write",
        action="store_true",
        help="Write client config after backup (default: dry-run preview only)",
    )
    _add_json_arg(disconnect)

    client_run = subparsers.add_parser(
        "client-run",
        help="Plan non-invasive runtime attach for a supported MCP client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Default is dry-run planning only; AgentVeil does not write client configs.\n"
            "Example:\n"
            "  agentveil-mcp-proxy client-run codex --json\n"
            "  agentveil-mcp-proxy client-run cursor --json\n"
            "  agentveil-mcp-proxy client-run some_unknown_client --json"
        ),
    )
    client_run.add_argument(
        "client",
        help="Client id (cursor, claude_code, codex, or any unknown id for generic route)",
    )
    _add_common_path_args(client_run)
    _add_passphrase_args(client_run)
    client_run.add_argument(
        "--proxy-command",
        default=None,
        help="Proxy executable for the generic MCP route package",
    )
    client_run.add_argument(
        "--exec",
        action="store_true",
        help="Execute runtime attach when supported (never default)",
    )
    client_run.add_argument(
        "--launch",
        action="store_true",
        help="Alias for --exec",
    )
    client_run.add_argument(
        "--prompt",
        default=None,
        help="Prompt to pass to Codex when --exec/--launch is used",
    )
    _add_json_arg(client_run)

    explain = subparsers.add_parser(
        "explain",
        help="Print bounded operator guidance without starting transport",
    )
    explain_subparsers = explain.add_subparsers(dest="explain_action", required=True)
    explain_role = explain_subparsers.add_parser(
        "role",
        help="Show allowed, approval-required, and denied action families by role preset",
    )
    _add_common_path_args(explain_role)
    explain_role.add_argument(
        "--preset",
        choices=list(ROLE_PRESET_NAMES),
        default=None,
        help="Explain one preset; default reads role_preset from config or the preset set",
    )
    _add_json_arg(explain_role)

    templates = subparsers.add_parser(
        "templates",
        help="Print copy-paste runnable starter commands for review/build/readonly agents",
    )
    templates_subparsers = templates.add_subparsers(dest="templates_action", required=True)
    templates_print = templates_subparsers.add_parser(
        "print",
        help="Render starter init/client-config/explain/run commands",
    )
    templates_print.add_argument(
        "--template",
        choices=[*AGENT_TEMPLATE_NAMES, "set"],
        default="set",
        help="Starter template to render (default: set)",
    )
    templates_print.add_argument(
        "--home",
        type=Path,
        default=None,
        help="Concrete AVP home path to embed in generated commands",
    )
    templates_print.add_argument(
        "--sandbox",
        type=Path,
        default=None,
        help="Concrete quickstart filesystem sandbox path to embed in generated commands",
    )
    templates_print.add_argument(
        "--proxy-command",
        default=None,
        help="Path to agentveil-mcp-proxy executable (default: resolve from PATH)",
    )
    _add_json_arg(templates_print)

    wizard = subparsers.add_parser(
        "wizard",
        help="Generate and validate MCP client config routed through the proxy",
    )
    wizard_subparsers = wizard.add_subparsers(dest="wizard_action", required=True)
    wizard_print = wizard_subparsers.add_parser(
        "print",
        help="Render validated proxy-routed MCP client config for one agent template",
    )
    wizard_print.add_argument(
        "--template",
        required=True,
        choices=list(AGENT_TEMPLATE_NAMES),
        help="Agent template to render (review, build, readonly)",
    )
    wizard_print.add_argument("--home", type=Path, required=True, help="AVP home for the template")
    wizard_print.add_argument(
        "--sandbox",
        type=Path,
        required=True,
        help="Quickstart filesystem sandbox path for the template",
    )
    wizard_print.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to render",
    )
    wizard_print.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help="MCP server entry name inside mcpServers",
    )
    wizard_print.add_argument(
        "--proxy-command",
        default=None,
        help="Path to agentveil-mcp-proxy executable (default: resolve from PATH)",
    )
    wizard_print.add_argument(
        "--init",
        action="store_true",
        help="Run template init first when proxy config is missing",
    )
    _add_json_arg(wizard_print)

    wizard_validate = wizard_subparsers.add_parser(
        "validate",
        help="Validate an MCP client config file routes through the proxy",
    )
    wizard_validate.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to MCP client JSON config to validate",
    )
    wizard_validate.add_argument(
        "--proxy-command",
        default=None,
        help="Expected proxy executable name/path for validation",
    )
    wizard_validate.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Expected proxy config path embedded in --config run args",
    )
    _add_json_arg(wizard_validate)

    setup = subparsers.add_parser(
        "setup",
        help="Adaptive setup wizard for proxy and MCP client config",
    )
    setup_subparsers = setup.add_subparsers(dest="setup_action", required=True)
    setup_run = setup_subparsers.add_parser(
        "run",
        help="Plan adaptive setup and write proxy/client config with backup",
    )
    setup_run.add_argument("--home", type=Path, required=True, help="AVP home for setup output")
    setup_run.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="Path to metadata-only tool inventory JSON",
    )
    setup_run.add_argument(
        "--mode",
        default="review",
        choices=["readonly", "review", "build"],
        help="Requested setup mode",
    )
    setup_run.add_argument(
        "--overlay",
        action="append",
        default=[],
        dest="overlays",
        help="Optional setup overlay id (repeatable)",
    )
    setup_run.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to write",
    )
    setup_run.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help="MCP server entry name inside mcpServers",
    )
    setup_run.add_argument(
        "--proxy-command",
        default=None,
        help="Path to agentveil-mcp-proxy executable (default: resolve from PATH)",
    )
    setup_run.add_argument(
        "--agent-name",
        default="adaptive-setup",
        help="AVP agent name embedded in generated proxy config",
    )
    setup_run.add_argument(
        "--trusted-signer-did",
        default="did:key:z6MktrustedSigner",
        help="Trusted signer DID for generated proxy config validation",
    )
    _add_json_arg(setup_run)

    setup_status = setup_subparsers.add_parser(
        "status",
        help=(
            "Without --home: project-local Claude connector status. "
            "With --home: adaptive setup wizard status."
        ),
    )
    # --home is optional (option A): bare `setup status` reports the project
    # connector status; `setup status --home <path>` keeps the adaptive wizard
    # behavior, back-compatible with existing callers.
    setup_status.add_argument("--home", type=Path, default=None, help="AVP home to inspect (wizard mode)")
    setup_status.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Project directory for connector status (default: current directory)",
    )
    setup_status.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to inspect",
    )
    setup_status.add_argument(
        "--proxy-command",
        default=None,
        help="Expected proxy executable name/path for routing validation",
    )
    setup_status.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Proxy config path to inspect (default: <home>/mcp-proxy/config.json)",
    )
    _add_json_arg(setup_status)

    setup_restore = setup_subparsers.add_parser(
        "restore",
        help="Restore setup-managed config files from backups",
    )
    setup_restore.add_argument("--home", type=Path, required=True, help="AVP home to restore")
    setup_restore.add_argument(
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        default="all",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        choices=["proxy", "client", "all"],
        help="Which setup-managed files to restore",
    )
    setup_restore.add_argument(
        "--client",
        default="cursor",
        choices=list(CLIENT_TARGETS),
        help="Desktop MCP client target to restore",
    )
    _add_json_arg(setup_restore)

    setup_claude_code = setup_subparsers.add_parser(
        "claude-code",
        help="One-command Claude Code connector setup (proxy route + MCP route + hook)",
    )
    setup_claude_code.add_argument(
        "--project-dir", type=Path, default=None,
        help="Project directory to set up (default: current directory)",
    )
    setup_claude_code.add_argument(
        "--choose-folder", action="store_true",
        help="Open the macOS folder picker to choose the project directory",
    )
    setup_claude_code.add_argument(
        "--sandbox", type=Path, default=None,
        help="Quickstart filesystem sandbox path (default: selected project directory)",
    )
    setup_claude_code.add_argument(
        "--yes", action="store_true",
        help="Apply the setup; without it the command only previews",
    )
    setup_claude_code.add_argument(
        "--passphrase-file", type=Path, default=None,
        help="Encrypt the proxy identity with this passphrase file (default: plaintext quickstart)",
    )
    setup_claude_code.add_argument(
        "--force", action="store_true",
        help="Re-initialize the proxy route even if its config already exists",
    )
    _add_json_arg(setup_claude_code)

    setup_remove = setup_subparsers.add_parser(
        "remove",
        help="Remove a one-command connector (AgentVeil-managed entries only)",
    )
    setup_remove.add_argument("target", choices=["claude-code"], help="Connector to remove")
    setup_remove.add_argument(
        "--project-dir", type=Path, default=None,
        help="Project directory to remove from (default: current directory)",
    )
    setup_remove.add_argument(
        "--yes", action="store_true",
        help="Apply the removal; without it the command only previews",
    )
    _add_json_arg(setup_remove)

    install_claude_hook = subparsers.add_parser(
        "install-claude-hook",
        help="Install the AgentVeil PreToolUse hook into a project's .claude/settings.json",
    )
    install_claude_hook.add_argument(
        "--project",
        action="store_true",
        required=True,
        help="Project scope (required; the only supported scope in this release)",
    )
    install_claude_hook.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Project directory to install into (default: current directory)",
    )
    install_claude_hook.add_argument(
        "--yes",
        action="store_true",
        help="Proceed with the write; without it the command only previews",
    )
    _add_json_arg(install_claude_hook)

    status_claude_hook = subparsers.add_parser(
        "status-claude-hook",
        help="Show AgentVeil Claude Code project hook status (bounded)",
    )
    status_claude_hook.add_argument(
        "--project", action="store_true", required=True, help="Project scope (required)"
    )
    status_claude_hook.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Project directory to inspect (default: current directory)",
    )
    _add_json_arg(status_claude_hook)

    uninstall_claude_hook = subparsers.add_parser(
        "uninstall-claude-hook",
        help="Remove the AgentVeil PreToolUse hook from a project's .claude/settings.json",
    )
    uninstall_claude_hook.add_argument(
        "--project", action="store_true", required=True, help="Project scope (required)"
    )
    uninstall_claude_hook.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Project directory to uninstall from (default: current directory)",
    )
    uninstall_claude_hook.add_argument(
        "--yes",
        action="store_true",
        help="Proceed with the removal; without it the command only previews",
    )
    _add_json_arg(uninstall_claude_hook)

    return parser


def _normalize_connect_argv(argv: list[str]) -> list[str]:
    """Support ``connect status <client>`` without a nested argparse subparser."""

    if len(argv) >= 3 and argv[0] == "connect" and argv[1] == "status":
        client = argv[2]
        if client not in (*CLIENT_PACK_IDS, ALL_CLIENTS_TARGET):
            return argv
        return ["connect", client, "--status", *argv[3:]]
    return argv


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


def run_install_claude_hook_cli(
    *, project_dir: Path | None, assume_yes: bool, output_json: bool
) -> int:
    """Install/upsert the AgentVeil PreToolUse hook into a project."""
    from agentveil_mcp_proxy import claude_hook_setup

    target = Path(project_dir) if project_dir is not None else Path.cwd()
    settings_path = claude_hook_setup.project_settings_path(target)
    rel_settings = ".claude/settings.json"

    if not assume_yes:
        message = (
            f"Would install the AgentVeil PreToolUse hook into {settings_path}. "
            "Re-run with --yes to write it."
        )
        if output_json:
            _print_json({
                "ok": False,
                "action": "install-claude-hook",
                "applied": False,
                "errors": ["confirmation required: pass --yes"],
                "warnings": [message],
                "settings_relpath": rel_settings,
            })
        else:
            print(message)
        return 0

    try:
        result = claude_hook_setup.install_hook(target)
    except claude_hook_setup.HookSetupError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc

    if output_json:
        _print_operator_json({
            "ok": True,
            "action": "install-claude-hook",
            "applied": True,
            "scope": "project",
            "settings_relpath": rel_settings,
            "evidence_relpath": ".claude/agentveil/evidence.jsonl",
            "created_settings": result.created_settings,
            "replaced_existing_managed": result.replaced_existing_managed,
            "reload_required": result.reload_required,
            "matched_tool_classes": list(claude_hook_setup.MATCHED_TOOL_CLASSES),
        })
    else:
        print(f"Installed AgentVeil PreToolUse hook: {settings_path}")
        print(f"Evidence: {result.evidence_path}")
        print("Restart Claude Code to load the hook.")
    return 0


def run_status_claude_hook_cli(*, project_dir: Path | None, output_json: bool) -> int:
    """Print bounded project hook status."""
    from agentveil_mcp_proxy import claude_hook_setup

    target = Path(project_dir) if project_dir is not None else Path.cwd()
    status = claude_hook_setup.status_hook(target)
    bounded = status.to_bounded_dict()
    if output_json:
        _print_operator_json(bounded)
    else:
        print(f"status: {bounded['status']} ({bounded['state']})")
        print(f"managed hook present: {bounded['managed_hook_present']}")
        print(f"command points to module: {bounded['hook_command_points_to_module']}")
        print(f"reload required: {bounded['reload_required']}")
        for note in bounded["notes"]:
            print(f"- {note}")
    return 0


def run_uninstall_claude_hook_cli(
    *, project_dir: Path | None, assume_yes: bool, output_json: bool
) -> int:
    """Remove only AgentVeil-managed hook entries from a project."""
    from agentveil_mcp_proxy import claude_hook_setup

    target = Path(project_dir) if project_dir is not None else Path.cwd()
    settings_path = claude_hook_setup.project_settings_path(target)

    if not assume_yes:
        message = (
            f"Would remove the AgentVeil PreToolUse hook from {settings_path}. "
            "Re-run with --yes to apply."
        )
        if output_json:
            _print_json({
                "ok": False,
                "action": "uninstall-claude-hook",
                "applied": False,
                "errors": ["confirmation required: pass --yes"],
                "warnings": [message],
                "settings_relpath": ".claude/settings.json",
            })
        else:
            print(message)
        return 0

    try:
        result = claude_hook_setup.uninstall_hook(target)
    except claude_hook_setup.HookSetupError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc

    if output_json:
        _print_operator_json({
            "ok": True,
            "action": "uninstall-claude-hook",
            "applied": True,
            "scope": "project",
            "settings_existed": result.settings_existed,
            "removed_entries": result.removed_entries,
            "reload_required": result.reload_required,
        })
    else:
        if result.removed_entries:
            print(f"Removed {result.removed_entries} AgentVeil hook entry(ies): {settings_path}")
            print("Restart Claude Code to drop the hook.")
        else:
            print("No AgentVeil-managed hook entry found; nothing to remove.")
    return 0


def _setup_claude_code_home(project_dir: Path) -> Path:
    """Project-local proxy home for the one-command connector."""
    return project_dir / ".avp"


def _choose_setup_project_folder() -> Path:
    """Open the native macOS folder picker and return the selected directory."""
    if sys.platform != "darwin":
        raise ProxyCliError("--choose-folder is currently supported on macOS only", exit_code=2)
    import subprocess

    script = (
        'POSIX path of (choose folder with prompt '
        '"Choose the project folder to protect with AgentVeil")'
    )
    try:
        result = subprocess.run(  # noqa: S603 - fixed osascript invocation
            ["osascript", "-e", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProxyCliError(
            f"could not open folder picker: {exc.__class__.__name__}",
            exit_code=2,
        ) from exc
    if result.returncode != 0:
        raise ProxyCliError("folder selection cancelled", exit_code=2)
    selected = result.stdout.strip()
    if not selected:
        raise ProxyCliError("folder selection returned an empty path", exit_code=2)
    return Path(selected)


def _resolve_setup_proxy_command() -> str | None:
    """Resolve the console script used by generated Claude setup config."""
    import shutil

    invoked = Path(sys.argv[0])
    if invoked.exists() and invoked.name == "agentveil-mcp-proxy":
        return str(invoked.resolve())
    resolved = shutil.which("agentveil-mcp-proxy")
    if resolved:
        return resolved
    return None


def _configure_claude_setup_approval_ui(config_path: Path) -> None:
    """Disable browser auto-open for Claude setup-managed approvals.

    Claude Code already displays the exact pending approval URL in chat. Opening
    the bare Approval Center dashboard from the proxy creates a confusing empty
    browser tab during first-run setup and approval retries.
    """
    config_payload = _read_json(config_path, "proxy config")
    approval = config_payload.get("approval")
    if not isinstance(approval, dict):
        approval = {}
        config_payload["approval"] = approval
    approval["ui_open_mode"] = ApprovalUiOpenMode.TERMINAL.value
    _secure_write_json(config_path, config_payload, force=True)


def run_setup_claude_code_cli(
    *,
    project_dir: Path | None,
    choose_folder: bool,
    sandbox: Path | None,
    assume_yes: bool,
    passphrase_file: Path | None,
    force: bool,
    output_json: bool,
) -> int:
    """One-command Claude Code connector setup.

    Orchestrates the existing primitives end-to-end: proxy quickstart route
    (`init_proxy`), Claude MCP route (`connect claude_code`), and the
    project-local hook (`install_hook`). It does not duplicate policy/approval
    logic. It does not claim Claude Code has reloaded; it states restart is
    required.
    """
    from agentveil_mcp_proxy import claude_hook_setup

    if choose_folder and project_dir is not None:
        raise ProxyCliError("--choose-folder cannot be combined with --project-dir", exit_code=2)
    selected_project = _choose_setup_project_folder() if choose_folder else project_dir
    target = (Path(selected_project) if selected_project is not None else Path.cwd()).resolve()
    sandbox_path = Path(sandbox).resolve() if sandbox is not None else target
    home = _setup_claude_code_home(target)
    config_path = home / "mcp-proxy" / "config.json"

    if not assume_yes:
        message = (
            f"Would set up the Claude Code connector in {target}: proxy quickstart "
            f"route, project .mcp.json, and the project hook. Re-run with --yes."
        )
        if output_json:
            _print_json({
                "ok": False, "action": "setup-claude-code", "applied": False,
                "errors": ["confirmation required: pass --yes"], "warnings": [message],
            })
        else:
            print(message)
        return 0

    quiet = io.StringIO()
    # 1. Proxy quickstart route (idempotent unless --force).
    proxy_present = config_path.exists()
    proxy_initialized = False
    if force or not proxy_present:
        downstream = quickstart_filesystem_downstream(sandbox_path)
        try:
            init_proxy(
                home=home,
                config_path=None,
                downstream_config=downstream,
                plaintext=(passphrase_file is None),
                passphrase_file=passphrase_file,
                force=force,
                err=quiet,
            )
        except ProxyCliError:
            raise
        proxy_initialized = True
    if config_path.exists():
        _configure_claude_setup_approval_ui(config_path)

    # 2. Claude Code MCP route (.mcp.json) — reuse the connect command. Resolve
    # the installed console script explicitly (matches the supported manual
    # `connect --proxy-command "$(which agentveil-mcp-proxy)"` path). The route
    # is considered configured once .mcp.json carries the AgentVeil entry; a
    # non-zero launch-proof is not fatal to setup if the route was written.
    resolved_proxy_command = _resolve_setup_proxy_command()
    run_connect_cli(
        client_id="claude_code",
        home=home,
        project_root=target,
        write=True,
        proxy_command=resolved_proxy_command,
        out=quiet,
    )
    if not claude_hook_setup.mcp_route_present(target):
        raise ProxyCliError(
            "could not write the Claude MCP route; ensure agentveil-mcp-proxy is "
            "installed and on PATH",
            exit_code=1,
        )

    # 3. Project-local hook.
    try:
        install_result = claude_hook_setup.install_hook(target)
    except claude_hook_setup.HookSetupError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc

    # 4. Approval Center: take ownership of lifecycle. Without a live center,
    # controlled MCP write approvals would surface URLs that the user cannot
    # open (ERR_CONNECTION_REFUSED). Setup must not claim ready in that case.
    from agentveil_mcp_proxy import claude_center_lifecycle

    proxy_cmd_for_center = resolved_proxy_command
    if not proxy_cmd_for_center:
        raise ProxyCliError(
            "agentveil-mcp-proxy console script not on PATH; cannot start Approval Center",
            exit_code=1,
        )
    center_result = claude_center_lifecycle.ensure_running(
        home=home,
        proxy_command=proxy_cmd_for_center,
        passphrase_file=passphrase_file,
    )
    center_running = center_result.status.state == "running"

    # 5. Bounded status summary.
    status = claude_hook_setup.connector_status(target, proxy_route_present=config_path.exists())
    sandbox_label = "project" if sandbox is None else "custom"

    if not center_running:
        if output_json:
            _print_json({
                "ok": False,
                "action": "setup-claude-code",
                "applied": True,
                "scope": "project",
                "proxy_route_initialized": proxy_initialized,
                "mcp_route_relpath": ".mcp.json",
                "hook_relpath": ".claude/settings.json",
                "sandbox_relpath": sandbox_label,
                "identity_encrypted": passphrase_file is not None,
                "approval_center": {"state": center_result.status.state, "reason": center_result.reason},
                "errors": [
                    "approval_center not running; controlled MCP writes would surface "
                    "unreachable approval URLs. Setup is not ready/protected."
                ],
                "warnings": [],
            })
        else:
            print("Claude Code connector partially set up:")
            print(f"  proxy route: {'initialized' if proxy_initialized else 'already present'}")
            print("  MCP route:   .mcp.json written")
            print("  hook:        .claude/settings.json present")
            print(f"  approval_center: {center_result.status.state} ({center_result.reason})")
            print("ERROR: setup is NOT ready — Approval Center could not start.", file=sys.stderr)
        return 1

    if output_json:
        _print_operator_json({
            "ok": True,
            "action": "setup-claude-code",
            "applied": True,
            "scope": "project",
            "proxy_route_initialized": proxy_initialized,
            "mcp_route_relpath": ".mcp.json",
            "hook_relpath": ".claude/settings.json",
            "sandbox_relpath": sandbox_label,
            "identity_encrypted": passphrase_file is not None,
            "approval_center": {
                "state": center_result.status.state,
                "started": center_result.started,
                "reused": center_result.reused,
                "restarted": center_result.restarted,
            },
            "reload_required": True,
            "status": status,
        })
    else:
        print("Claude Code connector set up for this project:")
        print(f"  proxy route: {'initialized' if proxy_initialized else 'already present'}")
        print("  MCP route:   .mcp.json written")
        print(f"  hook:        .claude/settings.json ({'created' if install_result.created_settings else 'updated'})")
        if passphrase_file is None:
            print("  identity:    stored unencrypted (quickstart); use --passphrase-file to encrypt")
        action = "reused" if center_result.reused else ("restarted" if center_result.restarted else "started")
        print(f"  approval_center: running ({action})")
        print(f"  status:      {status['status']}")
        print("Restart Claude Code for this project, then run `agentveil-mcp-proxy setup status`.")
    return 0


def run_setup_connector_status_cli(*, project_dir: Path | None, output_json: bool) -> int:
    """Project-local Claude connector status (bare `setup status`)."""
    from agentveil_mcp_proxy import claude_center_lifecycle, claude_hook_setup

    target = (Path(project_dir) if project_dir is not None else Path.cwd()).resolve()
    home = _setup_claude_code_home(target)
    config_path = home / "mcp-proxy" / "config.json"
    status = claude_hook_setup.connector_status(target, proxy_route_present=config_path.exists())
    center = claude_center_lifecycle.check_status(home)
    status["approval_center"] = center.state
    # Setup is not "ready" unless the center is running; downgrade product
    # status accordingly so we never say protected with a dead approval path.
    if center.state != "running" and status["status"] != "unsafe":
        status["status"] = "unsafe" if status["mcp_route"] == "missing" else "advisory"
    if output_json:
        _print_operator_json(status)
    else:
        print(f"status: {status['status']}")
        print(f"  hook:       {status['hook']}")
        print(f"  mcp route:  {status['mcp_route']}")
        print(f"  proxy route:{status['proxy_route']}")
        print(f"  approval_center: {center.state}")
        print(f"  restart required: {status['restart_required']}")
        print(f"  next: {status['next_step']}")
    return 0


def run_setup_remove_claude_code_cli(
    *, project_dir: Path | None, assume_yes: bool, output_json: bool
) -> int:
    """Remove the one-command Claude connector — AgentVeil-managed entries only."""
    from agentveil_mcp_proxy import claude_hook_setup

    target = (Path(project_dir) if project_dir is not None else Path.cwd()).resolve()

    if not assume_yes:
        message = (
            f"Would remove AgentVeil-managed Claude hook and MCP route entries from "
            f"{target} (unrelated settings and MCP servers preserved). Re-run with --yes."
        )
        if output_json:
            _print_json({
                "ok": False, "action": "setup-remove-claude-code", "applied": False,
                "errors": ["confirmation required: pass --yes"], "warnings": [message],
            })
        else:
            print(message)
        return 0

    from agentveil_mcp_proxy import claude_center_lifecycle

    try:
        hook_result = claude_hook_setup.uninstall_hook(target)
        route_result = claude_hook_setup.remove_mcp_route(target)
    except claude_hook_setup.HookSetupError as exc:
        raise ProxyCliError(str(exc), exit_code=1) from exc

    center_stop = claude_center_lifecycle.stop_if_managed(_setup_claude_code_home(target))
    removed_any = (
        hook_result.removed_entries > 0
        or route_result.removed
        or center_stop["stopped"]
    )
    if output_json:
        _print_operator_json({
            "ok": True,
            "action": "setup-remove-claude-code",
            "applied": True,
            "scope": "project",
            "hook_entries_removed": hook_result.removed_entries,
            "mcp_route_removed": route_result.removed,
            "approval_center_stopped": center_stop["stopped"],
            "reload_required": removed_any,
        })
    else:
        print(f"Removed: hook entries={hook_result.removed_entries}, mcp route={route_result.removed}, "
              f"approval_center={'stopped' if center_stop['stopped'] else 'not running'}")
        print("Unrelated Claude settings and MCP servers preserved.")
        if removed_any:
            print("Restart Claude Code for this project to drop the connector.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parse_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(
        _normalize_connect_argv(_normalize_downstream_arg_values(parse_argv))
    )
    try:
        if args.command == "init":
            downstream_config = None
            policy_pack = args.policy_pack
            setup_profile = init_setup_profile(explicit_role=False)
            if args.product_route_profile is not None:
                if args.quickstart_filesystem is not None:
                    raise ProxyCliError(
                        "--product-route-profile cannot be combined with --quickstart-filesystem"
                    )
                if args.downstream_name or args.downstream_command or args.downstream_arg:
                    raise ProxyCliError(
                        "--product-route-profile cannot be combined with downstream options"
                    )
                profile_root = args.product_route_profile.expanduser().resolve()
                initialize_product_route_profile(profile_root)
                downstream_config = build_product_route_downstream_config(profile_root)
                policy_pack = "product_route"
                setup_profile = PRODUCT_ROUTE_SETUP_PROFILE
            elif args.quickstart_filesystem is not None:
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
            role_preset, explicit_role = resolve_init_role_preset(args.role)
            if args.product_route_profile is None:
                setup_profile = init_setup_profile(explicit_role=explicit_role)
            json_warnings = [PLAINTEXT_WARNING] if args.json_output and args.plaintext else []
            result = init_proxy(
                home=args.home,
                config_path=args.config,
                base_url=args.base_url,
                agent_name=args.agent_name,
                trusted_signer_dids=args.trusted_signer_did,
                policy_pack=policy_pack,
                role_preset=role_preset,
                setup_profile=setup_profile,
                ttl_days=args.ttl_days,
                allowed_categories=args.allowed_category or DEFAULT_ALLOWED_CATEGORIES,
                downstream_config=downstream_config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                plaintext=args.plaintext,
                err=io.StringIO() if args.json_output else sys.stderr,
                force=args.force,
            )
            config = load_proxy_config(result.config_path)
            setup_label = user_facing_setup_label(
                role_preset=config.role_preset,
                explicit_role=explicit_role,
                setup_profile=setup_profile,
            )
            if args.json_output:
                init_json_payload: dict[str, Any] = {
                    "ok": True,
                    "errors": [],
                    "warnings": json_warnings,
                    "agent_name": result.agent_name,
                    "agent_did": result.agent_did,
                    **_artifact_refs(
                        identity_path=result.identity_path,
                        config_path=result.config_path,
                        control_grant_path=result.control_grant_path,
                    ),
                    "control_grant_expires_at": result.control_grant_expires_at,
                    "setup_profile": setup_profile,
                    "setup_label": setup_label,
                    "downstream": _downstream_info_bounded(config),
                    "evidence_count": _evidence_count(proxy_paths(args.home, args.config)),
                }
                if setup_profile != PRODUCT_ROUTE_SETUP_PROFILE:
                    init_json_payload["role_preset"] = config.role_preset
                    init_json_payload["role_authority"] = {
                        "mode": config.role_authority.mode.value,
                        "role": config.role_authority.role,
                        "authority": config.role_authority.authority,
                    }
                _print_operator_json(init_json_payload)
            else:
                print(f"Created protected agent connection: {result.agent_did}")
                print(f"Setup: {setup_label}")
                print(f"Identity file: {result.identity_path.name}")
                print(f"Config file: {result.config_path.name}")
                print(f"Control grant file: {result.control_grant_path.name}")
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
        if args.command == "approval-center":
            if args.approval_center_action != "serve":
                raise ProxyCliError("approval-center action must be serve")
            return serve_approval_center(
                home=args.home,
                config_path=args.config,
                passphrase=args.passphrase,
                passphrase_file=args.passphrase_file,
                port=args.port,
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
                approval_ui_mode=args.approval_ui_mode,
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
        if args.command == "control":
            if args.control_action == "status":
                return print_control_status_cli(
                    home=args.home,
                    client_id=args.client,
                    proxy_command=args.proxy_command,
                    config_path=args.config,
                    out=sys.stdout,
                    output_json=args.json_output,
                )
            if args.control_action == "timeline":
                return print_control_timeline_cli(
                    home=args.home,
                    config_path=args.config,
                    limit=args.limit,
                    out=sys.stdout,
                    output_json=args.json_output,
                )
            raise ProxyCliError("control action must be status or timeline")
        if args.command == "permission-doctor":
            return print_permission_doctor_cli(
                home=args.home,
                client_id=args.client,
                proxy_command=args.proxy_command,
                config_path=args.config,
                out=sys.stdout,
                output_json=args.json_output,
            )
        if args.command == "client-config":
            if args.client_config_action == "print":
                print_client_configs(
                    clients=args.client or sorted(CLIENT_TARGETS),
                    server_name=args.server_name,
                    command=args.proxy_command,
                    home=args.home,
                    config_path=args.config,
                    passphrase_file=args.passphrase_file,
                    output_json=args.json_output,
                )
                return 0
            if args.client_config_action == "packs":
                return print_client_packs_cli(
                    clients=args.client,
                    output_json=args.json_output,
                )
            if args.client_config_action == "guidance":
                return print_client_guidance_cli(
                    clients=args.client,
                    output_json=args.json_output,
                )
            raise ProxyCliError("client-config action must be print, packs, or guidance")
        if args.command == "client-doctor":
            return run_client_doctor_cli(
                client_id=args.client,
                home=args.home,
                config_path=args.config,
                passphrase_file=args.passphrase_file,
                proxy_command=args.proxy_command,
                list_only=args.list_only,
                output_json=args.json_output,
            )
        if args.command == "connect":
            if args.status:
                return run_connect_status_cli(
                    client_id=args.client,
                    home=args.home,
                    config_path=args.config,
                    passphrase_file=args.passphrase_file,
                    proxy_command=args.proxy_command,
                    server_name=args.server_name,
                    project_root=args.project_root,
                    output_json=args.json_output,
            )
            if not args.client:
                # claim-check: allow "all" below is a CLI target literal, not a coverage claim.
                raise ProxyCliError("client id required; example: connect cursor or connect all")
            return run_connect_cli(
                client_id=args.client,
                home=args.home,
                config_path=args.config,
                passphrase_file=args.passphrase_file,
                proxy_command=args.proxy_command,
                server_name=args.server_name,
                project_root=args.project_root,
                write=args.write,
                output_json=args.json_output,
            )
        if args.command == "disconnect":
            return run_disconnect_cli(
                client_id=args.client,
                home=args.home,
                config_path=args.config,
                server_name=args.server_name,
                project_root=args.project_root,
                write=args.write,
                output_json=args.json_output,
            )
        if args.command == "client-run":
            return run_client_run_cli(
                client_id=args.client,
                home=args.home,
                config_path=args.config,
                passphrase_file=args.passphrase_file,
                proxy_command=args.proxy_command,
                launch=args.exec or args.launch,
                prompt=args.prompt,
                output_json=args.json_output,
            )
        if args.command == "explain":
            if args.explain_action != "role":
                raise ProxyCliError("explain action must be role")
            return explain_role_proxy(
                home=args.home,
                config_path=args.config,
                preset=args.preset,
                output_json=args.json_output,
            )
        if args.command == "templates":
            if args.templates_action != "print":
                raise ProxyCliError("templates action must be print")
            template_id = None if args.template == "set" else args.template
            return print_agent_templates(
                template_id=template_id,
                home=args.home,
                sandbox_root=args.sandbox,
                proxy_command=args.proxy_command,
                output_json=args.json_output,
            )
        if args.command == "wizard":
            if args.wizard_action == "print":
                return print_config_wizard(
                    template_id=args.template,
                    home=args.home,
                    sandbox_root=args.sandbox,
                    client_id=args.client,
                    server_name=args.server_name,
                    proxy_command=args.proxy_command,
                    ensure_initialized=args.init,
                    output_json=args.json_output,
                )
            if args.wizard_action == "validate":
                return validate_config_wizard(
                    input_path=args.input,
                    proxy_command=args.proxy_command,
                    config_path=args.config,
                    output_json=args.json_output,
                )
            raise ProxyCliError("wizard action must be print or validate")
        if args.command == "setup":
            if args.setup_action == "run":
                return run_setup_wizard_cli(
                    home=args.home,
                    inventory_path=args.inventory,
                    mode=args.mode,
                    overlays=args.overlays,
                    client_id=args.client,
                    server_name=args.server_name,
                    proxy_command=args.proxy_command,
                    agent_name=args.agent_name,
                    trusted_signer_did=args.trusted_signer_did,
                    output_json=args.json_output,
                )
            if args.setup_action == "status":
                # Option A: bare `setup status` = project connector status;
                # `setup status --home <path>` = existing adaptive wizard status.
                if args.home is None:
                    return run_setup_connector_status_cli(
                        project_dir=args.project_dir,
                        output_json=args.json_output,
                    )
                return print_setup_status_cli(
                    home=args.home,
                    client_id=args.client,
                    proxy_command=args.proxy_command,
                    config_path=args.config,
                    output_json=args.json_output,
                )
            if args.setup_action == "restore":
                return restore_setup_cli(
                    home=args.home,
                    target=args.target,
                    client_id=args.client,
                    output_json=args.json_output,
                )
            if args.setup_action == "claude-code":
                return run_setup_claude_code_cli(
                    project_dir=args.project_dir,
                    choose_folder=args.choose_folder,
                    sandbox=args.sandbox,
                    assume_yes=args.yes,
                    passphrase_file=args.passphrase_file,
                    force=args.force,
                    output_json=args.json_output,
                )
            if args.setup_action == "remove":
                if args.target != "claude-code":
                    raise ProxyCliError("setup remove target must be claude-code")
                return run_setup_remove_claude_code_cli(
                    project_dir=args.project_dir,
                    assume_yes=args.yes,
                    output_json=args.json_output,
                )
            raise ProxyCliError(
                "setup action must be claude-code, status, remove, run, or restore"
            )
        if args.command == "install-claude-hook":
            return run_install_claude_hook_cli(
                project_dir=args.project_dir,
                assume_yes=args.yes,
                output_json=args.json_output,
            )
        if args.command == "status-claude-hook":
            return run_status_claude_hook_cli(
                project_dir=args.project_dir,
                output_json=args.json_output,
            )
        if args.command == "uninstall-claude-hook":
            return run_uninstall_claude_hook_cli(
                project_dir=args.project_dir,
                assume_yes=args.yes,
                output_json=args.json_output,
            )
    except (
        ProxyCliError,
        ApprovalEvidenceError,
        EvidenceExportError,
        EvidenceVerificationError,
        ControlSurfaceError,
        PermissionDoctorError,
    ) as exc:
        if getattr(args, "json_output", False):
            if isinstance(exc, (ControlSurfaceError, PermissionDoctorError)):
                error_message = exc.public_message()
            else:
                error_message = str(exc)
            _print_json({
                "ok": False,
                "errors": [error_message],
                "warnings": [],
                "downstream": None,
                "evidence_count": None,
            })
        else:
            if isinstance(exc, (ControlSurfaceError, PermissionDoctorError)):
                error_message = exc.public_message()
            else:
                error_message = str(exc)
            print(f"ERROR: {error_message}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, ProxyCliError) else 1
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
