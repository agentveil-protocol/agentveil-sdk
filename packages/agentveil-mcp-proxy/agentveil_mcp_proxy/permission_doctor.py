"""Permission doctor and bounded blast-radius preview for MCP proxy operators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.classification import ClassifiedToolCall
from agentveil_mcp_proxy.config_wizard import (
    ConfigWizardError,
    derive_setup_status,
    is_proxy_routed_mcp_entry,
    load_mcp_client_document,
    resolve_setup_paths,
    setup_status_to_dict,
)
from agentveil_mcp_proxy.client_config import resolve_proxy_command
from agentveil_mcp_proxy.control_surface import (
    redirect_pack_summaries,
    redirect_playbook_coverage,
)
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError

SetupMode = Literal["soft", "controlled", "partial", "bypass", "secure_unavailable"]
CapabilityLevel = Literal["yes", "no", "possible", "unknown"]
CredentialPosture = Literal[
    "visible_static_key",
    "short_lived_token",
    "brokered",
    "hardware_bound",
    "unknown",
]

_LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")
_SECRET_MARKERS = ("secret", "password", "private_key", "api_key", "token")
_PRIVACY_BOUNDARY_MESSAGE = "permission doctor output failed privacy boundary check"

_WRITE_FAMILIES = frozenset({
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "exec",
    "shell",
})
_READ_FAMILIES = frozenset({
    "read",
    "list",
    "get",
    "search",
    "fetch",
})
_SECRET_TOOL_MARKERS = ("secret", "credential", "vault", "password", "token", "key")
_SHELL_TOOL_MARKERS = ("shell", "exec", "bash", "terminal", "run_command")
_PACKAGE_TOOL_MARKERS = ("install", "npm", "pip", "package", "dependency")
_NETWORK_TOOL_MARKERS = ("fetch", "http", "request", "curl", "send", "email", "webhook")
_PERSISTENCE_TOOL_MARKERS = ("config", "settings", "persist", "write_file", "update")
_DEPLOY_TOOL_MARKERS = ("deploy", "release", "publish", "rollback", "prod")
_SAFE_CREDENTIAL_POSTURES = frozenset({
    "visible_static_key",
    "short_lived_token",
    "brokered",
    "hardware_bound",
    "unknown",
})


def _scrub_safe_privacy_labels(text: str) -> str:
    """Remove known bounded enum labels before secret-marker scanning."""

    scrubbed = text
    for label in _SAFE_CREDENTIAL_POSTURES:
        scrubbed = scrubbed.replace(label, "__SAFE_CREDENTIAL_POSTURE__")
    return scrubbed


class PermissionDoctorError(Exception):
    """Bounded permission-doctor error without raw filesystem paths."""

    def __init__(self, message: str, *, code: str = "permission_doctor_error") -> None:
        super().__init__(message)
        self.code = code

    def public_message(self) -> str:
        if self.code == "privacy_violation":
            return _PRIVACY_BOUNDARY_MESSAGE
        return str(self)


def assert_permission_doctor_output_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    lowered = _scrub_safe_privacy_labels(serialized).lower()
    for marker in _LOCAL_PATH_MARKERS:
        if marker.lower() in lowered:
            raise PermissionDoctorError(
                _PRIVACY_BOUNDARY_MESSAGE,
                code="privacy_violation",
            )
    for marker in _SECRET_MARKERS:
        if marker in lowered:
            raise PermissionDoctorError(
                _PRIVACY_BOUNDARY_MESSAGE,
                code="privacy_violation",
            )
    if '": "/' in serialized:
        raise PermissionDoctorError(
            _PRIVACY_BOUNDARY_MESSAGE,
            code="privacy_violation",
        )


def infer_credential_posture_from_identity(identity: Mapping[str, Any] | None) -> CredentialPosture:
    """Infer credential posture from caller-provided metadata only."""

    if not identity:
        return "unknown"
    if identity.get("private_key_encrypted") or identity.get("encrypted_blob"):
        return "brokered"
    if identity.get("private_key_hex"):
        return "visible_static_key"
    if identity.get("registered") is True:
        return "short_lived_token"
    return "unknown"


def _capability_level(
    *,
    possible: bool,
    denied: bool = False,
) -> CapabilityLevel:
    if denied:
        return "no"
    if possible:
        return "possible"
    return "unknown"


def build_blast_radius_preview(
    classification: ClassifiedToolCall,
    *,
    reason: str,
    config: ProxyConfig | None = None,
    identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build bounded blast-radius preview from classification and policy metadata."""

    tool = classification.tool.lower()
    action_family = classification.action_family.lower()
    server = classification.server.lower()
    risk = classification.risk_class.value

    secret_access = any(marker in tool or marker in server for marker in _SECRET_TOOL_MARKERS)
    file_read = action_family in _READ_FAMILIES or tool.startswith(("read_", "get_", "list_", "fetch_"))
    file_write = action_family in _WRITE_FAMILIES or tool.startswith(("write_", "create_", "update_"))
    file_delete = action_family in {"delete", "remove"} or tool.startswith(("delete_", "remove_"))
    shell_execution = action_family in {"shell", "exec"} or any(m in tool for m in _SHELL_TOOL_MARKERS)
    package_install = any(m in tool for m in _PACKAGE_TOOL_MARKERS) or action_family == "install"
    external_network = any(m in tool for m in _NETWORK_TOOL_MARKERS)
    persistence_change = any(m in tool for m in _PERSISTENCE_TOOL_MARKERS) or file_write
    deploy_release = any(m in tool for m in _DEPLOY_TOOL_MARKERS) or action_family == "production"  # claim-check: allow "production" is bounded action-family vocabulary.

    if classification.role == "readonly" and file_write:
        file_write = False
        file_delete = False
        persistence_change = False

    preview: dict[str, Any] = {
        "tool": classification.tool,
        "server": classification.server,
        "action_family": classification.action_family,
        "risk_class": risk,
        "capabilities": {
            "secret_access": _capability_level(possible=secret_access),
            "file_read": _capability_level(possible=file_read),
            "file_write": _capability_level(possible=file_write),
            "file_delete": _capability_level(possible=file_delete),
            "shell_execution": _capability_level(possible=shell_execution),
            "package_install": _capability_level(possible=package_install),
            "external_network_send": _capability_level(possible=external_network),
            "persistence_config_change": _capability_level(possible=persistence_change),
            "deploy_release": _capability_level(possible=deploy_release),
        },
        "credential_posture": infer_credential_posture_from_identity(identity),
        "why_approval_required": reason,
        "policy_rule_id": classification.policy_evaluation.policy_rule_id,
    }
    if classification.role is not None:
        preview["role"] = classification.role
    if classification.authority is not None:
        preview["authority"] = classification.authority
    if config is not None and config.role_preset is not None:
        preview["role_preset"] = config.role_preset
    return preview


def format_blast_radius_summary(preview: Mapping[str, Any]) -> str:
    """Render one bounded blast-radius line for terminal approval output."""

    caps = preview.get("capabilities", {})
    if not isinstance(caps, Mapping):
        caps = {}
    parts = [
        "blast radius:",
        f"read={caps.get('file_read', 'unknown')}",
        f"write={caps.get('file_write', 'unknown')}",
        f"delete={caps.get('file_delete', 'unknown')}",
        f"secret={caps.get('secret_access', 'unknown')}",
        f"shell={caps.get('shell_execution', 'unknown')}",
        f"package={caps.get('package_install', 'unknown')}",
        f"network={caps.get('external_network_send', 'unknown')}",
        f"persist={caps.get('persistence_config_change', 'unknown')}",
        f"deploy={caps.get('deploy_release', 'unknown')}",
        f"credential={preview.get('credential_posture', 'unknown')}",
    ]
    return " ".join(str(part) for part in parts)


def blast_radius_lines(preview: Mapping[str, Any]) -> tuple[str, ...]:
    """Return human-readable blast-radius lines for doctor/approval surfaces."""

    caps = preview.get("capabilities", {})
    if not isinstance(caps, Mapping):
        caps = {}
    lines = [
        f"Secret access: {caps.get('secret_access', 'unknown')}",
        f"File read: {caps.get('file_read', 'unknown')}",
        f"File write: {caps.get('file_write', 'unknown')}",
        f"File delete: {caps.get('file_delete', 'unknown')}",
        f"Shell execution: {caps.get('shell_execution', 'unknown')}",
        f"Package install: {caps.get('package_install', 'unknown')}",
        f"External network/send: {caps.get('external_network_send', 'unknown')}",
        f"Persistence/config change: {caps.get('persistence_config_change', 'unknown')}",
        f"Deploy/release: {caps.get('deploy_release', 'unknown')}",
        f"Credential posture: {preview.get('credential_posture', 'unknown')}",
    ]
    why = preview.get("why_approval_required")
    if isinstance(why, str) and why:
        lines.append(f"Why approval required: {why}")
    return tuple(lines)


def derive_setup_mode(
    *,
    setup_status: str,
    client_routes_through_proxy: bool,
    direct_downstream_entries_count: int,
    bypass_risks: tuple[str, ...] | list[str],
    proxy_config_valid: bool,
    proxy_routed_entries_count: int = 0,
) -> SetupMode:
    """Derive doctor setup mode from actual setup files."""

    if not proxy_config_valid or setup_status == "incomplete":
        return "secure_unavailable"

    has_direct = direct_downstream_entries_count > 0
    has_routed = proxy_routed_entries_count > 0 or client_routes_through_proxy

    if has_direct and has_routed:
        return "partial"
    if setup_status == "bypass" or (has_direct and not has_routed):
        return "bypass"
    if setup_status == "partial":
        return "partial"
    if bypass_risks and client_routes_through_proxy:
        return "soft"
    if setup_status == "protected" and client_routes_through_proxy:
        return "controlled"
    if bypass_risks:
        return "soft"
    return "secure_unavailable"


def _redirect_coverage_lines() -> list[str]:
    lines = [item["summary"] for item in redirect_pack_summaries()]
    for playbook in redirect_playbook_coverage():
        lines.append(
            f"{playbook.get('redirect_playbook_id')}: {playbook.get('automation_level')}"
        )
    return lines


def _control_boundaries(
    *,
    setup_mode: SetupMode,
    bypass_risks: tuple[str, ...] | list[str],
    protected_packs: list[str],
) -> dict[str, list[str]]:
    controlled = [
        "Routed MCP tool calls through AgentVeil proxy",
        "Local policy evaluation before downstream execution",
    ]
    if protected_packs:
        controlled.append(
            "Policy coverage packs: " + ", ".join(protected_packs),
        )
    observed = [
        "Approval evidence and daily control status/timeline",
        "Bounded deny/redirect metadata and target_reached summaries",
    ]
    delegated = [
        "Provider-native IDE tools outside routed MCP",
        "Host shell and direct downstream paths not routed through AgentVeil",
    ]
    unsupported = [
        "Shell redirects unless routed through a controlled adapter",
        "Git/GitHub redirect playbooks (planned visibility only)",
        "Host-wide or provider-native execution control",
    ]
    bypass = list(bypass_risks)
    if setup_mode in {"bypass", "partial", "soft"}:
        bypass.append("Direct client/downstream routes may bypass AgentVeil")
    return {
        "controlled": controlled,
        "observed": observed,
        "delegated": delegated,
        "unsupported": unsupported,
        "bypass": bypass,
    }


def _protected_packs_from_config(config: ProxyConfig | None) -> list[str]:
    if config is None:
        return []
    packs: set[str] = set()
    for rule in config.policy.rules:
        servers = rule.match.server
        if isinstance(servers, str):
            if servers in {"filesystem", "git", "github", "shell", "package", "default"}:
                packs.add(servers)
        else:
            for item in servers:
                if item in {"filesystem", "git", "github", "shell", "package", "default"}:
                    packs.add(item)
    return sorted(packs)


def _count_proxy_routed_entries(
    document: Mapping[str, Any],
    *,
    proxy_command: str | None,
    config_path: Path,
) -> int:
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping):
        return 0
    return sum(
        1
        for entry in servers.values()
        if isinstance(entry, Mapping)
        and is_proxy_routed_mcp_entry(
            entry,
            proxy_command=proxy_command,
            config_path=config_path,
        )
    )


def build_permission_doctor_report(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_config_path: Path | None = None,
    proxy_command: str | None = None,
    identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build permission doctor report from actual setup/config metadata.

    ``identity`` must be caller-provided bounded metadata when credential posture
    is needed. Doctor does not read identity or credential files.
    """

    from agentveil_mcp_proxy.cli import proxy_paths

    paths = proxy_paths(home, proxy_config_path)
    setup_paths = resolve_setup_paths(home, proxy_config_path=paths.config_path)
    config_path = paths.config_path
    resolved_proxy_command = resolve_proxy_command(proxy_command)
    config_error: str | None = None
    config: ProxyConfig | None = None
    proxy_routed_entries_count = 0

    try:
        setup_report = derive_setup_status(
            home=home,
            client_id=client_id,
            proxy_command=proxy_command,
            proxy_config_path=config_path,
        )
        setup_payload = setup_status_to_dict(setup_report)
    except ConfigWizardError as exc:
        setup_payload = {
            "setup_status": "incomplete",
            "mode": None,
            "role_preset": None,
            "proxy_config_valid": False,
            "client_config_routes_through_agentveil": False,
            "direct_downstream_entries_count": 0,
            "bypass_risks": ["setup_status_unavailable"],
        }
        config_error = "setup_status_unavailable"

    if setup_paths.client_config_path.is_file():
        try:
            client_document = load_mcp_client_document(setup_paths.client_config_path)
            proxy_routed_entries_count = _count_proxy_routed_entries(
                client_document,
                proxy_command=resolved_proxy_command,
                config_path=config_path,
            )
        except ConfigWizardError:
            proxy_routed_entries_count = 0

    if config_path.is_file():
        try:
            raw_config = json.loads(config_path.read_text(encoding="utf-8"))
            config = ProxyConfig.from_dict(raw_config)
        except (ProxyConfigError, json.JSONDecodeError, OSError, TypeError, ValueError):
            setup_payload["setup_status"] = "incomplete"
            setup_payload["proxy_config_valid"] = False
            config_error = config_error or "proxy_config_invalid"

    setup_mode = derive_setup_mode(
        setup_status=str(setup_payload.get("setup_status", "incomplete")),
        client_routes_through_proxy=bool(
            setup_payload.get("client_config_routes_through_agentveil", False),
        ),
        direct_downstream_entries_count=int(
            setup_payload.get("direct_downstream_entries_count", 0),
        ),
        bypass_risks=tuple(setup_payload.get("bypass_risks", ())),
        proxy_config_valid=bool(setup_payload.get("proxy_config_valid", False)),
        proxy_routed_entries_count=proxy_routed_entries_count,
    )
    protected_packs = _protected_packs_from_config(config)
    boundaries = _control_boundaries(
        setup_mode=setup_mode,
        bypass_risks=tuple(setup_payload.get("bypass_risks", ())),
        protected_packs=protected_packs,
    )

    payload: dict[str, Any] = {
        "ok": config_error is None,
        "errors": [] if config_error is None else [config_error],
        "setup_mode": setup_mode,
        "isolation_posture": "secure_unavailable",
        "setup_status": setup_payload.get("setup_status"),
        "mode": setup_payload.get("mode"),
        "role_preset": setup_payload.get("role_preset") or (
            config.role_preset if config is not None else None
        ),
        "client_routes_through_proxy": setup_payload.get(
            "client_config_routes_through_agentveil",
            False,
        ),
        "direct_downstream_entries_count": setup_payload.get(
            "direct_downstream_entries_count",
            0,
        ),
        "proxy_routed_entries_count": proxy_routed_entries_count,
        "boundaries": boundaries,
        "redirect_coverage_lines": _redirect_coverage_lines(),
        "credential_posture": infer_credential_posture_from_identity(identity),
        "protected_packs": protected_packs,
    }
    assert_permission_doctor_output_is_privacy_safe(payload)
    assert "secure" != payload["setup_mode"]  # claim-check: allow negative assertion for bounded setup-mode vocabulary.
    return payload


def format_permission_doctor_report(payload: Mapping[str, Any]) -> str:
    """Render human-readable permission doctor output."""

    lines = [
        "Permission doctor",
        f"Setup mode: {payload.get('setup_mode', 'unknown')}",
        f"Isolation posture: {payload.get('isolation_posture', 'secure_unavailable')}",
        f"Setup status: {payload.get('setup_status', 'unknown')}",
        f"Role preset: {payload.get('role_preset', 'unknown')}",
        f"Client routes through proxy: {payload.get('client_routes_through_proxy', False)}",
        f"Direct downstream entries: {payload.get('direct_downstream_entries_count', 0)}",
        f"Credential posture: {payload.get('credential_posture', 'unknown')}",
        "Boundaries:",
    ]
    boundaries = payload.get("boundaries", {})
    if isinstance(boundaries, Mapping):
        for name in ("controlled", "observed", "delegated", "unsupported", "bypass"):
            items = boundaries.get(name, [])
            if not items:
                continue
            lines.append(f"  {name}:")
            for item in items:
                lines.append(f"    - {item}")
    lines.append("Redirect coverage:")
    for item in payload.get("redirect_coverage_lines", ()):
        lines.append(f"  - {item}")
    for error in payload.get("errors", ()):
        lines.append(f"ERROR: {error}")
    return "\n".join(lines)


__all__ = [
    "CapabilityLevel",
    "CredentialPosture",
    "PermissionDoctorError",
    "SetupMode",
    "assert_permission_doctor_output_is_privacy_safe",
    "blast_radius_lines",
    "build_blast_radius_preview",
    "build_permission_doctor_report",
    "derive_setup_mode",
    "format_blast_radius_summary",
    "format_permission_doctor_report",
    "infer_credential_posture_from_identity",
]
