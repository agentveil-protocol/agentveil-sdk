"""Proxy-routed MCP client config wizard for configured MCP client entries."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.agent_templates import (
    AGENT_TEMPLATE_NAMES,
    normalize_agent_template_name,
    resolve_agent_template,
    run_agent_template_init,
)
from agentveil_mcp_proxy.client_config import (
    CLIENT_TARGETS,
    ClientConfigError,
    DEFAULT_PROXY_COMMAND,
    DEFAULT_SERVER_NAME,
    assert_rendered_config_is_privacy_safe,
    format_client_config_text,
    read_role_preset_from_config,
    render_client_configs,
    resolve_proxy_command,
)

_PROXY_COMMAND_NAMES: tuple[str, ...] = (DEFAULT_PROXY_COMMAND,)
_DOWNSTREAM_BYPASS_MARKERS: tuple[str, ...] = (
    "quickstart_filesystem",
    "mcp-server",
    "@modelcontextprotocol/",
    "server-filesystem",
    "server-git",
    "server-fetch",
)
_BYPASS_GUIDANCE = (
    "Route MCP tools through agentveil-mcp-proxy run --config <proxy-config> "
    "instead of pointing the desktop client at downstream commands directly."
)


class ConfigWizardError(ValueError):
    """Raised when wizard input or rendered client config is unsafe."""


@dataclass(frozen=True)
class ProxyRoutingValidation:
    """Result of validating one MCP client config document."""

    ok: bool
    issues: tuple[str, ...]
    bypass_detected: bool
    guidance: str | None = None


@dataclass(frozen=True)
class SafeConfigWizardResult:
    """Bounded proxy-config wizard output for one agent template."""

    template_id: str
    role_preset: str
    home: Path
    config_path: Path
    sandbox_root: Path
    proxy_command: str
    client_id: str
    server_name: str
    rendered: dict[str, dict[str, Any]]
    validation: ProxyRoutingValidation


def _entry_tokens(entry: Mapping[str, Any]) -> tuple[str, ...]:
    command = entry.get("command")
    args = entry.get("args")
    tokens: list[str] = []
    if isinstance(command, str):
        tokens.append(command)
    if isinstance(args, list):
        tokens.extend(str(item) for item in args)
    return tuple(tokens)


def _proxy_config_arg_value(args: list[Any]) -> str | None:
    """Return the non-empty ``--config`` value from proxy run args, if present."""

    try:
        config_index = args.index("--config")
    except ValueError:
        return None
    if config_index + 1 >= len(args):
        return None
    value = args[config_index + 1]
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _proxy_command_matches(entry: Mapping[str, Any], *, proxy_command: str | None = None) -> bool:
    command = entry.get("command")
    if not isinstance(command, str):
        return False
    expected_command = resolve_proxy_command(proxy_command)
    command_name = _proxy_executable_name(command)
    expected_name = _proxy_executable_name(expected_command)
    return command_name == expected_name or command == expected_command


def _proxy_executable_name(command: str) -> str:
    """Return a comparable proxy executable name across POSIX and Windows paths."""

    name = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _is_incomplete_proxy_entry(
    entry: Mapping[str, Any],
    *,
    proxy_command: str | None = None,
) -> bool:
    """Return True when an entry targets the proxy but omits required run args."""

    args = entry.get("args")
    if not _proxy_command_matches(entry, proxy_command=proxy_command):
        return False
    if not isinstance(args, list) or not args or args[0] != "run":
        return False
    return _proxy_config_arg_value(args) is None


def is_proxy_routed_mcp_entry(
    entry: Mapping[str, Any],
    *,
    proxy_command: str | None = None,
    config_path: Path | None = None,
) -> bool:
    """Return True when one MCP server entry routes through the proxy run path."""

    command = entry.get("command")
    args = entry.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not args:
        return False
    if not _proxy_command_matches(entry, proxy_command=proxy_command):
        return False
    if args[0] != "run":
        return False
    config_value = _proxy_config_arg_value(args)
    if config_value is None:
        return False
    if config_path is not None:
        if Path(config_value).expanduser() != config_path.expanduser():
            return False
    return True


def detect_direct_downstream_bypass(
    document: Mapping[str, Any],
    *,
    proxy_command: str | None = None,
    config_path: Path | None = None,
) -> ProxyRoutingValidation:
    """Detect MCP client entries that bypass the proxy path."""

    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping):
        return ProxyRoutingValidation(
            ok=False,
            issues=("missing or invalid mcpServers object",),
            bypass_detected=True,
            guidance=_BYPASS_GUIDANCE,
        )

    issues: list[str] = []
    bypass_detected = False
    for server_name, entry in servers.items():
        if not isinstance(entry, Mapping):
            issues.append(f"{server_name}: invalid MCP server entry")
            bypass_detected = True
            continue
        if is_proxy_routed_mcp_entry(
            entry,
            proxy_command=proxy_command,
            config_path=config_path,
        ):
            continue
        if _is_incomplete_proxy_entry(entry, proxy_command=proxy_command):
            issues.append(f"{server_name}: proxy run args must include --config <proxy-config>")
        else:
            tokens = _entry_tokens(entry)
            joined = " ".join(tokens).lower()
            if any(marker in joined for marker in _DOWNSTREAM_BYPASS_MARKERS):
                issues.append(f"{server_name}: direct downstream MCP server bypasses proxy")
            else:
                command = entry.get("command")
                command_name = Path(str(command)).name if command is not None else ""
                if command_name not in _PROXY_COMMAND_NAMES:
                    issues.append(f"{server_name}: client command does not route through agentveil-mcp-proxy")
                else:
                    issues.append(
                        f"{server_name}: MCP server entry does not route through "
                        "agentveil-mcp-proxy run --config <proxy-config>"
                    )
        bypass_detected = True

    if issues:
        return ProxyRoutingValidation(
            ok=False,
            issues=tuple(issues),
            bypass_detected=bypass_detected,
            guidance=_BYPASS_GUIDANCE,
        )
    return ProxyRoutingValidation(ok=True, issues=(), bypass_detected=False)


def validate_mcp_client_document(
    document: Mapping[str, Any],
    *,
    proxy_command: str | None = None,
    config_path: Path | None = None,
) -> ProxyRoutingValidation:
    """Validate configured MCP server entries route through the proxy."""

    validation = detect_direct_downstream_bypass(
        document,
        proxy_command=proxy_command,
        config_path=config_path,
    )
    if not validation.ok:
        return validation
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping) or not servers:
        return ProxyRoutingValidation(
            ok=False,
            issues=("mcpServers must contain at least one proxy-routed entry",),
            bypass_detected=True,
            guidance=_BYPASS_GUIDANCE,
        )
    return validation


def assert_safe_proxy_routed_document(
    document: Mapping[str, Any],
    *,
    proxy_command: str | None = None,
    config_path: Path | None = None,
) -> None:
    """Raise when a rendered MCP client document would bypass the proxy."""

    validation = validate_mcp_client_document(
        document,
        proxy_command=proxy_command,
        config_path=config_path,
    )
    if validation.ok:
        return
    issue_text = "; ".join(validation.issues)
    raise ConfigWizardError(f"unsafe MCP client config: {issue_text}")


def document_contains_direct_downstream_command(document: Mapping[str, Any]) -> bool:
    """Return True when any MCP server entry points at downstream commands directly."""

    return detect_direct_downstream_bypass(document).bypass_detected


def build_safe_config_wizard_result(
    template_id: str,
    *,
    home: Path,
    sandbox_root: Path,
    client_id: str = "cursor",
    server_name: str = DEFAULT_SERVER_NAME,
    proxy_command: str | None = None,
    ensure_initialized: bool = False,
) -> SafeConfigWizardResult:
    """Render and validate proxy-routed MCP client config for one agent template."""

    spec = resolve_agent_template(template_id)
    resolved_home = home.expanduser()
    resolved_sandbox = sandbox_root.expanduser()
    config_path = resolved_home / "mcp-proxy" / "config.json"
    if ensure_initialized and not config_path.is_file():
        run_agent_template_init(
            template_id,
            home=resolved_home,
            sandbox_root=resolved_sandbox,
            force=False,
        )
    if not config_path.is_file():
        raise ConfigWizardError(
            f"proxy config not found at {config_path}; run template init or pass --init"
        )

    if client_id not in CLIENT_TARGETS:
        supported = ", ".join(sorted(CLIENT_TARGETS))
        raise ConfigWizardError(f"unsupported client {client_id!r}; supported: {supported}")

    resolved_proxy_command = resolve_proxy_command(proxy_command)
    try:
        rendered = render_client_configs(
            clients=[client_id],
            server_name=server_name,
            command=resolved_proxy_command,
            home=resolved_home,
            config_path=config_path,
        )
    except ClientConfigError as exc:
        raise ConfigWizardError(str(exc)) from exc

    document = rendered[client_id]
    assert_safe_proxy_routed_document(
        document,
        proxy_command=resolved_proxy_command,
        config_path=config_path,
    )
    assert_wizard_output_is_privacy_safe(
        rendered,
        proxy_command=resolved_proxy_command,
        config_path=config_path,
    )

    role_preset = read_role_preset_from_config(config_path) or spec.role_preset
    validation = validate_mcp_client_document(
        document,
        proxy_command=resolved_proxy_command,
        config_path=config_path,
    )
    return SafeConfigWizardResult(
        template_id=spec.template_id,
        role_preset=role_preset,
        home=resolved_home,
        config_path=config_path,
        sandbox_root=resolved_sandbox,
        proxy_command=resolved_proxy_command,
        client_id=client_id,
        server_name=server_name,
        rendered=rendered,
        validation=validation,
    )


def build_wizard_summary(result: SafeConfigWizardResult) -> dict[str, Any]:
    """Return bounded JSON-compatible wizard summary fields."""

    return {
        "template_id": result.template_id,
        "role_preset": result.role_preset,
        "home": str(result.home),
        "config_path": str(result.config_path),
        "sandbox_root": str(result.sandbox_root),
        "proxy_command": result.proxy_command,
        "client_id": result.client_id,
        "server_name": result.server_name,
        "bypass_detected": result.validation.bypass_detected,
        "proxy_routed": result.validation.ok,
        "issues": list(result.validation.issues),
        "guidance": result.validation.guidance,
    }


def format_wizard_summary_text(result: SafeConfigWizardResult) -> str:
    """Render a bounded human-readable wizard summary."""

    summary = build_wizard_summary(result)
    lines = [
        f"Template: {summary['template_id']}",
        f"Role preset: {summary['role_preset']}",
        f"Home: {summary['home']}",
        f"Config: {summary['config_path']}",
        f"Proxy command: {summary['proxy_command']}",
        f"Client: {summary['client_id']}",
        f"Proxy routed: {summary['proxy_routed']}",
        f"Bypass detected: {summary['bypass_detected']}",
    ]
    if summary["guidance"]:
        lines.append(f"Guidance: {summary['guidance']}")
    return "\n".join(lines)


def format_safe_config_wizard_output(result: SafeConfigWizardResult) -> str:
    """Render summary plus copy-paste MCP client config."""

    return (
        format_wizard_summary_text(result)
        + "\n\n"
        + format_client_config_text(result.rendered)
    )


def load_mcp_client_document(path: Path) -> dict[str, Any]:
    """Load one MCP client JSON document for wizard validation."""

    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigWizardError(f"unable to read MCP client config: {path}") from exc
    if not isinstance(payload, dict):
        raise ConfigWizardError("MCP client config must be a JSON object")
    return payload


def assert_wizard_output_is_privacy_safe(
    rendered: Mapping[str, Mapping[str, Any]],
    *,
    proxy_command: str,
    config_path: Path,
    forbidden_substrings: tuple[str, ...] = (),
) -> None:
    """Reject wizard output that could leak secrets or private key material."""

    payload = {
        "rendered": rendered,
        "proxy_command": proxy_command,
        "config_path": str(config_path),
    }
    serialized = json.dumps(payload, sort_keys=True).lower()
    for marker in (
        "private_key",
        "secret_",
        "api_key",
        "ssh-rsa",
        "begin private key",
        *forbidden_substrings,
    ):
        if marker and marker.lower() in serialized:
            raise ConfigWizardError(f"wizard output must not include {marker!r}")
    assert_rendered_config_is_privacy_safe(rendered, forbidden_substrings=forbidden_substrings)


__all__ = [
    "AGENT_TEMPLATE_NAMES",
    "ConfigWizardError",
    "ProxyRoutingValidation",
    "SafeConfigWizardResult",
    "assert_safe_proxy_routed_document",
    "assert_wizard_output_is_privacy_safe",
    "build_safe_config_wizard_result",
    "build_wizard_summary",
    "detect_direct_downstream_bypass",
    "document_contains_direct_downstream_command",
    "format_safe_config_wizard_output",
    "format_wizard_summary_text",
    "is_proxy_routed_mcp_entry",
    "load_mcp_client_document",
    "normalize_agent_template_name",
    "validate_mcp_client_document",
]
