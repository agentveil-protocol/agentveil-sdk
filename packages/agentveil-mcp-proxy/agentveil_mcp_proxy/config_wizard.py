"""Proxy-routed MCP client config wizard for configured MCP client entries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from agentveil_mcp_proxy.agent_templates import (
    AGENT_TEMPLATE_NAMES,
    normalize_agent_template_name,
    resolve_agent_template,
    run_agent_template_init,
)
from agentveil_mcp_proxy.adaptive_setup import (
    AdaptiveSetupResult,
    ToolInventoryEntry,
    plan_adaptive_setup,
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
    setup_client_config_path,
)
from agentveil_mcp_proxy.role_presets import (
    DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET,
    SAFE_AUTOPILOT_USER_LABEL,
    user_facing_setup_label,
)
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError

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

    def __init__(
        self,
        message: str,
        *,
        target: str | None = None,
        basename: str | None = None,
    ) -> None:
        super().__init__(message)
        self.target = target
        self.basename = basename


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
    setup_label = (
        SAFE_AUTOPILOT_USER_LABEL
        if summary["role_preset"] == DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET
        else user_facing_setup_label(
            role_preset=str(summary["role_preset"]),
            explicit_role=True,
        )
    )
    lines = [
        f"Template: {summary['template_id']}",
        f"Setup: {setup_label}",
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


SetupStatusValue = Literal["protected", "partial", "bypass", "incomplete"]
_SETUP_MANIFEST_NAME = "setup-manifest.json"
_DEFAULT_TRUSTED_SIGNER_DID = "did:key:z6MktrustedSigner"


@dataclass(frozen=True)
class SetupBackupRef:
    """Bounded backup metadata for one setup-managed file."""

    basename: str
    hash: str
    created_at: str


@dataclass(frozen=True)
class SetupPaths:
    """Filesystem locations used by the adaptive setup wizard."""

    home: Path
    proxy_config_path: Path
    client_config_path: Path
    backup_dir: Path
    manifest_path: Path


@dataclass(frozen=True)
class SetupStatusReport:
    """Structured setup/status output derived from actual files."""

    setup_status: SetupStatusValue
    mode: str | None
    role_preset: str | None
    proxy_config_valid: bool
    client_config_routes_through_agentveil: bool
    direct_downstream_entries_count: int
    bypass_risks: tuple[str, ...]
    backup_ref: SetupBackupRef | None


@dataclass(frozen=True)
class SetupWizardResult:
    """Result of one adaptive setup run."""

    ok: bool
    setup_status: SetupStatusValue
    summary: dict[str, Any]
    proxy_config_written: bool
    client_config_written: bool
    backup_refs: tuple[SetupBackupRef, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class SetupRestoreResult:
    """Result of restoring setup-managed files from backups."""

    ok: bool
    restored_targets: tuple[str, ...]
    restored_refs: tuple[Mapping[str, str], ...]
    errors: tuple[str, ...]


def resolve_setup_paths(
    home: Path,
    *,
    client_id: str = "cursor",
    proxy_config_path: Path | None = None,
) -> SetupPaths:
    """Return setup-managed paths under one AVP home."""

    resolved_home = home.expanduser()
    proxy_dir = resolved_home / "mcp-proxy"
    config_path = (
        proxy_config_path.expanduser()
        if proxy_config_path is not None
        else proxy_dir / "config.json"
    )
    return SetupPaths(
        home=resolved_home,
        proxy_config_path=config_path,
        client_config_path=setup_client_config_path(resolved_home, client_id),
        backup_dir=proxy_dir / "backups",
        manifest_path=proxy_dir / _SETUP_MANIFEST_NAME,
    )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _public_content_hash(content: bytes) -> str:
    return f"sha256:{_content_hash(content)}"


def _config_file_ref(target: str, path: Path) -> dict[str, str]:
    """Return bounded metadata for one setup-managed config file."""

    expanded = path.expanduser()
    if expanded.is_file():
        digest = _public_content_hash(expanded.read_bytes())
    else:
        digest = ""
    return {
        "target": target,
        "basename": expanded.name,
        "hash": digest,
    }


def _setup_target_for_basename(name: str) -> str:
    if name == "config.json":
        return "proxy"
    if name.endswith("-mcp.json"):
        return "client"
    return "file"


def format_setup_error_payload(exc: ConfigWizardError, *, ok: bool = False) -> dict[str, Any]:
    """Return bounded JSON-compatible setup error output."""

    message = str(exc)
    payload: dict[str, Any] = {
        "ok": ok,
        "error": message,
        "errors": [message],
    }
    if exc.target is not None:
        payload["target"] = exc.target
    if exc.basename is not None:
        payload["basename"] = exc.basename
    return payload


def create_file_backup(
    path: Path,
    backup_dir: Path,
    *,
    target: str | None = None,
) -> SetupBackupRef:
    """Copy one file into the bounded setup backup directory."""

    source = path.expanduser()
    if not source.is_file():
        resolved_target = target or _setup_target_for_basename(source.name)
        raise ConfigWizardError(
            f"cannot back up missing file: {source.name}",
            target=resolved_target,
            basename=source.name,
        )
    backup_dir.mkdir(parents=True, exist_ok=True)
    created_at = _utc_now_iso()
    timestamp = created_at.replace(":", "").replace("-", "")
    basename = f"{source.name}.{timestamp}.bak"
    destination = backup_dir / basename
    content = source.read_bytes()
    destination.write_bytes(content)
    return SetupBackupRef(
        basename=basename,
        hash=_content_hash(content),
        created_at=created_at,
    )


def restore_file_from_backup(
    backup_path: Path,
    target_path: Path,
    *,
    kind: str | None = None,
) -> bytes:
    """Restore one file from a backup path and return restored bytes."""

    backup = backup_path.expanduser()
    destination = target_path.expanduser()
    if not backup.is_file():
        label = kind or "backup"
        raise ConfigWizardError(
            f"{label} backup not found",
            target=label if label in {"proxy", "client"} else None,
            basename=backup.name,
        )
    content = backup.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(destination.suffix + ".restore.tmp")
    try:
        temp_path.write_bytes(content)
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists() and not destination.exists():
            temp_path.unlink(missing_ok=True)
    return content


def _atomic_write_bytes(
    target_path: Path,
    content: bytes,
    *,
    backup_dir: Path,
) -> SetupBackupRef | None:
    """Write bytes atomically after creating a backup when the target exists."""

    target = target_path.expanduser()
    backup_ref: SetupBackupRef | None = None
    if target.is_file():
        backup_ref = create_file_backup(target, backup_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_suffix(target.suffix + ".tmp")
    try:
        temp_path.write_bytes(content)
        os.replace(temp_path, target)
    except OSError:
        if backup_ref is not None:
            restore_file_from_backup(backup_dir / backup_ref.basename, target)
        raise
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
    return backup_ref


def parse_tool_inventory(payload: Any) -> tuple[ToolInventoryEntry, ...]:
    """Parse bounded metadata-only tool inventory rows."""

    if not isinstance(payload, Sequence) or isinstance(payload, (str, bytes, bytearray)):
        raise ConfigWizardError("tool inventory must be a JSON array")
    entries: list[ToolInventoryEntry] = []
    for index, item in enumerate(payload):
        if not isinstance(item, Mapping):
            raise ConfigWizardError(f"tool inventory[{index}] must be an object")
        tool_name = item.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ConfigWizardError(f"tool inventory[{index}] requires tool_name")
        capabilities = item.get("capabilities", ())
        if capabilities is None:
            capabilities = ()
        if not isinstance(capabilities, Sequence) or isinstance(capabilities, (str, bytes)):
            raise ConfigWizardError(f"tool inventory[{index}].capabilities must be a list")
        server_label = item.get("server_label")
        path_hint = item.get("path_hint")
        category_hint = item.get("category_hint")
        entries.append(
            ToolInventoryEntry(
                tool_name=tool_name.strip(),
                server_label=server_label if isinstance(server_label, str) else None,
                capabilities=tuple(str(value) for value in capabilities),
                path_hint=path_hint if isinstance(path_hint, str) else None,
                category_hint=category_hint if isinstance(category_hint, str) else None,
            )
        )
    return tuple(entries)


def load_tool_inventory_file(path: Path) -> tuple[ToolInventoryEntry, ...]:
    """Load tool inventory metadata from one JSON file."""

    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigWizardError(
            f"unable to read tool inventory: {path.name}",
            target="inventory",
            basename=path.name,
        ) from exc
    return parse_tool_inventory(payload)


def _backup_ref_to_dict(ref: SetupBackupRef | None) -> dict[str, str] | None:
    if ref is None:
        return None
    digest = f"sha256:{ref.hash}" if ref.hash else ""
    return {
        "basename": ref.basename,
        "hash": digest,
        "created_at": ref.created_at,
    }


def _backup_ref_from_dict(payload: Mapping[str, Any] | None) -> SetupBackupRef | None:
    if not isinstance(payload, Mapping):
        return None
    basename = payload.get("basename")
    digest = payload.get("hash")
    created_at = payload.get("created_at")
    if not (
        isinstance(basename, str)
        and basename.strip()
        and isinstance(digest, str)
        and digest.strip()
        and isinstance(created_at, str)
        and created_at.strip()
    ):
        return None
    if digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    return SetupBackupRef(basename=basename, hash=digest, created_at=created_at)


def _write_setup_manifest(
    manifest_path: Path,
    *,
    mode: str | None,
    role_preset: str | None,
    setup_complete: bool,
    config_validatable: bool,
    proxy_backup: SetupBackupRef | None,
    client_backup: SetupBackupRef | None,
) -> None:
    payload = {
        "last_setup_at": _utc_now_iso(),
        "mode": mode,
        "role_preset": role_preset,
        "setup_complete": setup_complete,
        "config_validatable": config_validatable,
        "proxy_backup": _backup_ref_to_dict(proxy_backup),
        "client_backup": _backup_ref_to_dict(client_backup),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_setup_manifest(manifest_path: Path) -> dict[str, Any] | None:
    if not manifest_path.is_file():
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _proxy_config_is_valid(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    try:
        ProxyConfig.from_dict(payload)
    except ProxyConfigError:
        return False
    return True


def _read_proxy_mode_and_preset(path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(payload, dict):
        return None, None
    role_preset = payload.get("role_preset")
    mode = None
    if role_preset == "reviewer":
        mode = "review"
    elif isinstance(role_preset, str):
        mode = role_preset
    return (
        mode if isinstance(mode, str) else None,
        role_preset if isinstance(role_preset, str) else None,
    )


def _count_direct_downstream_entries(document: Mapping[str, Any]) -> int:
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping):
        return 0
    return sum(
        1
        for entry in servers.values()
        if isinstance(entry, Mapping)
        and not is_proxy_routed_mcp_entry(entry)
    )


def derive_setup_status(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_command: str | None = None,
    proxy_config_path: Path | None = None,
) -> SetupStatusReport:
    """Derive setup status from actual proxy and client config files."""

    paths = resolve_setup_paths(
        home,
        client_id=client_id,
        proxy_config_path=proxy_config_path,
    )
    resolved_proxy_command = resolve_proxy_command(proxy_command)
    proxy_valid = _proxy_config_is_valid(paths.proxy_config_path)
    mode, role_preset = _read_proxy_mode_and_preset(paths.proxy_config_path)
    manifest = _load_setup_manifest(paths.manifest_path)
    backup_ref = _backup_ref_from_dict(manifest.get("proxy_backup") if manifest else None)

    client_exists = paths.client_config_path.is_file()
    client_routes = False
    bypass_risks: list[str] = []
    downstream_count = 0

    if client_exists:
        try:
            document = load_mcp_client_document(paths.client_config_path)
        except ConfigWizardError:
            document = {}
        downstream_count = _count_direct_downstream_entries(document)
        validation = validate_mcp_client_document(
            document,
            proxy_command=resolved_proxy_command,
            config_path=paths.proxy_config_path,
        )
        client_routes = validation.ok
        bypass_risks.extend(validation.issues)
    elif paths.proxy_config_path.is_file():
        bypass_risks.append("client config file is missing")

    if not paths.proxy_config_path.is_file():
        setup_status: SetupStatusValue = "incomplete"
    elif not proxy_valid:
        setup_status = "incomplete"
    elif not client_exists:
        setup_status = "partial"
    elif client_routes and downstream_count == 0:
        setup_status = "protected"
    elif downstream_count > 0 and not client_routes:
        setup_status = "bypass"
    elif client_routes:
        setup_status = "protected"
    else:
        setup_status = "partial"

    if manifest and manifest.get("setup_complete") is False:
        setup_status = "incomplete"
    if manifest and manifest.get("config_validatable") is False:
        setup_status = "incomplete"

    return SetupStatusReport(
        setup_status=setup_status,
        mode=mode,
        role_preset=role_preset,
        proxy_config_valid=proxy_valid,
        client_config_routes_through_agentveil=client_routes,
        direct_downstream_entries_count=downstream_count,
        bypass_risks=tuple(bypass_risks),
        backup_ref=backup_ref,
    )


def build_setup_summary(
    *,
    plan_result: AdaptiveSetupResult,
    setup_status: SetupStatusValue,
    proxy_config_path: Path,
    client_config_path: Path | None = None,
    client_document: Mapping[str, Any] | None,
    client_validation: ProxyRoutingValidation | None,
) -> dict[str, Any]:
    """Return bounded setup summary aligned with generated config files."""

    summary_lines = list(plan_result.summary.lines)
    client_routes = client_validation.ok if client_validation is not None else False
    summary: dict[str, Any] = {
        "mode": plan_result.plan.mode,
        "role_preset": plan_result.plan.role_preset,
        "packs": list(plan_result.plan.packs),
        "overlays": [item.overlay_id for item in plan_result.plan.overlays],
        "unsupported_overlays": [
            item.overlay_id for item in plan_result.plan.overlays if not item.config_mappable
        ],
        "unknown_tools": list(plan_result.plan.unknown_tools),
        "requires_classification": plan_result.plan.requires_classification,
        "config_validatable": plan_result.plan.config_validatable,
        "setup_status": setup_status,
        "proxy_config_valid": plan_result.config_validated,
        "client_config_routes_through_agentveil": client_routes,
        "summary_lines": summary_lines,
        "protection_status": plan_result.plan.protection_status,
        "routing_active": plan_result.plan.routing_active,
    }
    if proxy_config_path.is_file():
        summary["proxy_config_ref"] = _config_file_ref("proxy", proxy_config_path)
    if client_config_path is not None and client_config_path.is_file():
        summary["client_config_ref"] = _config_file_ref("client", client_config_path)
    return summary


def setup_status_to_dict(status: SetupStatusReport) -> dict[str, Any]:
    """Return JSON-compatible structured setup status fields."""

    payload: dict[str, Any] = {
        "setup_status": status.setup_status,
        "mode": status.mode,
        "role_preset": status.role_preset,
        "proxy_config_valid": status.proxy_config_valid,
        "client_config_routes_through_agentveil": status.client_config_routes_through_agentveil,
        "direct_downstream_entries_count": status.direct_downstream_entries_count,
        "bypass_risks": list(status.bypass_risks),
    }
    if status.backup_ref is not None:
        payload["backup_ref"] = _backup_ref_to_dict(status.backup_ref)
    return payload


def run_setup_wizard(
    *,
    home: Path,
    inventory: Sequence[ToolInventoryEntry],
    requested_mode: str | None = "review",
    overlays: Sequence[str] = (),
    client_id: str = "cursor",
    server_name: str = DEFAULT_SERVER_NAME,
    proxy_command: str | None = None,
    agent_name: str = "adaptive-setup",
    avp_base_url: str = "https://agentveil.dev",
    trusted_signer_did: str = _DEFAULT_TRUSTED_SIGNER_DID,
) -> SetupWizardResult:
    """Run adaptive setup, write configs with backup, and return bounded output."""

    if client_id not in CLIENT_TARGETS:
        supported = ", ".join(sorted(CLIENT_TARGETS))
        raise ConfigWizardError(f"unsupported client {client_id!r}; supported: {supported}")

    paths = resolve_setup_paths(home, client_id=client_id)
    resolved_proxy_command = resolve_proxy_command(proxy_command)
    plan_result = plan_adaptive_setup(
        inventory,
        requested_mode=requested_mode,
        overlays=overlays,
        avp_agent_name=agent_name,
        avp_base_url=avp_base_url,
        trusted_signer_did=trusted_signer_did,
    )

    if not plan_result.plan.config_validatable:
        _write_setup_manifest(
            paths.manifest_path,
            mode=plan_result.plan.mode,
            role_preset=plan_result.plan.role_preset,
            setup_complete=False,
            config_validatable=False,
            proxy_backup=None,
            client_backup=None,
        )
        status = derive_setup_status(
            home=paths.home,
            client_id=client_id,
            proxy_command=resolved_proxy_command,
            proxy_config_path=paths.proxy_config_path,
        )
        summary = build_setup_summary(
            plan_result=plan_result,
            setup_status="incomplete",
            proxy_config_path=paths.proxy_config_path,
            client_config_path=paths.client_config_path,
            client_document=None,
            client_validation=None,
        )
        reason = plan_result.plan.unsupported_reason or "adaptive setup plan is not config-validatable"
        return SetupWizardResult(
            ok=False,
            setup_status="incomplete",
            summary=summary,
            proxy_config_written=False,
            client_config_written=False,
            backup_refs=(),
            errors=(reason,),
        )

    proxy_backup: SetupBackupRef | None = None
    client_backup: SetupBackupRef | None = None
    original_proxy = (
        paths.proxy_config_path.read_bytes()
        if paths.proxy_config_path.is_file()
        else None
    )
    original_client = (
        paths.client_config_path.read_bytes()
        if paths.client_config_path.is_file()
        else None
    )

    try:
        proxy_text = json.dumps(plan_result.config_data, indent=2, sort_keys=True) + "\n"
        proxy_backup = _atomic_write_bytes(
            paths.proxy_config_path,
            proxy_text.encode("utf-8"),
            backup_dir=paths.backup_dir,
        )

        rendered = render_client_configs(
            clients=[client_id],
            server_name=server_name,
            command=resolved_proxy_command,
            home=paths.home,
            config_path=paths.proxy_config_path,
        )
        client_document = rendered[client_id]
        assert_safe_proxy_routed_document(
            client_document,
            proxy_command=resolved_proxy_command,
            config_path=paths.proxy_config_path,
        )
        client_text = json.dumps(client_document, indent=2, sort_keys=True) + "\n"
        client_backup = _atomic_write_bytes(
            paths.client_config_path,
            client_text.encode("utf-8"),
            backup_dir=paths.backup_dir,
        )
    except (ClientConfigError, ConfigWizardError, OSError) as exc:
        if original_proxy is not None:
            paths.proxy_config_path.write_bytes(original_proxy)
        elif paths.proxy_config_path.is_file():
            paths.proxy_config_path.unlink(missing_ok=True)
        if original_client is not None:
            paths.client_config_path.write_bytes(original_client)
        elif paths.client_config_path.is_file():
            paths.client_config_path.unlink(missing_ok=True)
        return SetupWizardResult(
            ok=False,
            setup_status="incomplete",
            summary=build_setup_summary(
                plan_result=plan_result,
                setup_status="incomplete",
                proxy_config_path=paths.proxy_config_path,
                client_config_path=paths.client_config_path,
                client_document=None,
                client_validation=None,
            ),
            proxy_config_written=False,
            client_config_written=False,
            backup_refs=tuple(ref for ref in (proxy_backup, client_backup) if ref is not None),
            errors=(str(exc),),
        )

    client_validation = validate_mcp_client_document(
        client_document,
        proxy_command=resolved_proxy_command,
        config_path=paths.proxy_config_path,
    )
    _write_setup_manifest(
        paths.manifest_path,
        mode=plan_result.plan.mode,
        role_preset=plan_result.plan.role_preset,
        setup_complete=True,
        config_validatable=True,
        proxy_backup=proxy_backup,
        client_backup=client_backup,
    )
    status = derive_setup_status(
        home=paths.home,
        client_id=client_id,
        proxy_command=resolved_proxy_command,
        proxy_config_path=paths.proxy_config_path,
    )
    summary = build_setup_summary(
        plan_result=plan_result,
        setup_status=status.setup_status,
        proxy_config_path=paths.proxy_config_path,
        client_config_path=paths.client_config_path,
        client_document=client_document,
        client_validation=client_validation,
    )
    backup_refs = tuple(ref for ref in (proxy_backup, client_backup) if ref is not None)
    return SetupWizardResult(
        ok=status.setup_status == "protected",
        setup_status=status.setup_status,
        summary=summary,
        proxy_config_written=True,
        client_config_written=True,
        backup_refs=backup_refs,
        errors=(),
    )


def restore_setup_files(
    *,
    home: Path,
    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    target: Literal["proxy", "client", "all"] = "all",
    client_id: str = "cursor",
) -> SetupRestoreResult:
    """Restore setup-managed files from recorded backups."""

    paths = resolve_setup_paths(home, client_id=client_id)
    manifest = _load_setup_manifest(paths.manifest_path)
    if manifest is None:
        return SetupRestoreResult(
            ok=False,
            restored_targets=(),
            restored_refs=(),
            errors=("setup manifest not found",),
        )

    restored: list[str] = []
    restored_refs: list[dict[str, str]] = []
    errors: list[str] = []

    def _restore_one(kind: str, ref: SetupBackupRef | None, destination: Path) -> None:
        if ref is None:
            errors.append(f"{kind} backup ref missing")
            return
        backup_path = paths.backup_dir / ref.basename
        if not backup_path.is_file():
            errors.append(f"{kind} backup not found")
            return
        try:
            content = restore_file_from_backup(backup_path, destination, kind=kind)
            if _content_hash(content) != ref.hash:
                errors.append(f"{kind} backup hash mismatch")
                return
            restored.append(kind)
            restored_refs.append(_config_file_ref(kind, destination))
        except ConfigWizardError:
            errors.append(f"{kind} restore failed")

    proxy_backup = _backup_ref_from_dict(manifest.get("proxy_backup"))
    client_backup = _backup_ref_from_dict(manifest.get("client_backup"))

    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    if target in {"proxy", "all"}:
        _restore_one("proxy", proxy_backup, paths.proxy_config_path)
    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    if target in {"client", "all"}:
        _restore_one("client", client_backup, paths.client_config_path)

    if restored and paths.proxy_config_path.is_file():
        mode, role_preset = _read_proxy_mode_and_preset(paths.proxy_config_path)
        proxy_valid = _proxy_config_is_valid(paths.proxy_config_path)
        client_exists = paths.client_config_path.is_file()
        _write_setup_manifest(
            paths.manifest_path,
            mode=mode,
            role_preset=role_preset,
            setup_complete=proxy_valid and client_exists,
            config_validatable=proxy_valid,
            proxy_backup=proxy_backup,
            client_backup=client_backup,
        )

    return SetupRestoreResult(
        ok=bool(restored) and not errors,
        restored_targets=tuple(restored),
        restored_refs=tuple(restored_refs),
        errors=tuple(errors),
    )


def setup_restore_to_dict(result: SetupRestoreResult) -> dict[str, Any]:
    """Return bounded JSON-compatible restore output."""

    return {
        "ok": result.ok,
        "restored_targets": list(result.restored_targets),
        "restored_refs": [dict(item) for item in result.restored_refs],
        "errors": list(result.errors),
    }


def assert_setup_output_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    """Reject setup output that could leak secrets, raw config contents, or full paths."""

    serialized = json.dumps(payload, sort_keys=True)
    lowered = serialized.lower()
    for marker in (
        "private_key",
        "api_key",
        "ssh-rsa",
        "begin private key",
        "password",
        "stdout",
        "stderr",
        "/private/",
        "/var/folders/",
        "/users/",
    ):
        if marker in lowered:
            raise ConfigWizardError(f"setup output must not include {marker!r}")
    if '": "/' in serialized or '": "/' in lowered:
        raise ConfigWizardError("setup output must not include absolute local filesystem paths")


__all__ = [
    "AGENT_TEMPLATE_NAMES",
    "ConfigWizardError",
    "ProxyRoutingValidation",
    "SafeConfigWizardResult",
    "SetupBackupRef",
    "SetupPaths",
    "SetupRestoreResult",
    "SetupStatusReport",
    "SetupStatusValue",
    "SetupWizardResult",
    "assert_safe_proxy_routed_document",
    "assert_setup_output_is_privacy_safe",
    "assert_wizard_output_is_privacy_safe",
    "build_safe_config_wizard_result",
    "build_setup_summary",
    "build_wizard_summary",
    "create_file_backup",
    "derive_setup_status",
    "detect_direct_downstream_bypass",
    "document_contains_direct_downstream_command",
    "format_safe_config_wizard_output",
    "format_setup_error_payload",
    "format_wizard_summary_text",
    "is_proxy_routed_mcp_entry",
    "load_mcp_client_document",
    "load_tool_inventory_file",
    "normalize_agent_template_name",
    "parse_tool_inventory",
    "resolve_setup_paths",
    "restore_file_from_backup",
    "restore_setup_files",
    "run_setup_wizard",
    "setup_restore_to_dict",
    "setup_status_to_dict",
    "validate_mcp_client_document",
]
