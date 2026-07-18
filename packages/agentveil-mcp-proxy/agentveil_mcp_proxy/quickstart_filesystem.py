"""Tiny stdio MCP server for `agentveil-mcp-proxy --quickstart-filesystem`.

This server is intentionally small and sandbox-rooted. It exists so a fresh
install can exercise MCP initialize, tools/list, and simple filesystem tool
calls without installing an external Node-based MCP server first.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping

HASH_PREFIX = "sha256:"
AGENTVEIL_CONTROL_PATH_DENIED = "agentveil control path access denied"
INSTRUCTION_SURFACE_RISK_MESSAGE = (
    "Repo instruction files detected; risky changes need approval."
)
INSTRUCTION_SURFACE_RULE_ID = "instruction_surface_detected"
_INSTRUCTION_SURFACE_BASENAMES = frozenset({
    "agents.md",
    "claude.md",
    ".cursorrules",
})
_COPILOT_INSTRUCTIONS_PATH = (".github", "copilot-instructions.md")
# Exact metadata components hidden from list_workspace; unrelated dotfiles stay visible.
_LISTING_HIDDEN_METADATA_COMPONENTS = frozenset({".git", ".avp"})


def normalized_relative_path_segments(path: str) -> list[str]:
    """Return normalized relative path segments without ``.`` entries."""

    normalized = path.replace("\\", "/")
    resolved = posixpath.normpath(normalized)
    return [segment for segment in resolved.split("/") if segment and segment != "."]


def is_agentveil_control_relative_path(path: str) -> bool:
    """Return True when ``path`` lexically appears under ``.avp/mcp-proxy/``."""

    lowered = [segment.lower() for segment in normalized_relative_path_segments(path)]
    for index, segment in enumerate(lowered):
        if (
            segment == ".avp"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "mcp-proxy"
        ):
            return True
    return False


def is_hidden_listing_relative_path(path: str) -> bool:
    """Return True when ``path`` lexically includes a listing-hidden metadata component.

    Exact segment match only: ``.git/config`` and ``.avp/state.json`` are hidden,
    while ``docs/my.git.notes`` and ``docs/avp-guide.md`` stay visible.
    """

    lowered = [segment.lower() for segment in normalized_relative_path_segments(path)]
    return any(segment in _LISTING_HIDDEN_METADATA_COMPONENTS for segment in lowered)


def _root_resolved(root: Path) -> Path:
    return root.expanduser().resolve()


def agentveil_control_root(root: Path) -> Path:
    """Return the resolved AgentVeil control directory under ``root``."""

    return (_root_resolved(root) / ".avp" / "mcp-proxy").resolve()


def listing_metadata_roots(root: Path) -> tuple[Path, ...]:
    """Return resolved ``.git`` and ``.avp`` roots under the sandbox."""

    root_resolved = _root_resolved(root)
    return tuple(
        (root_resolved / name).resolve()
        for name in sorted(_LISTING_HIDDEN_METADATA_COMPONENTS)
    )


def is_resolved_path_under_agentveil_control(root: Path, resolved: Path) -> bool:
    """Return True when a resolved filesystem target is inside the control root."""

    control_root = agentveil_control_root(root)
    try:
        target = resolved.resolve()
    except OSError:
        return False
    if target == control_root:
        return True
    try:
        target.relative_to(control_root)
    except ValueError:
        return False
    return True


def is_resolved_path_under_listing_metadata(root: Path, resolved: Path) -> bool:
    """Return True when a resolved target lives under ``.git`` or ``.avp``."""

    try:
        target = resolved.resolve()
    except OSError:
        return False
    for meta_root in listing_metadata_roots(root):
        if target == meta_root:
            return True
        try:
            target.relative_to(meta_root)
        except ValueError:
            continue
        return True
    return False


def quickstart_sandbox_root_from_downstream_args(args: list[str]) -> Path | None:
    """Extract the quickstart sandbox root from downstream launch args."""

    if len(args) < 2:
        return None
    server_script = str(args[0])
    if "quickstart_filesystem" not in server_script:
        return None
    try:
        return Path(args[1]).expanduser().resolve()
    except OSError:
        return None


JSONRPC_VERSION = "2.0"


def _response(request_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": dict(result)}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _instruction_surface_type_for_path(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    parts = [
        segment
        for segment in normalized.split("/")
        if segment and segment not in (".", "..")
    ]
    lowered = [segment.lower() for segment in parts]
    if not lowered:
        return None
    basename = lowered[-1]
    if basename in _INSTRUCTION_SURFACE_BASENAMES:
        return basename.replace(".", "_")
    if len(lowered) >= 2 and tuple(lowered[-2:]) == _COPILOT_INSTRUCTIONS_PATH:
        return "github_copilot_instructions"
    for index, segment in enumerate(lowered):
        if (
            segment == ".cursor"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "rules"
        ):
            return "cursor_rules"
    return None


def _size_bucket(byte_count: int) -> str:
    if byte_count <= 4096:
        return "small"
    if byte_count <= 65536:
        return "medium"
    return "large"


def _scan_instruction_surfaces(root: Path) -> list[dict[str, str]]:
    if not root.is_dir():
        return []
    surfaces: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(root.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(root).as_posix()
        surface_type = _instruction_surface_type_for_path(relative)
        if surface_type is None:
            continue
        stat = item.stat()
        basename = item.name
        ref = HASH_PREFIX + hashlib.sha256(
            f"{surface_type}:{basename}:{stat.st_size}".encode("utf-8")
        ).hexdigest()
        key = (surface_type, basename)
        if key in seen:
            continue
        seen.add(key)
        surfaces.append({
            "surface_type": surface_type,
            "basename": basename,
            "size_bucket": _size_bucket(stat.st_size),
            "ref": ref,
            "rule_id": INSTRUCTION_SURFACE_RULE_ID,
        })
    return surfaces


def _summarize_instruction_surface_risk(surfaces: list[dict[str, str]]) -> dict[str, object]:
    detected = bool(surfaces)
    return {
        "instruction_surfaces_detected": detected,
        "instruction_surface_count": len(surfaces),
        "instruction_surface_risk_message": (
            INSTRUCTION_SURFACE_RISK_MESSAGE if detected else None
        ),
        "instruction_surfaces": list(surfaces),
    }


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "list_workspace",
            "description": "List files under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "read_file",
            "description": "Read a UTF-8 text file under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "get_file_info",
            "description": "Return bounded metadata for one file under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "instruction_surface_status",
            "description": (
                "Return bounded metadata when repo instruction files are present."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "local_proof",
            "description": (
                "Return bounded local AgentVeil proof/evidence summary without shell."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "last": {
                        "type": "integer",
                        "description": "Maximum number of recent evidence events to return.",
                    },
                    "verify": {
                        "type": "boolean",
                        "description": "When true, include local hash-chain verify status.",
                    },
                    "session": {
                        "type": ["string", "null"],
                        "description": "Optional session id filter.",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["text", "json"],
                        "description": "Output format. Default is human-readable text.",
                    },
                    "debug": {
                        "type": "boolean",
                        "description": "When true, return bounded JSON with debug fields.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "write_file",
            "description": "Write a UTF-8 text file under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
        {
            "name": "delete_file",
            "description": "Delete one file under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "rmdir_tree",
            "description": "Remove a directory tree under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "move_file",
            "description": "Move or rename one file within the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                },
                "required": ["source", "destination"],
                "additionalProperties": False,
            },
        },
        {
            "name": "copy_file",
            "description": "Copy one file within the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                },
                "required": ["source", "destination"],
                "additionalProperties": False,
            },
        },
        {
            "name": "chmod_file",
            "description": "Change file mode bits for one sandbox file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "mode": {"type": "integer"},
                },
                "required": ["path", "mode"],
                "additionalProperties": False,
            },
        },
        {
            "name": "create_symlink",
            "description": "Create a symlink under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["path", "target"],
                "additionalProperties": False,
            },
        },
    ]


def _path_parts(requested: str) -> list[str]:
    """Return sandbox-relative path segments after lexical ``..``/``.`` collapse.

    Internal relative forms such as ``ops/../ops/file.json`` resolve to
    ``ops/file.json``. Paths that still escape the workspace root after
    normalization (``../outside.txt``, ``ops/../../outside.txt``) are denied.
    Absolute paths are denied before any filesystem resolution.
    """

    normalized = requested.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("path escapes quickstart sandbox")
    # Lexical canonicalize first so in-workspace ``..`` is not rejected early.
    resolved = posixpath.normpath(normalized)
    if resolved.startswith("/") or resolved == ".." or resolved.startswith("../"):
        raise ValueError("path escapes quickstart sandbox")
    parts = [segment for segment in resolved.split("/") if segment and segment != "."]
    if any(part == ".." for part in parts):
        raise ValueError("path escapes quickstart sandbox")
    return parts


def _resolved_inside_root(root: Path, parts: list[str]) -> Path:
    root_resolved = _root_resolved(root)
    current = root_resolved
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            resolved = current.resolve()
            if resolved != root_resolved and root_resolved not in resolved.parents:
                raise ValueError("symlink escape denied")
            current = resolved
    final = (root_resolved / Path(*parts)).resolve()
    if final != root_resolved and root_resolved not in final.parents:
        raise ValueError("path escapes quickstart sandbox")
    if final.exists() and final.is_symlink():
        resolved = final.resolve()
        if resolved != root_resolved and root_resolved not in resolved.parents:
            raise ValueError("symlink escape denied")
    return final


def _safe_child(root: Path, requested: str) -> Path:
    return _resolved_inside_root(root, _path_parts(requested))


def _sandbox_relative_display_path(root: Path, target: Path) -> str:
    """Return a sandbox-relative display path using the resolved sandbox root.

    Product setup may point the configured root at a symlink
    (``product-profile/workspace`` → real workspace). Containment already
    resolves through that symlink; response formatting must use the same
    resolved root so ``Path.relative_to`` does not raise a false
    not-in-subpath error after a successful mutation.
    """

    return target.relative_to(_root_resolved(root)).as_posix()


def requested_path_targets_agentveil_control(root: Path, requested: str) -> bool:
    """Return True when ``requested`` resolves to an AgentVeil control artifact."""

    if is_agentveil_control_relative_path(requested):
        return True
    try:
        target = _safe_child(root, requested)
    except ValueError:
        return False
    return is_resolved_path_under_agentveil_control(root, target)


def filter_agentveil_control_paths(root: Path, paths: list[str]) -> list[str]:
    """Drop listing entries under control/metadata roots or aliases to them.

    Hides exact ``.git`` / ``.avp`` path components and resolved targets under
    those roots (including symlink aliases). Does not hide unrelated dotfiles
    such as ``.github/**`` or ``.env.example``.
    """

    return filter_workspace_listing_paths(root, paths)


def filter_workspace_listing_paths(root: Path | None, paths: list[str]) -> list[str]:
    """Filter ``list_workspace`` lines for quickstart and external downstreams."""

    filtered: list[str] = []
    root_resolved = None if root is None else _root_resolved(root)
    for path in paths:
        if not path or is_hidden_listing_relative_path(path):
            continue
        if is_agentveil_control_relative_path(path):
            continue
        if root_resolved is None:
            filtered.append(path)
            continue
        try:
            candidate = root_resolved / Path(*_path_parts(path))
        except ValueError:
            continue
        if candidate.exists() or candidate.is_symlink():
            try:
                if is_resolved_path_under_listing_metadata(root, candidate):
                    continue
                if is_resolved_path_under_agentveil_control(root, candidate):
                    continue
            except OSError:
                continue
        filtered.append(path)
    return filtered


def workspace_listing_paths(root: Path) -> list[str]:
    """Return bounded workspace file paths excluding listing-hidden metadata."""

    root_resolved = _root_resolved(root)
    listed: list[str] = []
    for item in sorted(root_resolved.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(root_resolved).as_posix()
        if is_hidden_listing_relative_path(relative):
            continue
        try:
            resolved = item.resolve()
        except OSError:
            continue
        if is_resolved_path_under_listing_metadata(root, resolved):
            continue
        if is_resolved_path_under_agentveil_control(root, resolved):
            continue
        listed.append(relative)
    return listed


def _safe_symlink_target(root: Path, link_path: Path, target: str) -> None:
    normalized = target.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("symlink target escapes quickstart sandbox")
    target_parts = _path_parts(normalized)
    root_resolved = _root_resolved(root)
    anchor = link_path.parent
    resolved_target = (anchor / Path(*target_parts)).resolve()
    if resolved_target != root_resolved and root_resolved not in resolved_target.parents:
        raise ValueError("symlink target escapes quickstart sandbox")


def _handle_tools_call(root: Path, request_id: Any, params: Mapping[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, Mapping):
        return _error(request_id, -32602, "arguments must be an object")
    if name == "list_workspace":
        files = workspace_listing_paths(root)
        return _response(request_id, {"content": [{"type": "text", "text": "\n".join(files)}]})
    if name == "read_file":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            target = _safe_child(root, path)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if is_resolved_path_under_agentveil_control(root, target):
            return _error(request_id, -32602, AGENTVEIL_CONTROL_PATH_DENIED)
        if not target.is_file():
            return _error(request_id, -32602, "file not found")
        return _response(
            request_id,
            {"content": [{"type": "text", "text": target.read_text(encoding="utf-8")}]},
        )
    if name == "get_file_info":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            target = _safe_child(root, path)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if is_resolved_path_under_agentveil_control(root, target):
            return _error(request_id, -32602, AGENTVEIL_CONTROL_PATH_DENIED)
        if not target.exists():
            return _error(request_id, -32602, "file not found")
        if not target.is_file():
            return _error(request_id, -32602, "path is not a file")
        stat = target.stat()
        info = {
            "path": _sandbox_relative_display_path(root, target),
            "size_bytes": stat.st_size,
            "size_bucket": _size_bucket(stat.st_size),
        }
        return _response(
            request_id,
            {"content": [{"type": "text", "text": json.dumps(info, separators=(",", ":"))}]},
        )
    if name == "instruction_surface_status":
        summary = _summarize_instruction_surface_risk(_scan_instruction_surfaces(root))
        return _response(
            request_id,
            {"content": [{"type": "text", "text": json.dumps(summary, separators=(",", ":"))}]},
        )
    if name == "local_proof":
        return _error(
            request_id,
            -32603,
            "local_proof is handled by the AgentVeil MCP proxy, not the filesystem downstream",
        )
    if name == "write_file":
        path = arguments.get("path")
        content = arguments.get("content")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        if not isinstance(content, str):
            return _error(request_id, -32602, "content must be a string")
        try:
            target = _safe_child(root, path)
            display_path = _sandbox_relative_display_path(root, target)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"wrote {display_path}"}]},
        )
    if name == "delete_file":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            target = _safe_child(root, path)
            display_path = _sandbox_relative_display_path(root, target)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if not target.is_file():
            return _error(request_id, -32602, "file not found")
        target.unlink()
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"deleted {display_path}"}]},
        )
    if name == "rmdir_tree":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            target = _safe_child(root, path)
            display_path = _sandbox_relative_display_path(root, target)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if not target.is_dir():
            return _error(request_id, -32602, "directory not found")
        if target == _root_resolved(root):
            return _error(request_id, -32602, "cannot remove sandbox root")
        shutil.rmtree(target)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"removed {display_path}"}]},
        )
    if name == "move_file":
        source = arguments.get("source")
        destination = arguments.get("destination")
        if not isinstance(source, str) or not source:
            return _error(request_id, -32602, "source must be a non-empty string")
        if not isinstance(destination, str) or not destination:
            return _error(request_id, -32602, "destination must be a non-empty string")
        try:
            src = _safe_child(root, source)
            dst = _safe_child(root, destination)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if not src.is_file():
            return _error(request_id, -32602, "source file not found")
        dst.parent.mkdir(parents=True, exist_ok=True)
        src.replace(dst)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "moved file"}]},
        )
    if name == "copy_file":
        source = arguments.get("source")
        destination = arguments.get("destination")
        if not isinstance(source, str) or not source:
            return _error(request_id, -32602, "source must be a non-empty string")
        if not isinstance(destination, str) or not destination:
            return _error(request_id, -32602, "destination must be a non-empty string")
        try:
            src = _safe_child(root, source)
            dst = _safe_child(root, destination)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if not src.is_file():
            return _error(request_id, -32602, "source file not found")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "copied file"}]},
        )
    if name == "chmod_file":
        path = arguments.get("path")
        mode = arguments.get("mode")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        if not isinstance(mode, int) or isinstance(mode, bool):
            return _error(request_id, -32602, "mode must be an integer")
        try:
            target = _safe_child(root, path)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        if not target.is_file():
            return _error(request_id, -32602, "file not found")
        os.chmod(target, mode)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "changed mode"}]},
        )
    if name == "create_symlink":
        path = arguments.get("path")
        target = arguments.get("target")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        if not isinstance(target, str) or not target:
            return _error(request_id, -32602, "target must be a non-empty string")
        try:
            link_path = _safe_child(root, path)
            _safe_symlink_target(root, link_path, target)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        link_path.parent.mkdir(parents=True, exist_ok=True)
        if link_path.exists() or link_path.is_symlink():
            return _error(request_id, -32602, "path already exists")
        link_path.symlink_to(target)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "created symlink"}]},
        )
    return _error(request_id, -32601, "unknown tool")


def handle_message(root: Path, message: Mapping[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentveil-quickstart-filesystem", "version": "0"},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _response(request_id, {"tools": _tools()})
    if method == "tools/call":
        params = message.get("params", {})
        if not isinstance(params, Mapping):
            return _error(request_id, -32602, "params must be an object")
        return _handle_tools_call(root, request_id, params)
    return _error(request_id, -32601, "method not found")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print("usage: python -m agentveil_mcp_proxy.quickstart_filesystem SANDBOX")
        return 0
    if len(argv) != 1:
        print("usage: python -m agentveil_mcp_proxy.quickstart_filesystem SANDBOX", file=sys.stderr)
        return 2
    root = Path(argv[0]).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            response = _error(None, -32700, "parse error")
        else:
            if not isinstance(message, Mapping):
                response = _error(None, -32600, "request must be an object")
            else:
                response = handle_message(root, message)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
