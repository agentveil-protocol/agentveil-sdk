"""Tiny stdio MCP server for `agentveil-mcp-proxy --quickstart-filesystem`.

This server is intentionally small and sandbox-rooted. It exists so a fresh
install can exercise MCP initialize, tools/list, and simple filesystem tool
calls without installing an external Node-based MCP server first.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import posixpath
import shutil
import stat as stat_mod
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
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
QUICKSTART_READ_POOL_SIZE = 20
READ_ONLY_TOOL_NAMES = frozenset({
    "read_file",
    "get_file_info",
    "list_workspace",
    "instruction_surface_status",
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


def _resolved_mutation_parts(root: Path, requested: str) -> tuple[list[str], Path]:
    """Validate ``requested`` and return canonical sandbox-relative mutation parts.

    Validated internal symlinks are resolved by ``_safe_child`` first; fd-bound mutations
    walk the resolved path chain rather than the original lexical alias segments.
    """

    target = _safe_child(root, requested)
    parts = target.relative_to(_root_resolved(root)).parts
    if not parts:
        raise ValueError("path escapes quickstart sandbox")
    return list(parts), target


def _mutation_unavailable() -> ValueError:
    return ValueError("filesystem mutation unavailable on this platform")


def _is_symlink_errno(exc: OSError) -> bool:
    # macOS uses ELOOP (62); some platforms may surface EINVAL for O_NOFOLLOW.
    return exc.errno in {getattr(errno, "ELOOP", None), getattr(errno, "EINVAL", None)}


def _deny_symlink_race() -> ValueError:
    return ValueError("symlink race denied")


def _dir_fd_required_ops() -> tuple[Any, ...]:
    return (os.open, os.stat, os.unlink, os.mkdir, os.rename, os.chmod, os.symlink)


def _fd_bound_mutations_available() -> bool:
    if not (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")):
        return False
    # claim-check: allow capability detection requires every listed dir_fd operation.
    return all(op in os.supports_dir_fd for op in _dir_fd_required_ops())


def _select_mutation_backend() -> str:
    if _fd_bound_mutations_available():
        return "fd"
    if sys.platform == "win32":
        return "windows"
    raise _mutation_unavailable()


def _open_root_fd(root: Path) -> int:
    return os.open(_root_resolved(root), os.O_RDONLY | os.O_DIRECTORY)


def _open_dir_nofollow(dir_fd: int, name: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=dir_fd,
        )
    except OSError as exc:
        if _is_symlink_errno(exc):
            raise _deny_symlink_race() from exc
        raise


def _walk_parent_fd(
    root_fd: int,
    parts: list[str],
    *,
    create_missing: bool = False,
) -> tuple[int, list[int]]:
    """Open the parent directory of ``parts`` via O_NOFOLLOW opens from ``root_fd``.

    Returns ``(parent_fd, owned_fds)`` where each fd in ``owned_fds`` must be closed by
    the caller (including ``parent_fd`` when it is not ``root_fd``).
    """

    if not parts:
        raise ValueError("path escapes quickstart sandbox")
    owned: list[int] = []
    current = root_fd
    try:
        for name in parts[:-1]:
            try:
                next_fd = _open_dir_nofollow(current, name)
            except FileNotFoundError:
                if not create_missing:
                    raise
                try:
                    os.mkdir(name, 0o755, dir_fd=current)
                except FileExistsError:
                    next_fd = _open_dir_nofollow(current, name)
                else:
                    next_fd = _open_dir_nofollow(current, name)
            except NotADirectoryError as exc:
                raise ValueError("path is not a directory") from exc
            except OSError as exc:
                if _is_symlink_errno(exc):
                    raise _deny_symlink_race() from exc
                if exc.errno == errno.ENOTDIR:
                    raise ValueError("path is not a directory") from exc
                raise
            owned.append(next_fd)
            current = next_fd
        return current, owned
    except Exception:
        for fd in reversed(owned):
            os.close(fd)
        raise


def _walk_parent_for_mutation(
    root_binding: int,
    parts: list[str],
    *,
    create_missing: bool = False,
) -> tuple[int, list[int]]:
    if _select_mutation_backend() == "windows":
        return _win32_walk_parent(root_binding, parts, create_missing=create_missing)
    return _walk_parent_fd(root_binding, parts, create_missing=create_missing)


def _close_fds(fds: list[int]) -> None:
    for fd in reversed(fds):
        try:
            os.close(fd)
        except OSError:
            pass


def _lstat_at(dir_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _ensure_regular_file_at(dir_fd: int, name: str) -> None:
    try:
        st = _lstat_at(dir_fd, name)
    except FileNotFoundError as exc:
        raise ValueError("file not found") from exc
    except OSError as exc:
        if _is_symlink_errno(exc):
            raise _deny_symlink_race() from exc
        raise
    if stat_mod.S_ISLNK(st.st_mode):
        raise _deny_symlink_race()
    if not stat_mod.S_ISREG(st.st_mode):
        raise ValueError("path is not a file")


def _ensure_directory_at(dir_fd: int, name: str) -> None:
    try:
        st = _lstat_at(dir_fd, name)
    except FileNotFoundError as exc:
        raise ValueError("directory not found") from exc
    except OSError as exc:
        if _is_symlink_errno(exc):
            raise _deny_symlink_race() from exc
        raise
    if stat_mod.S_ISLNK(st.st_mode):
        raise _deny_symlink_race()
    if not stat_mod.S_ISDIR(st.st_mode):
        raise ValueError("directory not found")


def _write_file_fd(root: Path, parts: list[str], content: str) -> None:
    root_fd = _open_root_fd(root)
    owned: list[int] = []
    try:
        parent_fd, owned = _walk_parent_for_mutation(root_fd, parts, create_missing=True)
        name = parts[-1]
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, 0o644, dir_fd=parent_fd)
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            raise
        try:
            data = content.encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
    finally:
        _close_fds(owned)
        os.close(root_fd)


def _unlink_file_fd(root: Path, parts: list[str]) -> None:
    root_fd = _open_root_fd(root)
    owned: list[int] = []
    try:
        parent_fd, owned = _walk_parent_for_mutation(root_fd, parts, create_missing=False)
        name = parts[-1]
        _ensure_regular_file_at(parent_fd, name)
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            raise
    finally:
        _close_fds(owned)
        os.close(root_fd)


def _rmtree_at(parent_fd: int, name: str) -> None:
    _ensure_directory_at(parent_fd, name)
    dir_fd = _open_dir_nofollow(parent_fd, name)
    try:
        for entry in os.listdir(dir_fd):
            try:
                st = _lstat_at(dir_fd, entry)
            except FileNotFoundError:
                continue
            if stat_mod.S_ISDIR(st.st_mode) and not stat_mod.S_ISLNK(st.st_mode):
                _rmtree_at(dir_fd, entry)
            else:
                try:
                    os.unlink(entry, dir_fd=dir_fd)
                except OSError as exc:
                    if _is_symlink_errno(exc):
                        raise _deny_symlink_race() from exc
                    raise
    finally:
        os.close(dir_fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as exc:
        if _is_symlink_errno(exc):
            raise _deny_symlink_race() from exc
        raise


def _rmdir_tree_fd(root: Path, parts: list[str]) -> None:
    if not parts:
        raise ValueError("cannot remove sandbox root")
    root_fd = _open_root_fd(root)
    owned: list[int] = []
    try:
        parent_fd, owned = _walk_parent_for_mutation(root_fd, parts, create_missing=False)
        _rmtree_at(parent_fd, parts[-1])
    finally:
        _close_fds(owned)
        os.close(root_fd)


def _move_file_fd(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    root_fd = _open_root_fd(root)
    src_owned: list[int] = []
    dst_owned: list[int] = []
    try:
        src_parent, src_owned = _walk_parent_for_mutation(
            root_fd, source_parts, create_missing=False,
        )
        _ensure_regular_file_at(src_parent, source_parts[-1])
        dst_parent, dst_owned = _walk_parent_for_mutation(
            root_fd, dest_parts, create_missing=True,
        )
        try:
            st = _lstat_at(dst_parent, dest_parts[-1])
        except FileNotFoundError:
            st = None
        if st is not None and stat_mod.S_ISLNK(st.st_mode):
            raise _deny_symlink_race()
        try:
            os.rename(
                source_parts[-1],
                dest_parts[-1],
                src_dir_fd=src_parent,
                dst_dir_fd=dst_parent,
            )
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            raise
    finally:
        _close_fds(dst_owned)
        _close_fds(src_owned)
        os.close(root_fd)


def _copy_file_fd(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    root_fd = _open_root_fd(root)
    src_owned: list[int] = []
    dst_owned: list[int] = []
    src_fd = -1
    dst_fd = -1
    try:
        src_parent, src_owned = _walk_parent_for_mutation(
            root_fd, source_parts, create_missing=False,
        )
        _ensure_regular_file_at(src_parent, source_parts[-1])
        try:
            src_fd = os.open(
                source_parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=src_parent,
            )
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            raise
        dst_parent, dst_owned = _walk_parent_for_mutation(
            root_fd, dest_parts, create_missing=True,
        )
        try:
            dst_fd = os.open(
                dest_parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o644,
                dir_fd=dst_parent,
            )
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            raise
        while True:
            chunk = os.read(src_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(dst_fd, view)
                view = view[written:]
        try:
            src_st = os.fstat(src_fd)
            os.fchmod(dst_fd, stat_mod.S_IMODE(src_st.st_mode))
        except OSError:
            pass
    finally:
        if dst_fd >= 0:
            os.close(dst_fd)
        if src_fd >= 0:
            os.close(src_fd)
        _close_fds(dst_owned)
        _close_fds(src_owned)
        os.close(root_fd)


def _chmod_file_fd(root: Path, parts: list[str], mode: int) -> None:
    root_fd = _open_root_fd(root)
    owned: list[int] = []
    try:
        parent_fd, owned = _walk_parent_for_mutation(root_fd, parts, create_missing=False)
        _ensure_regular_file_at(parent_fd, parts[-1])
        try:
            os.chmod(parts[-1], mode, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            if exc.errno in {errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)}:
                raise _mutation_unavailable() from exc
            raise
    finally:
        _close_fds(owned)
        os.close(root_fd)


def _create_symlink_fd(root: Path, link_parts: list[str], target: str) -> None:
    root_fd = _open_root_fd(root)
    owned: list[int] = []
    try:
        parent_fd, owned = _walk_parent_for_mutation(root_fd, link_parts, create_missing=True)
        name = link_parts[-1]
        try:
            st = _lstat_at(parent_fd, name)
        except FileNotFoundError:
            st = None
        if st is not None:
            raise ValueError("path already exists")
        try:
            os.symlink(target, name, dir_fd=parent_fd)
        except OSError as exc:
            if _is_symlink_errno(exc):
                raise _deny_symlink_race() from exc
            if exc.errno == errno.EEXIST:
                raise ValueError("path already exists") from exc
            raise
    finally:
        _close_fds(owned)
        os.close(root_fd)


def _write_file_at(root: Path, parts: list[str], content: str) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _write_file_fd(root, parts, content)
    elif backend == "windows":
        _write_file_windows(root, parts, content)
    else:
        raise _mutation_unavailable()


def _unlink_file_at(root: Path, parts: list[str]) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _unlink_file_fd(root, parts)
    elif backend == "windows":
        _unlink_file_windows(root, parts)
    else:
        raise _mutation_unavailable()


def _rmdir_tree_at(root: Path, parts: list[str]) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _rmdir_tree_fd(root, parts)
    elif backend == "windows":
        _rmdir_tree_windows(root, parts)
    else:
        raise _mutation_unavailable()


def _move_file_at(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _move_file_fd(root, source_parts, dest_parts)
    elif backend == "windows":
        _move_file_windows(root, source_parts, dest_parts)
    else:
        raise _mutation_unavailable()


def _copy_file_at(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _copy_file_fd(root, source_parts, dest_parts)
    elif backend == "windows":
        _copy_file_windows(root, source_parts, dest_parts)
    else:
        raise _mutation_unavailable()


def _chmod_file_at(root: Path, parts: list[str], mode: int) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _chmod_file_fd(root, parts, mode)
    elif backend == "windows":
        _chmod_file_windows(root, parts, mode)
    else:
        raise _mutation_unavailable()


def _create_symlink_at(root: Path, link_parts: list[str], target: str) -> None:
    backend = _select_mutation_backend()
    if backend == "fd":
        _create_symlink_fd(root, link_parts, target)
    elif backend == "windows":
        _create_symlink_windows(root, link_parts, target)
    else:
        raise _mutation_unavailable()


def _win32_walk_parent(
    root_handle: int,
    parts: list[str],
    *,
    create_missing: bool = False,
) -> tuple[int, list[int]]:
    raise _mutation_unavailable()


def _write_file_windows(root: Path, parts: list[str], content: str) -> None:
    raise _mutation_unavailable()


def _unlink_file_windows(root: Path, parts: list[str]) -> None:
    raise _mutation_unavailable()


def _rmdir_tree_windows(root: Path, parts: list[str]) -> None:
    raise _mutation_unavailable()


def _move_file_windows(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    raise _mutation_unavailable()


def _copy_file_windows(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
    raise _mutation_unavailable()


def _chmod_file_windows(root: Path, parts: list[str], mode: int) -> None:
    raise _mutation_unavailable()


def _create_symlink_windows(root: Path, link_parts: list[str], target: str) -> None:
    raise _mutation_unavailable()


if sys.platform == "win32":
    import ctypes
    import struct
    from ctypes import wintypes

    _WIN32_INVALID_HANDLE = wintypes.HANDLE(-1).value
    _WIN32_FILE_SHARE_READ = 0x00000001
    _WIN32_FILE_SHARE_WRITE = 0x00000002
    _WIN32_FILE_SHARE_DELETE = 0x00000004
    _WIN32_GENERIC_READ = 0x80000000
    _WIN32_GENERIC_WRITE = 0x40000000
    _WIN32_DELETE = 0x00010000
    _WIN32_FILE_READ_ATTRIBUTES = 0x00000080
    _WIN32_FILE_WRITE_ATTRIBUTES = 0x00000100
    _WIN32_SYNCHRONIZE = 0x00100000
    _WIN32_FILE_ATTRIBUTE_NORMAL = 0x00000080
    _WIN32_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _WIN32_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _WIN32_FILE_ATTRIBUTE_READONLY = 0x00000001
    _WIN32_FSCTL_SET_REPARSE_POINT = 0x000900A4
    _WIN32_IO_REPARSE_TAG_SYMLINK = 0xA000000C
    _WIN32_SYMLINK_FLAG_RELATIVE = 0x00000001
    _WIN32_FILE_DIRECTORY_INFORMATION = 1
    _WIN32_FILE_DIRECTORY_FILE = 0x00000001
    _WIN32_FILE_NON_DIRECTORY_FILE = 0x00000040
    _WIN32_FILE_OPEN_REPARSE_POINT = 0x00200000
    _WIN32_FILE_DELETE_ON_CLOSE = 0x00001000
    _WIN32_FILE_OPEN = 1
    _WIN32_FILE_CREATE = 2
    _WIN32_FILE_OPEN_IF = 3
    _WIN32_FILE_OVERWRITE_IF = 5
    _WIN32_FILE_CREATE_NEW = 4
    _WIN32_OBJ_CASE_INSENSITIVE = 0x00000040
    _WIN32_STATUS_SUCCESS = 0
    _WIN32_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    _WIN32_STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    _WIN32_STATUS_NOT_A_DIRECTORY = 0xC0000103
    _WIN32_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    _WIN32_FILE_INFORMATION_CLASS_BASIC = 4
    _WIN32_FILE_INFORMATION_CLASS_RENAME = 10
    _WIN32_FILE_INFORMATION_CLASS_DISPOSITION = 13
    _WIN32_FILE_NAME_OPENED = 34
    _WIN32_FILE_OPENED = 1
    _WIN32_FILE_CREATED = 2
    _WIN32_FILE_OVERWRITTEN = 3
    _WIN32_FILE_SUPERSEDED = 0
    _WIN32_FILE_EXISTS = 4
    _WIN32_FILE_DOES_NOT_EXIST = 5
    _WIN32_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _WIN32_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _WIN32_OPEN_EXISTING = 3
    _WIN32_STATUS_NO_MORE_FILES = 0x80000006

    _NTSTATUS = ctypes.c_long

    class _WIN32_UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ushort),
            ("MaximumLength", ctypes.c_ushort),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _WIN32_OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_WIN32_UNICODE_STRING)),
            ("Attributes", ctypes.c_ulong),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _WIN32_IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_long),
            ("Information", ctypes.c_void_p),
        ]

    class _WIN32_FILE_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("CreationTime", wintypes.LARGE_INTEGER),
            ("LastAccessTime", wintypes.LARGE_INTEGER),
            ("LastWriteTime", wintypes.LARGE_INTEGER),
            ("ChangeTime", wintypes.LARGE_INTEGER),
            ("FileAttributes", wintypes.DWORD),
        ]

    class _WIN32_FILE_DISPOSITION_INFORMATION(ctypes.Structure):
        _fields_ = [("DeleteFile", ctypes.c_ubyte)]

    class _WIN32_FILE_RENAME_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_ubyte),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.ULONG),
            ("FileName", wintypes.WCHAR * 1),
        ]

    _ntdll = ctypes.WinDLL("ntdll")
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_WIN32_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_WIN32_IO_STATUS_BLOCK),
        ctypes.POINTER(wintypes.LARGE_INTEGER),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    _ntdll.NtCreateFile.restype = _NTSTATUS

    _ntdll.NtQueryInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WIN32_IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _ntdll.NtQueryInformationFile.restype = _NTSTATUS

    _ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WIN32_IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _ntdll.NtSetInformationFile.restype = _NTSTATUS

    _ntdll.NtQueryDirectoryFile.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(_WIN32_IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.BOOLEAN,
        ctypes.POINTER(_WIN32_UNICODE_STRING),
        wintypes.BOOLEAN,
    ]
    _ntdll.NtQueryDirectoryFile.restype = _NTSTATUS

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL

    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL

    _kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    _kernel32.SetEndOfFile.restype = wintypes.BOOL

    _kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL

    def _win32_handle_value(handle: Any) -> int:
        if handle is None:
            return 0
        if isinstance(handle, int):
            return handle
        value = getattr(handle, "value", handle)
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        return int(value)

    def _win32_handle(value: int) -> wintypes.HANDLE:
        return wintypes.HANDLE(value)

    def _win32_close(handle: int) -> None:
        _kernel32.CloseHandle(_win32_handle(handle))

    def _win32_ntstatus(status: int) -> int:
        return int(status) & 0xFFFFFFFF

    def _win32_status_eq(status: int, expected: int) -> bool:
        return _win32_ntstatus(status) == _win32_ntstatus(expected)

    def _win32_create_failed(handle: Any) -> bool:
        value = _win32_handle_value(handle)
        return value == _WIN32_INVALID_HANDLE or value == -1

    def _win32_status_to_oserror(status: int) -> OSError:
        code = _win32_ntstatus(status)
        if code == _WIN32_STATUS_OBJECT_NAME_NOT_FOUND:
            return FileNotFoundError("file not found")
        if code == _WIN32_STATUS_OBJECT_PATH_NOT_FOUND:
            return FileNotFoundError("path not found")
        if code == _WIN32_STATUS_NOT_A_DIRECTORY:
            return NotADirectoryError("path is not a directory")
        if code == _WIN32_STATUS_OBJECT_NAME_COLLISION:
            return FileExistsError("path already exists")
        return OSError(f"NTSTATUS 0x{code:08X}")

    def _win32_unicode_string(name: str) -> _WIN32_UNICODE_STRING:
        us = _WIN32_UNICODE_STRING()
        us.Buffer = name
        byte_len = len(name) * 2
        us.Length = byte_len
        us.MaximumLength = byte_len + 2
        return us

    def _win32_object_attributes(
        name: str,
        *,
        root_directory: int = 0,
    ) -> tuple[_WIN32_OBJECT_ATTRIBUTES, _WIN32_UNICODE_STRING]:
        us = _win32_unicode_string(name)
        oa = _WIN32_OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(_WIN32_OBJECT_ATTRIBUTES)
        oa.RootDirectory = _win32_handle(root_directory) if root_directory else wintypes.HANDLE(0)
        oa.ObjectName = ctypes.pointer(us)
        oa.Attributes = _WIN32_OBJ_CASE_INSENSITIVE
        return oa, us

    def _win32_nt_create_file(
        name: str,
        *,
        root_directory: int = 0,
        access: int,
        disposition: int,
        options: int,
        attributes: int = _WIN32_FILE_ATTRIBUTE_NORMAL,
    ) -> tuple[int, int]:
        iosb = _WIN32_IO_STATUS_BLOCK()
        oa, _us = _win32_object_attributes(name, root_directory=root_directory)
        handle = wintypes.HANDLE()
        options |= _WIN32_FILE_SYNCHRONOUS_IO_NONALERT
        status = _ntdll.NtCreateFile(
            ctypes.byref(handle),
            access,
            ctypes.byref(oa),
            ctypes.byref(iosb),
            None,
            attributes,
            _WIN32_FILE_SHARE_READ | _WIN32_FILE_SHARE_WRITE | _WIN32_FILE_SHARE_DELETE,
            disposition,
            options,
            None,
            0,
        )
        if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
            raise _win32_status_to_oserror(status)
        return _win32_handle_value(handle), int(iosb.Information or 0)

    def _win32_query_basic(handle: int) -> _WIN32_FILE_BASIC_INFORMATION:
        iosb = _WIN32_IO_STATUS_BLOCK()
        info = _WIN32_FILE_BASIC_INFORMATION()
        status = _ntdll.NtQueryInformationFile(
            _win32_handle(handle),
            ctypes.byref(iosb),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _WIN32_FILE_INFORMATION_CLASS_BASIC,
        )
        if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
            raise _win32_status_to_oserror(status)
        return info

    def _win32_handle_is_reparse(handle: int) -> bool:
        return bool(_win32_query_basic(handle).FileAttributes & _WIN32_FILE_ATTRIBUTE_REPARSE_POINT)

    def _win32_close_handles(handles: list[int]) -> None:
        for handle in reversed(handles):
            try:
                _win32_close(handle)
            except OSError:
                pass

    def _win32_open_root(root: Path) -> int:
        handle = _kernel32.CreateFileW(
            str(_root_resolved(root)),
            _WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE | _WIN32_FILE_READ_ATTRIBUTES,
            _WIN32_FILE_SHARE_READ | _WIN32_FILE_SHARE_WRITE | _WIN32_FILE_SHARE_DELETE,
            None,
            _WIN32_OPEN_EXISTING,
            _WIN32_FILE_FLAG_BACKUP_SEMANTICS | _WIN32_FILE_OPEN_REPARSE_POINT,
            wintypes.HANDLE(0),
        )
        if _win32_create_failed(handle):
            raise ctypes.WinError(ctypes.get_last_error())
        root_handle = _win32_handle_value(handle)
        if _win32_handle_is_reparse(root_handle):
            _win32_close(root_handle)
            raise _deny_symlink_race()
        return root_handle

    def _win32_open_dir_nofollow(parent_handle: int, name: str) -> int:
        handle, _info = _win32_nt_create_file(
            name,
            root_directory=parent_handle,
            access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE | _WIN32_FILE_READ_ATTRIBUTES,
            disposition=_WIN32_FILE_OPEN,
            options=_WIN32_FILE_DIRECTORY_FILE | _WIN32_FILE_OPEN_REPARSE_POINT,
        )
        if _win32_handle_is_reparse(handle):
            _win32_close(handle)
            raise _deny_symlink_race()
        return handle

    def _win32_create_dir(parent_handle: int, name: str) -> int:
        handle, _info = _win32_nt_create_file(
            name,
            root_directory=parent_handle,
            access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE | _WIN32_FILE_READ_ATTRIBUTES,
            disposition=_WIN32_FILE_CREATE,
            options=_WIN32_FILE_DIRECTORY_FILE | _WIN32_FILE_OPEN_REPARSE_POINT,
            attributes=_WIN32_FILE_ATTRIBUTE_DIRECTORY | _WIN32_FILE_ATTRIBUTE_NORMAL,
        )
        if _win32_handle_is_reparse(handle):
            _win32_close(handle)
            raise _deny_symlink_race()
        return handle

    def _win32_walk_parent(
        root_handle: int,
        parts: list[str],
        *,
        create_missing: bool = False,
    ) -> tuple[int, list[int]]:
        if not parts:
            raise ValueError("path escapes quickstart sandbox")
        owned: list[int] = []
        current = root_handle
        try:
            for name in parts[:-1]:
                try:
                    next_handle = _win32_open_dir_nofollow(current, name)
                except FileNotFoundError:
                    if not create_missing:
                        raise
                    try:
                        next_handle = _win32_create_dir(current, name)
                    except FileExistsError:
                        next_handle = _win32_open_dir_nofollow(current, name)
                except NotADirectoryError as exc:
                    raise ValueError("path is not a directory") from exc
                owned.append(next_handle)
                current = next_handle
            return current, owned
        except Exception:
            _win32_close_handles(owned)
            raise

    def _win32_write_handle(handle: int, data: bytes) -> None:
        written = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(data)
        ok = _kernel32.WriteFile(
            _win32_handle(handle),
            buffer,
            len(data),
            ctypes.byref(written),
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        if written.value != len(data):
            raise OSError("short write")
        if not _kernel32.SetEndOfFile(_win32_handle(handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def _win32_write_file_bytes(handle: int, data: bytes) -> None:
        written = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(data)
        ok = _kernel32.WriteFile(
            _win32_handle(handle),
            buffer,
            len(data),
            ctypes.byref(written),
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        if written.value != len(data):
            raise OSError("short write")

    class _Win32FileDirectoryInformation(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", wintypes.ULONG),
            ("FileIndex", wintypes.ULONG),
            ("CreationTime", wintypes.LARGE_INTEGER),
            ("LastAccessTime", wintypes.LARGE_INTEGER),
            ("LastWriteTime", wintypes.LARGE_INTEGER),
            ("ChangeTime", wintypes.LARGE_INTEGER),
            ("EndOfFile", wintypes.LARGE_INTEGER),
            ("AllocationSize", wintypes.LARGE_INTEGER),
            ("FileAttributes", wintypes.ULONG),
            ("FileNameLength", wintypes.ULONG),
            ("EaSize", wintypes.ULONG),
            ("ShortNameLength", ctypes.c_ubyte),
            ("ShortName", wintypes.WCHAR * 12),
            ("FileName", wintypes.WCHAR * 1),
        ]

    def _win32_list_directory(dir_handle: int) -> list[str]:
        names: list[str] = []
        buf = (ctypes.c_byte * 65536)()
        iosb = _WIN32_IO_STATUS_BLOCK()
        restart = True
        while True:
            status = _ntdll.NtQueryDirectoryFile(
                _win32_handle(dir_handle),
                wintypes.HANDLE(0),
                None,
                None,
                ctypes.byref(iosb),
                buf,
                len(buf),
                _WIN32_FILE_DIRECTORY_INFORMATION,
                False,
                None,
                restart,
            )
            restart = False
            if _win32_status_eq(status, _WIN32_STATUS_NO_MORE_FILES):
                break
            if _win32_status_eq(status, _WIN32_STATUS_OBJECT_NAME_NOT_FOUND):
                break
            if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
                raise _win32_status_to_oserror(status)
            offset = 0
            while True:
                entry = ctypes.cast(
                    ctypes.byref(buf, offset),
                    ctypes.POINTER(_Win32FileDirectoryInformation),
                ).contents
                name_len = entry.FileNameLength // 2
                name = ctypes.wstring_at(ctypes.addressof(entry.FileName), name_len)
                if name not in {".", ".."}:
                    names.append(name)
                if entry.NextEntryOffset == 0:
                    break
                offset += entry.NextEntryOffset
        return names

    def _win32_apply_mode_on_handle(handle: int, mode: int) -> None:
        info = _win32_query_basic(handle)
        attrs = info.FileAttributes
        if mode & stat_mod.S_IWRITE:
            attrs &= ~_WIN32_FILE_ATTRIBUTE_READONLY
        else:
            attrs |= _WIN32_FILE_ATTRIBUTE_READONLY
        info.FileAttributes = attrs
        iosb = _WIN32_IO_STATUS_BLOCK()
        status = _ntdll.NtSetInformationFile(
            _win32_handle(handle),
            ctypes.byref(iosb),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _WIN32_FILE_INFORMATION_CLASS_BASIC,
        )
        if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
            raise _win32_status_to_oserror(status)

    def _win32_set_symlink_reparse(handle: int, target: str) -> None:
        sub_utf16 = target.encode("utf-16le")
        print_utf16 = target.encode("utf-16le")
        sub_len = len(sub_utf16)
        print_len = len(print_utf16)
        path_buffer = sub_utf16 + b"\x00\x00" + print_utf16 + b"\x00\x00"
        sym_payload = struct.pack(
            "<HHHHI",
            0,
            sub_len,
            sub_len + 2,
            print_len,
            _WIN32_SYMLINK_FLAG_RELATIVE,
        ) + path_buffer
        reparse_buffer = struct.pack(
            "<IHH",
            _WIN32_IO_REPARSE_TAG_SYMLINK,
            len(sym_payload),
            0,
        ) + sym_payload
        input_buffer = ctypes.create_string_buffer(reparse_buffer)
        returned = wintypes.DWORD(0)
        ok = _kernel32.DeviceIoControl(
            _win32_handle(handle),
            _WIN32_FSCTL_SET_REPARSE_POINT,
            input_buffer,
            len(reparse_buffer),
            None,
            0,
            ctypes.byref(returned),
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def _win32_create_symlink_at(parent_handle: int, name: str, target: str) -> None:
        try:
            existing = _win32_open_file_nofollow(
                parent_handle,
                name,
                access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE,
                disposition=_WIN32_FILE_OPEN,
            )
        except FileNotFoundError:
            pass
        else:
            _win32_close(existing)
            raise ValueError("path already exists")
        handle, _info = _win32_nt_create_file(
            name,
            root_directory=parent_handle,
            access=_WIN32_GENERIC_WRITE | _WIN32_SYNCHRONIZE,
            disposition=_WIN32_FILE_CREATE,
            options=_WIN32_FILE_NON_DIRECTORY_FILE | _WIN32_FILE_OPEN_REPARSE_POINT,
        )
        try:
            _win32_set_symlink_reparse(handle, target)
        except Exception:
            try:
                _win32_delete_handle(handle)
            finally:
                _win32_close(handle)
            raise
        _win32_close(handle)

    def _win32_rmtree_at(parent_handle: int, name: str) -> None:
        dir_handle = _win32_open_dir_nofollow(parent_handle, name)
        try:
            for entry in _win32_list_directory(dir_handle):
                probe, _info = _win32_nt_create_file(
                    entry,
                    root_directory=dir_handle,
                    access=_WIN32_GENERIC_READ | _WIN32_FILE_READ_ATTRIBUTES | _WIN32_SYNCHRONIZE,
                    disposition=_WIN32_FILE_OPEN,
                    options=_WIN32_FILE_OPEN_REPARSE_POINT,
                )
                try:
                    if _win32_handle_is_reparse(probe):
                        raise _deny_symlink_race()
                    basic = _win32_query_basic(probe)
                finally:
                    _win32_close(probe)
                if basic.FileAttributes & _WIN32_FILE_ATTRIBUTE_DIRECTORY:
                    _win32_rmtree_at(dir_handle, entry)
                else:
                    file_handle = _win32_open_file_nofollow(
                        dir_handle,
                        entry,
                        access=_WIN32_DELETE | _WIN32_SYNCHRONIZE,
                        disposition=_WIN32_FILE_OPEN,
                    )
                    try:
                        _win32_delete_handle(file_handle)
                    finally:
                        _win32_close(file_handle)
        finally:
            _win32_close(dir_handle)
        dir_handle = _win32_open_dir_nofollow(parent_handle, name)
        try:
            _win32_delete_handle(dir_handle)
        finally:
            _win32_close(dir_handle)

    def _win32_open_file_nofollow(
        parent_handle: int,
        name: str,
        *,
        access: int,
        disposition: int,
    ) -> int:
        handle, _info = _win32_nt_create_file(
            name,
            root_directory=parent_handle,
            access=access,
            disposition=disposition,
            options=_WIN32_FILE_NON_DIRECTORY_FILE | _WIN32_FILE_OPEN_REPARSE_POINT,
        )
        if _win32_handle_is_reparse(handle):
            _win32_close(handle)
            raise _deny_symlink_race()
        return handle

    def _win32_delete_handle(handle: int) -> None:
        iosb = _WIN32_IO_STATUS_BLOCK()
        info = _WIN32_FILE_DISPOSITION_INFORMATION()
        info.DeleteFile = 1
        status = _ntdll.NtSetInformationFile(
            _win32_handle(handle),
            ctypes.byref(iosb),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _WIN32_FILE_INFORMATION_CLASS_DISPOSITION,
        )
        if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
            raise _win32_status_to_oserror(status)

    def _win32_rename_at(
        src_parent: int,
        src_name: str,
        dst_parent: int,
        dst_name: str,
        *,
        replace_if_exists: bool = True,
    ) -> None:
        dst_bytes = (dst_name + "\x00").encode("utf-16le")
        buf_size = ctypes.sizeof(_WIN32_FILE_RENAME_INFORMATION) + len(dst_bytes)
        buf = (ctypes.c_char * buf_size)()
        info = ctypes.cast(buf, ctypes.POINTER(_WIN32_FILE_RENAME_INFORMATION)).contents
        info.ReplaceIfExists = 1 if replace_if_exists else 0
        info.RootDirectory = _win32_handle(dst_parent)
        info.FileNameLength = len(dst_name) * 2
        ctypes.memmove(
            ctypes.addressof(info.FileName),
            dst_bytes,
            len(dst_bytes),
        )
        src_handle = _win32_open_file_nofollow(
            src_parent,
            src_name,
            access=_WIN32_DELETE | _WIN32_SYNCHRONIZE | _WIN32_GENERIC_READ,
            disposition=_WIN32_FILE_OPEN,
        )
        try:
            iosb = _WIN32_IO_STATUS_BLOCK()
            status = _ntdll.NtSetInformationFile(
                _win32_handle(src_handle),
                ctypes.byref(iosb),
                buf,
                buf_size,
                _WIN32_FILE_INFORMATION_CLASS_RENAME,
            )
            if not _win32_status_eq(status, _WIN32_STATUS_SUCCESS):
                raise _win32_status_to_oserror(status)
        finally:
            _win32_close(src_handle)

    def _write_file_windows(root: Path, parts: list[str], content: str) -> None:
        root_handle = _win32_open_root(root)
        owned: list[int] = []
        try:
            parent_handle, owned = _walk_parent_for_mutation(root_handle, parts, create_missing=True)
            handle = _win32_open_file_nofollow(
                parent_handle,
                parts[-1],
                access=_WIN32_GENERIC_WRITE | _WIN32_SYNCHRONIZE,
                disposition=_WIN32_FILE_OVERWRITE_IF,
            )
            try:
                _win32_write_handle(handle, content.encode("utf-8"))
            finally:
                _win32_close(handle)
        finally:
            _win32_close_handles(owned)
            _win32_close(root_handle)

    def _unlink_file_windows(root: Path, parts: list[str]) -> None:
        root_handle = _win32_open_root(root)
        owned: list[int] = []
        try:
            parent_handle, owned = _walk_parent_for_mutation(root_handle, parts, create_missing=False)
            handle = _win32_open_file_nofollow(
                parent_handle,
                parts[-1],
                access=_WIN32_DELETE | _WIN32_SYNCHRONIZE | _WIN32_GENERIC_READ,
                disposition=_WIN32_FILE_OPEN,
            )
            try:
                _win32_delete_handle(handle)
            finally:
                _win32_close(handle)
        finally:
            _win32_close_handles(owned)
            _win32_close(root_handle)

    def _rmdir_tree_windows(root: Path, parts: list[str]) -> None:
        if not parts:
            raise ValueError("cannot remove sandbox root")
        root_handle = _win32_open_root(root)
        owned: list[int] = []
        try:
            parent_handle, owned = _walk_parent_for_mutation(root_handle, parts, create_missing=False)
            _win32_rmtree_at(parent_handle, parts[-1])
        finally:
            _win32_close_handles(owned)
            _win32_close(root_handle)

    def _move_file_windows(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
        root_handle = _win32_open_root(root)
        src_owned: list[int] = []
        dst_owned: list[int] = []
        try:
            src_parent, src_owned = _walk_parent_for_mutation(
                root_handle, source_parts, create_missing=False,
            )
            src_handle = _win32_open_file_nofollow(
                src_parent,
                source_parts[-1],
                access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE,
                disposition=_WIN32_FILE_OPEN,
            )
            _win32_close(src_handle)
            dst_parent, dst_owned = _walk_parent_for_mutation(
                root_handle, dest_parts, create_missing=True,
            )
            try:
                dst_handle = _win32_open_file_nofollow(
                    dst_parent,
                    dest_parts[-1],
                    access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE,
                    disposition=_WIN32_FILE_OPEN,
                )
            except FileNotFoundError:
                pass
            else:
                try:
                    if _win32_handle_is_reparse(dst_handle):
                        raise _deny_symlink_race()
                finally:
                    _win32_close(dst_handle)
            _win32_rename_at(
                src_parent,
                source_parts[-1],
                dst_parent,
                dest_parts[-1],
            )
        finally:
            _win32_close_handles(dst_owned)
            _win32_close_handles(src_owned)
            _win32_close(root_handle)

    def _copy_file_windows(root: Path, source_parts: list[str], dest_parts: list[str]) -> None:
        root_handle = _win32_open_root(root)
        src_owned: list[int] = []
        dst_owned: list[int] = []
        src_handle = 0
        dst_handle = 0
        try:
            src_parent, src_owned = _walk_parent_for_mutation(
                root_handle, source_parts, create_missing=False,
            )
            src_handle = _win32_open_file_nofollow(
                src_parent,
                source_parts[-1],
                access=_WIN32_GENERIC_READ | _WIN32_SYNCHRONIZE,
                disposition=_WIN32_FILE_OPEN,
            )
            dst_parent, dst_owned = _walk_parent_for_mutation(
                root_handle, dest_parts, create_missing=True,
            )
            dst_handle = _win32_open_file_nofollow(
                dst_parent,
                dest_parts[-1],
                access=_WIN32_GENERIC_WRITE | _WIN32_SYNCHRONIZE,
                disposition=_WIN32_FILE_OVERWRITE_IF,
            )
            offset = 0
            while True:
                chunk = ctypes.create_string_buffer(1024 * 1024)
                read = wintypes.DWORD(0)
                ok = _kernel32.ReadFile(
                    _win32_handle(src_handle),
                    chunk,
                    len(chunk),
                    ctypes.byref(read),
                    None,
                )
                if not ok:
                    raise ctypes.WinError(ctypes.get_last_error())
                if read.value == 0:
                    break
                _win32_write_file_bytes(dst_handle, chunk.raw[: read.value])
                offset += read.value
            if not _kernel32.SetEndOfFile(_win32_handle(dst_handle)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if dst_handle:
                _win32_close(dst_handle)
            if src_handle:
                _win32_close(src_handle)
            _win32_close_handles(dst_owned)
            _win32_close_handles(src_owned)
            _win32_close(root_handle)

    def _chmod_file_windows(root: Path, parts: list[str], mode: int) -> None:
        root_handle = _win32_open_root(root)
        owned: list[int] = []
        try:
            parent_handle, owned = _walk_parent_for_mutation(root_handle, parts, create_missing=False)
            handle = _win32_open_file_nofollow(
                parent_handle,
                parts[-1],
                access=_WIN32_FILE_WRITE_ATTRIBUTES | _WIN32_SYNCHRONIZE | _WIN32_GENERIC_READ,
                disposition=_WIN32_FILE_OPEN,
            )
            try:
                _win32_apply_mode_on_handle(handle, mode)
            finally:
                _win32_close(handle)
        finally:
            _win32_close_handles(owned)
            _win32_close(root_handle)

    def _create_symlink_windows(root: Path, link_parts: list[str], target: str) -> None:
        root_handle = _win32_open_root(root)
        owned: list[int] = []
        try:
            parent_handle, owned = _walk_parent_for_mutation(
                root_handle, link_parts, create_missing=True,
            )
            _win32_create_symlink_at(parent_handle, link_parts[-1], target)
        finally:
            _win32_close_handles(owned)
            _win32_close(root_handle)


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
            parts, target = _resolved_mutation_parts(root, path)
            display_path = _sandbox_relative_display_path(root, target)
            _write_file_at(root, parts, content)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"wrote {display_path}"}]},
        )
    if name == "delete_file":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            parts, target = _resolved_mutation_parts(root, path)
            display_path = _sandbox_relative_display_path(root, target)
            _unlink_file_at(root, parts)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"deleted {display_path}"}]},
        )
    if name == "rmdir_tree":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        try:
            parts, target = _resolved_mutation_parts(root, path)
            display_path = _sandbox_relative_display_path(root, target)
            if target == _root_resolved(root) or not parts:
                return _error(request_id, -32602, "cannot remove sandbox root")
            _rmdir_tree_at(root, parts)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
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
            source_parts, _source = _resolved_mutation_parts(root, source)
            dest_parts, _dest = _resolved_mutation_parts(root, destination)
            _move_file_at(root, source_parts, dest_parts)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
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
            source_parts, _source = _resolved_mutation_parts(root, source)
            dest_parts, _dest = _resolved_mutation_parts(root, destination)
            _copy_file_at(root, source_parts, dest_parts)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
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
            parts, _target = _resolved_mutation_parts(root, path)
            _chmod_file_at(root, parts, mode)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
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
            parts, link_path = _resolved_mutation_parts(root, path)
            _safe_symlink_target(root, link_path, target)
            _create_symlink_at(root, parts, target)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        except OSError as exc:
            if _is_symlink_errno(exc):
                return _error(request_id, -32602, str(_deny_symlink_race()))
            return _error(request_id, -32602, "filesystem mutation failed")
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


def _is_read_only_tools_call(message: Mapping[str, Any]) -> bool:
    if message.get("method") != "tools/call":
        return False
    params = message.get("params")
    if not isinstance(params, Mapping):
        return False
    name = params.get("name")
    return isinstance(name, str) and name in READ_ONLY_TOOL_NAMES


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
    stdout_lock = threading.Lock()
    mutation_lock = threading.Lock()
    read_slots = threading.Semaphore(QUICKSTART_READ_POOL_SIZE)
    read_pool = ThreadPoolExecutor(
        max_workers=QUICKSTART_READ_POOL_SIZE,
        thread_name_prefix="quickstart-read",
    )

    def _emit(response: dict[str, Any] | None) -> None:
        if response is None:
            return
        with stdout_lock:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    def _dispatch(message: Mapping[str, Any]) -> None:
        if _is_read_only_tools_call(message):
            if not read_slots.acquire(blocking=False):
                request_id = message.get("id")
                _emit(_error(request_id, -32000, "read concurrency limit reached"))
                return

            def _read_task() -> None:
                try:
                    _emit(handle_message(root, message))
                finally:
                    read_slots.release()

            read_pool.submit(_read_task)
            return
        with mutation_lock:
            _emit(handle_message(root, message))

    try:
        for raw_line in sys.stdin:
            if not raw_line.strip():
                continue
            try:
                message = json.loads(raw_line)
            except json.JSONDecodeError:
                _emit(_error(None, -32700, "parse error"))
                continue
            if not isinstance(message, Mapping):
                _emit(_error(None, -32600, "request must be an object"))
                continue
            _dispatch(message)
    finally:
        read_pool.shutdown(wait=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
