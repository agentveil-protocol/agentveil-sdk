# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded custody helpers for local MCP proxy control artifacts.

Narrow helper for Approval Center manifest, owner-claim, and hook-runtime
binding writers. Not a generic filesystem framework.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Any


class ControlArtifactError(RuntimeError):
    """Bounded failure for local control-artifact custody.

    Deliberately carries no path, token, payload, or traceback text.
    """

    def __init__(self, code: str = "control_artifact_write_failed"):
        self.code = str(code)
        super().__init__(self.code)


def _uses_posix_filesystem_custody() -> bool:
    return os.name != "nt"


def ensure_control_directory(path: Path) -> None:
    """Create or validate one private control directory.

    Ancestors may be created with default umask. Only ``path`` itself is the
    control directory. It must be a real directory and not a symlink. POSIX
    platforms additionally require mode ``0700`` and current-user ownership;
    Windows relies on the user-profile ACL inherited at directory creation.

    Existing POSIX directories with any mode other than ``0700`` are rejected
    with a bounded error (no silent chmod repair).
    """

    target = Path(path)
    parent = target.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ControlArtifactError("control_directory_unavailable") from exc

    created = False
    try:
        os.mkdir(target, 0o700)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        raise ControlArtifactError("control_directory_unavailable") from exc

    try:
        st = os.lstat(target)
    except OSError as exc:
        raise ControlArtifactError("control_directory_invalid") from exc
    _assert_safe_control_directory_stat(st, require_mode_0700=not created)

    if created and _uses_posix_filesystem_custody():
        try:
            os.chmod(target, 0o700)
            st = os.lstat(target)
        except OSError as exc:
            raise ControlArtifactError("control_directory_invalid") from exc
        _assert_safe_control_directory_stat(st, require_mode_0700=True)


def _assert_safe_control_directory_stat(
    info: os.stat_result,
    *,
    require_mode_0700: bool,
) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise ControlArtifactError("control_directory_invalid")
    if not stat.S_ISDIR(info.st_mode):
        raise ControlArtifactError("control_directory_invalid")
    if _uses_posix_filesystem_custody():
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ControlArtifactError("control_directory_invalid")
        if require_mode_0700 and stat.S_IMODE(info.st_mode) != 0o700:
            raise ControlArtifactError("control_directory_invalid")


def _reject_unsafe_relative_name(name: str) -> None:
    parts = [part for part in name.split("/") if part]
    if not parts or any(part == ".." for part in parts):
        raise ControlArtifactError("control_artifact_write_failed")


def _open_control_subdirectory_at(parent_fd: int, name: str) -> int:
    _reject_unsafe_relative_name(name)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ControlArtifactError("control_directory_invalid") from exc


def ensure_control_subdirectory_at(parent_fd: int, name: str) -> int:
    """Create or validate one private directory relative to ``parent_fd``.

    Returns an open directory file descriptor for ``name``. The caller must
    close it when finished.
    """

    _reject_unsafe_relative_name(name)
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        raise ControlArtifactError("control_directory_unavailable") from exc

    child_fd = _open_control_subdirectory_at(parent_fd, name)
    try:
        st = os.fstat(child_fd)
        _assert_safe_control_directory_stat(st, require_mode_0700=not created)
        if created and _uses_posix_filesystem_custody():
            try:
                if not hasattr(os, "fchmod"):
                    raise ControlArtifactError("control_directory_invalid")
                os.fchmod(child_fd, 0o700)
                st = os.fstat(child_fd)
            except OSError as exc:
                raise ControlArtifactError("control_directory_invalid") from exc
            _assert_safe_control_directory_stat(st, require_mode_0700=True)
    except Exception:
        try:
            os.close(child_fd)
        except OSError:
            pass
        raise
    return child_fd


def _resolve_control_directory_at(
    base_fd: int,
    relative_dir: str,
) -> tuple[int, list[int]]:
    """Open a validated control directory relative to ``base_fd``."""

    if not relative_dir:
        return base_fd, []
    _reject_unsafe_relative_name(relative_dir)
    parts = [part for part in relative_dir.split("/") if part]
    if not parts:
        raise ControlArtifactError("control_artifact_write_failed")

    opened: list[int] = []
    current_fd = base_fd
    for part in parts:
        child_fd = ensure_control_subdirectory_at(current_fd, part)
        if current_fd != base_fd:
            opened.append(current_fd)
        current_fd = child_fd
    return current_fd, opened


def write_atomic_control_file_at(base_fd: int, relative_path: str, data: bytes) -> None:
    """Atomically publish ``data`` relative to an already-open control directory."""

    if not isinstance(data, (bytes, bytearray)):
        raise ControlArtifactError("control_artifact_write_failed")
    payload = bytes(data)
    _reject_unsafe_relative_name(relative_path)
    dir_name, _, file_name = relative_path.rpartition("/")
    dir_fd, extra_fds = _resolve_control_directory_at(base_fd, dir_name)
    if not dir_name:
        file_name = relative_path
    try:
        _reject_unsafe_regular_target_at(dir_fd, file_name, allow_missing=True)

        tmp_name = f".{file_name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd: int | None = None
        published = False
        try:
            try:
                fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
            except OSError as exc:
                raise ControlArtifactError("control_artifact_write_failed") from exc
            if _uses_posix_filesystem_custody():
                try:
                    if not hasattr(os, "fchmod"):
                        raise ControlArtifactError("control_artifact_write_failed")
                    os.fchmod(fd, 0o600)
                except OSError as exc:
                    raise ControlArtifactError("control_artifact_write_failed") from exc

            _write_all(fd, payload)
            try:
                os.fsync(fd)
            except OSError as exc:
                raise ControlArtifactError("control_artifact_write_failed") from exc
            os.close(fd)
            fd = None

            _reject_unsafe_regular_target_at(dir_fd, file_name, allow_missing=True)
            try:
                os.replace(tmp_name, file_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except OSError as exc:
                raise ControlArtifactError("control_artifact_write_failed") from exc
            published = True
            _fsync_directory_at(dir_fd)
            _reject_unsafe_regular_target_at(dir_fd, file_name, allow_missing=False)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if not published:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    finally:
        for extra_fd in extra_fds:
            try:
                os.close(extra_fd)
            except OSError:
                pass
        if dir_fd != base_fd:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _reject_unsafe_regular_target_at(
    dir_fd: int,
    name: str,
    *,
    allow_missing: bool,
) -> None:
    try:
        info = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        if allow_missing:
            return
        raise ControlArtifactError("control_artifact_write_failed")
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if not stat.S_ISREG(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if info.st_nlink > 1:
        raise ControlArtifactError("control_artifact_write_failed")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ControlArtifactError("control_artifact_write_failed")


def _fsync_directory_at(dir_fd: int) -> None:
    if not _uses_posix_filesystem_custody():
        return
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc


def write_atomic_control_file(path: Path, data: bytes) -> None:
    """Atomically publish ``data`` to ``path`` with ``0600`` from the first byte.

    Rejects symlink/non-regular targets. Does not follow target or temp
    symlinks. Fsyncs file content and the containing directory.
    """

    if not isinstance(data, (bytes, bytearray)):
        raise ControlArtifactError("control_artifact_write_failed")
    payload = bytes(data)
    target = Path(path)
    ensure_control_directory(target.parent)
    _reject_unsafe_regular_target(target, allow_missing=True)

    tmp_path = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    published = False
    try:
        try:
            fd = os.open(str(tmp_path), flags, 0o600)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        if _uses_posix_filesystem_custody():
            try:
                if not hasattr(os, "fchmod"):
                    raise ControlArtifactError("control_artifact_write_failed")
                os.fchmod(fd, 0o600)
            except OSError as exc:
                raise ControlArtifactError("control_artifact_write_failed") from exc

        _write_all(fd, payload)
        try:
            os.fsync(fd)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        os.close(fd)
        fd = None

        _reject_unsafe_regular_target(target, allow_missing=True)
        try:
            os.replace(str(tmp_path), str(target))
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        published = True
        _fsync_directory(target.parent)
        _reject_unsafe_regular_target(target, allow_missing=False)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if not published:
            try:
                os.unlink(str(tmp_path))
            except OSError:
                pass


def open_exclusive_control_file(path: Path) -> Any:
    """Open a regular control file for owner-claim publish without following links.

    Creates the file with mode ``0600`` when missing. Rejects symlink,
    non-regular, wrong-owner, and hardlinked targets before any truncate.
    Caller must acquire the process lock, then call
    ``rewrite_locked_control_file`` before exposing secrets.
    """

    target = Path(path)
    ensure_control_directory(target.parent)

    existing: os.stat_result | None
    try:
        existing = os.lstat(target)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc

    if existing is not None:
        _assert_safe_claim_target_stat(existing)
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(target), flags)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
    else:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(target), flags, 0o600)
        except FileExistsError:
            # Concurrent creator won the exclusive create; reopen existing.
            return open_exclusive_control_file(target)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        if _uses_posix_filesystem_custody():
            try:
                if not hasattr(os, "fchmod"):
                    raise ControlArtifactError("control_artifact_write_failed")
                os.fchmod(fd, 0o600)
            except OSError as exc:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise ControlArtifactError("control_artifact_write_failed") from exc

    try:
        info = os.fstat(fd)
        _assert_safe_claim_target_stat(info)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    return os.fdopen(fd, "r+", encoding="utf-8", newline="")


def rewrite_locked_control_file(fh: Any, data: bytes, *, directory: Path) -> None:
    """Rewrite a locked control file with ``0600`` before the first secret byte.

    Requires an exclusive process lock already held by the caller. Sets mode
    ``0600`` and verifies it before truncate/write. Writes the full payload,
    fsyncs the file, then fsyncs ``directory``. Any failure raises
    ``ControlArtifactError`` (no suppressed durability errors).
    """

    if not isinstance(data, (bytes, bytearray)):
        raise ControlArtifactError("control_artifact_write_failed")
    payload = bytes(data)
    try:
        fd = fh.fileno()
    except Exception as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc

    try:
        if _uses_posix_filesystem_custody():
            if not hasattr(os, "fchmod"):
                raise ControlArtifactError("control_artifact_write_failed")
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    if (
        _uses_posix_filesystem_custody()
        and stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ControlArtifactError("control_artifact_write_failed")
    _assert_safe_claim_target_stat(info)

    try:
        fh.seek(0)
        fh.truncate()
        fh.flush()
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc

    _write_all(fd, payload)
    try:
        fh.seek(0, os.SEEK_END)
        fh.flush()
        os.fsync(fd)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    _fsync_directory(Path(directory))


def _assert_safe_claim_target_stat(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if not stat.S_ISREG(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if info.st_nlink > 1:
        raise ControlArtifactError("control_artifact_write_failed")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ControlArtifactError("control_artifact_write_failed")


def _reject_unsafe_regular_target(path: Path, *, allow_missing: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return
        raise ControlArtifactError("control_artifact_write_failed")
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if not stat.S_ISREG(info.st_mode):
        raise ControlArtifactError("control_artifact_write_failed")
    if info.st_nlink > 1:
        raise ControlArtifactError("control_artifact_write_failed")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ControlArtifactError("control_artifact_write_failed")


def _write_all(fd: int, data: bytes) -> None:
    if not data:
        return
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        if written <= 0:
            raise ControlArtifactError("control_artifact_write_failed")
        offset += written


def _fsync_directory(path: Path) -> None:
    if not _uses_posix_filesystem_custody():
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        dir_fd = os.open(str(path), flags)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


__all__ = [
    "ControlArtifactError",
    "ensure_control_directory",
    "ensure_control_subdirectory_at",
    "open_exclusive_control_file",
    "rewrite_locked_control_file",
    "write_atomic_control_file",
    "write_atomic_control_file_at",
]
