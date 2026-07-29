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


def ensure_control_directory(path: Path) -> None:
    """Create or validate one control directory with mode ``0700``.

    Ancestors may be created with default umask. Only ``path`` itself is the
    control directory that must be ``0700``, owned by the current user, a real
    directory, and not a symlink.

    Existing directories with any mode other than ``0700`` are rejected
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

    if created:
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
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ControlArtifactError("control_directory_invalid")
    if require_mode_0700 and stat.S_IMODE(info.st_mode) != 0o700:
        raise ControlArtifactError("control_directory_invalid")


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
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    published = False
    try:
        try:
            fd = os.open(str(tmp_path), flags, 0o600)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        try:
            if hasattr(os, "fchmod"):
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
        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(target), flags)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
    else:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(target), flags, 0o600)
        except FileExistsError:
            # Concurrent creator won the exclusive create; reopen existing.
            return open_exclusive_control_file(target)
        except OSError as exc:
            raise ControlArtifactError("control_artifact_write_failed") from exc
        try:
            if hasattr(os, "fchmod"):
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
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            raise ControlArtifactError("control_artifact_write_failed")
        info = os.fstat(fd)
    except OSError as exc:
        raise ControlArtifactError("control_artifact_write_failed") from exc
    if stat.S_IMODE(info.st_mode) != 0o600:
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
    "open_exclusive_control_file",
    "rewrite_locked_control_file",
    "write_atomic_control_file",
]
