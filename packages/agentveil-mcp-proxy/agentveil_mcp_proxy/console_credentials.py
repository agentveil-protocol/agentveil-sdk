# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Owner-only local custody for the Console device token.

Stores exactly one credential at ``<AVP_HOME>/console/device-token.json`` with
``0700`` directory and ``0600`` file custody, strict bounded reads, atomic
writes, and a narrow validated delete. Credential file operations are pinned
to an opened ``console/`` directory descriptor so parent-path swaps do not
redirect reads, writes, deletes, or login locks in the supported POSIX path.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from agentveil_mcp_proxy.control_artifacts import (
    ControlArtifactError,
    ensure_control_directory,
)

CREDENTIAL_SCHEMA_VERSION = 1
CREDENTIAL_SCOPE = "bounded_summary_upload"

_CREDENTIAL_DIRNAME = "console"
_CREDENTIAL_FILENAME = "device-token.json"
_LOGIN_LOCK_FILENAME = ".login.lock"

_MAX_CREDENTIAL_FILE_BYTES = 8192
_MAX_TOKEN_LENGTH = 4096
_ALLOWED_KEYS = ("schema_version", "scope", "token")


class CredentialError(RuntimeError):
    """Bounded custody failure.

    Carries a short stable code without path, token, payload, or traceback
    text.
    """

    def __init__(self, code: str = "credential_custody_failed"):
        self.code = str(code)
        super().__init__(self.code)


@dataclass(frozen=True)
class StoredCredential:
    """The bounded, validated on-disk credential."""

    scope: str
    token: str


def _uses_posix_filesystem_custody() -> bool:
    return os.name != "nt"


def _supports_directory_fd_custody() -> bool:
    """Return whether this platform exposes the pinned-directory primitives."""

    if not _uses_posix_filesystem_custody():
        return False
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        return False
    import inspect

    try:
        signature = inspect.signature(os.open)
    except (TypeError, ValueError):
        return False
    if "dir_fd" not in signature.parameters:
        return False
    try:
        signature = inspect.signature(os.unlink)
    except (TypeError, ValueError):
        return False
    return "dir_fd" in signature.parameters


def credential_home(home: Path | None = None) -> Path:
    """Return the AVP home, respecting ``AVP_HOME`` like the rest of the CLI."""

    if home is not None:
        return Path(home).expanduser()
    return Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()


def credential_path(home: Path | None = None) -> Path:
    """Return the single Console device-token path under the AVP home."""

    return credential_home(home) / _CREDENTIAL_DIRNAME / _CREDENTIAL_FILENAME


def credential_directory(home: Path | None = None) -> Path:
    """Return the Console credential directory under the AVP home."""

    return credential_home(home) / _CREDENTIAL_DIRNAME


def _validate_token(token: object) -> str:
    if isinstance(token, bool) or not isinstance(token, str):
        raise CredentialError("credential_invalid")
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        raise CredentialError("credential_invalid")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in token):
        raise CredentialError("credential_invalid")
    return token


def _validate_scope(scope: object) -> str:
    if scope != CREDENTIAL_SCOPE:
        raise CredentialError("credential_invalid")
    return CREDENTIAL_SCOPE


def _serialize(credential: StoredCredential) -> bytes:
    payload = {
        "schema_version": CREDENTIAL_SCHEMA_VERSION,
        "scope": credential.scope,
        "token": credential.token,
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _assert_safe_directory_stat(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise CredentialError("credential_invalid")
    if not stat.S_ISDIR(info.st_mode):
        raise CredentialError("credential_invalid")
    if _uses_posix_filesystem_custody():
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise CredentialError("credential_invalid")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise CredentialError("credential_invalid")


def _assert_safe_regular_file(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise CredentialError("credential_invalid")
    if not stat.S_ISREG(info.st_mode):
        raise CredentialError("credential_invalid")
    if info.st_nlink > 1:
        raise CredentialError("credential_invalid")
    if _uses_posix_filesystem_custody():
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise CredentialError("credential_invalid")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise CredentialError("credential_invalid")


def _directory_open_flags(*, create: bool = False) -> int:
    if not _supports_directory_fd_custody():
        raise CredentialError("credential_unreadable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_open_flags(*, write: bool = False, create: bool = False) -> int:
    flags = os.O_RDONLY
    if write:
        flags = os.O_WRONLY
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _stat_in_directory(dir_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _open_pinned_credential_directory(
    home: Path | None,
    *,
    create: bool = False,
) -> int:
    """Open and validate ``console/``; return a pinned directory descriptor."""

    if not _supports_directory_fd_custody():
        raise CredentialError("credential_unreadable")

    directory = credential_directory(home)
    if create:
        try:
            ensure_control_directory(directory)
        except ControlArtifactError as exc:
            raise CredentialError("credential_unreadable") from exc

    try:
        dir_fd = os.open(str(directory), _directory_open_flags())
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise CredentialError("credential_unreadable") from exc

    try:
        _assert_safe_directory_stat(os.fstat(dir_fd))
    except Exception:
        try:
            os.close(dir_fd)
        except OSError:
            pass
        raise
    return dir_fd


def _write_all(fd: int, data: bytes) -> None:
    if not data:
        return
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError as exc:
            raise CredentialError("credential_write_failed") from exc
        if written <= 0:
            raise CredentialError("credential_write_failed")
        offset += written


def _fsync_directory_fd(dir_fd: int) -> None:
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise CredentialError("credential_write_failed") from exc


def _atomic_write_to_directory_fd(dir_fd: int, filename: str, data: bytes) -> None:
    """Atomically publish ``data`` to ``filename`` inside ``dir_fd``."""

    tmp_name = f".{filename}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    fd: int | None = None
    published = False
    try:
        try:
            fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            raise CredentialError("credential_write_failed") from exc
        if _uses_posix_filesystem_custody():
            try:
                os.fchmod(fd, 0o600)
            except OSError as exc:
                raise CredentialError("credential_write_failed") from exc

        _write_all(fd, data)
        try:
            os.fsync(fd)
        except OSError as exc:
            raise CredentialError("credential_write_failed") from exc
        os.close(fd)
        fd = None

        try:
            _stat_in_directory(dir_fd, filename)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise CredentialError("credential_write_failed") from exc
        else:
            info = _stat_in_directory(dir_fd, filename)
            _assert_safe_regular_file(info)

        try:
            os.replace(tmp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError as exc:
            raise CredentialError("credential_write_failed") from exc
        published = True
        _fsync_directory_fd(dir_fd)
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


def _load_from_directory_fd(dir_fd: int) -> StoredCredential | None:
    try:
        info = _stat_in_directory(dir_fd, _CREDENTIAL_FILENAME)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CredentialError("credential_unreadable") from exc

    _assert_safe_regular_file(info)
    if info.st_size > _MAX_CREDENTIAL_FILE_BYTES:
        raise CredentialError("credential_invalid")

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(_CREDENTIAL_FILENAME, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise CredentialError("credential_unreadable") from exc
    try:
        _assert_safe_regular_file(os.fstat(fd))
        raw = os.read(fd, _MAX_CREDENTIAL_FILE_BYTES + 1)
    except OSError as exc:
        raise CredentialError("credential_unreadable") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if len(raw) > _MAX_CREDENTIAL_FILE_BYTES:
        raise CredentialError("credential_invalid")

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise CredentialError("credential_invalid") from exc

    if not isinstance(parsed, dict) or set(parsed) != set(_ALLOWED_KEYS):
        raise CredentialError("credential_invalid")
    version = parsed["schema_version"]
    if isinstance(version, bool) or version != CREDENTIAL_SCHEMA_VERSION:
        raise CredentialError("credential_invalid")
    return StoredCredential(
        scope=_validate_scope(parsed["scope"]),
        token=_validate_token(parsed["token"]),
    )


def save_credential(
    token: str,
    *,
    scope: str = CREDENTIAL_SCOPE,
    home: Path | None = None,
) -> None:
    """Atomically persist exactly one validated credential (``0600``)."""

    credential = StoredCredential(
        scope=_validate_scope(scope),
        token=_validate_token(token),
    )
    dir_fd = _open_pinned_credential_directory(home, create=True)
    try:
        _atomic_write_to_directory_fd(
            dir_fd, _CREDENTIAL_FILENAME, _serialize(credential)
        )
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def load_credential(home: Path | None = None) -> StoredCredential | None:
    """Return the stored credential, ``None`` if absent, raise if unsafe/invalid."""

    try:
        dir_fd = _open_pinned_credential_directory(home, create=False)
    except FileNotFoundError:
        return None
    try:
        return _load_from_directory_fd(dir_fd)
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def delete_credential(home: Path | None = None) -> bool:
    """Safely remove only the exact regular owner-controlled credential file."""

    try:
        dir_fd = _open_pinned_credential_directory(home, create=False)
    except FileNotFoundError:
        return False
    try:
        try:
            info = _stat_in_directory(dir_fd, _CREDENTIAL_FILENAME)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise CredentialError("credential_unreadable") from exc

        _assert_safe_regular_file(info)
        try:
            os.unlink(_CREDENTIAL_FILENAME, dir_fd=dir_fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise CredentialError("credential_delete_failed") from exc
        _fsync_directory_fd(dir_fd)
        return True
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


@contextmanager
def console_login_lock(home: Path | None = None):
    """Exclusive process lock for one Console login lifecycle."""

    dir_fd = _open_pinned_credential_directory(home, create=True)
    lock_fd: int | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            lock_fd = os.open(_LOGIN_LOCK_FILENAME, flags, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            raise CredentialError("credential_unreadable") from exc

        if _uses_posix_filesystem_custody():
            try:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise CredentialError("login_in_progress") from exc

        yield
    finally:
        if lock_fd is not None:
            if _uses_posix_filesystem_custody():
                try:
                    import fcntl

                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
        try:
            os.close(dir_fd)
        except OSError:
            pass


__all__ = [
    "CREDENTIAL_SCHEMA_VERSION",
    "CREDENTIAL_SCOPE",
    "CredentialError",
    "StoredCredential",
    "credential_home",
    "credential_path",
    "credential_directory",
    "console_login_lock",
    "delete_credential",
    "load_credential",
    "save_credential",
]
