# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Owner-only local custody for the Console device token.

POSIX stores one credential at ``<AVP_HOME>/console/device-token.json`` with
``0700`` directory and ``0600`` file custody. File operations are pinned to an
opened ``console/`` directory descriptor so parent-path swaps do not redirect
reads, writes, deletes, or login locks. Windows stores the same credential in
the current user's Credential Manager generic-credential store rather than an
AVP plaintext file.
"""

from __future__ import annotations

import hashlib
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

_WINDOWS_CREDENTIAL_TYPE_GENERIC = 1
_WINDOWS_CREDENTIAL_PERSIST_LOCAL_MACHINE = 2
_WINDOWS_CREDENTIAL_BLOB_BYTES = 5 * 512
_WINDOWS_MAX_TOKEN_BYTES = _MAX_TOKEN_LENGTH * 4
_WINDOWS_MAX_CHUNKS = (
    _WINDOWS_MAX_TOKEN_BYTES + _WINDOWS_CREDENTIAL_BLOB_BYTES - 1
) // _WINDOWS_CREDENTIAL_BLOB_BYTES
_WINDOWS_METADATA_KEYS = (
    "schema_version",
    "scope",
    "generation",
    "chunk_count",
    "token_byte_length",
)
_WINDOWS_TARGET_PREFIX = "AgentVeil.Console.DeviceToken.v1"
_WINDOWS_WAIT_OBJECT_0 = 0
_WINDOWS_WAIT_ABANDONED = 0x80
_WINDOWS_WAIT_TIMEOUT = 0x102
_WINDOWS_LOCK_WAIT_MILLISECONDS = 5000
_WINDOWS_ERROR_NOT_FOUND = 1168


class CredentialError(RuntimeError):
    """Bounded custody failure.

    Carries a short stable code without path, token, payload, or traceback
    text.
    """

    def __init__(self, code: str = "credential_custody_failed"):
        self.code = str(code)
        super().__init__(self.code)


class _WindowsCredentialBackendError(RuntimeError):
    """Private native Credential Manager failure without platform details."""


class _WindowsCredentialLockTimeout(_WindowsCredentialBackendError):
    """Private named-mutex contention signal."""


@dataclass(frozen=True)
class StoredCredential:
    """The bounded, validated on-disk credential."""

    scope: str
    token: str


def _uses_posix_filesystem_custody() -> bool:
    return not _uses_windows_credential_manager()


def _uses_windows_credential_manager() -> bool:
    return os.name == "nt"


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


class _WindowsCredentialBackend:
    """Minimal current-user Generic Credential Manager adapter."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (AttributeError, OSError) as exc:
            raise _WindowsCredentialBackendError() from exc

        credential_pointer = ctypes.POINTER(Credential)
        advapi32.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(credential_pointer),
        ]
        advapi32.CredReadW.restype = wintypes.BOOL
        advapi32.CredWriteW.argtypes = [credential_pointer, wintypes.DWORD]
        advapi32.CredWriteW.restype = wintypes.BOOL
        advapi32.CredDeleteW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        advapi32.CredDeleteW.restype = wintypes.BOOL
        advapi32.CredFree.argtypes = [ctypes.c_void_p]
        advapi32.CredFree.restype = None

        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        self._advapi32 = advapi32
        self._kernel32 = kernel32
        self._Credential = Credential
        self._credential_pointer = credential_pointer
        self._ctypes = ctypes
        self._wintypes = wintypes

    def read(self, target: str) -> bytes | None:
        pointer = self._credential_pointer()
        if not self._advapi32.CredReadW(
            target,
            _WINDOWS_CREDENTIAL_TYPE_GENERIC,
            0,
            self._ctypes.byref(pointer),
        ):
            if self._ctypes.get_last_error() == _WINDOWS_ERROR_NOT_FOUND:
                return None
            raise _WindowsCredentialBackendError()
        try:
            credential = pointer.contents
            blob_size = int(credential.CredentialBlobSize)
            if blob_size > _WINDOWS_CREDENTIAL_BLOB_BYTES:
                raise _WindowsCredentialBackendError()
            if blob_size and not credential.CredentialBlob:
                raise _WindowsCredentialBackendError()
            return self._ctypes.string_at(credential.CredentialBlob, blob_size)
        finally:
            self._advapi32.CredFree(pointer)

    def write(self, target: str, blob: bytes) -> None:
        if not blob or len(blob) > _WINDOWS_CREDENTIAL_BLOB_BYTES:
            raise _WindowsCredentialBackendError()
        buffer = (self._ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        credential = self._Credential(
            Flags=0,
            Type=_WINDOWS_CREDENTIAL_TYPE_GENERIC,
            TargetName=target,
            Comment=None,
            LastWritten=self._wintypes.FILETIME(),
            CredentialBlobSize=len(blob),
            CredentialBlob=self._ctypes.cast(
                buffer, self._ctypes.POINTER(self._ctypes.c_ubyte)
            ),
            Persist=_WINDOWS_CREDENTIAL_PERSIST_LOCAL_MACHINE,
            AttributeCount=0,
            Attributes=None,
            TargetAlias=None,
            UserName=None,
        )
        if not self._advapi32.CredWriteW(self._ctypes.byref(credential), 0):
            raise _WindowsCredentialBackendError()

    def delete(self, target: str) -> bool:
        if self._advapi32.CredDeleteW(
            target,
            _WINDOWS_CREDENTIAL_TYPE_GENERIC,
            0,
        ):
            return True
        if self._ctypes.get_last_error() == _WINDOWS_ERROR_NOT_FOUND:
            return False
        raise _WindowsCredentialBackendError()

    @contextmanager
    def lock(self, name: str, *, nonblocking: bool):
        handle = self._kernel32.CreateMutexW(None, False, name)
        if not handle:
            raise _WindowsCredentialBackendError()
        acquired = False
        try:
            timeout = 0 if nonblocking else _WINDOWS_LOCK_WAIT_MILLISECONDS
            result = self._kernel32.WaitForSingleObject(handle, timeout)
            if result in (_WINDOWS_WAIT_OBJECT_0, _WINDOWS_WAIT_ABANDONED):
                acquired = True
            elif result == _WINDOWS_WAIT_TIMEOUT:
                raise _WindowsCredentialLockTimeout()
            else:
                raise _WindowsCredentialBackendError()
            yield
        finally:
            if acquired:
                self._kernel32.ReleaseMutex(handle)
            self._kernel32.CloseHandle(handle)


def _windows_credential_backend() -> _WindowsCredentialBackend:
    if not _uses_windows_credential_manager():
        raise _WindowsCredentialBackendError()
    return _WindowsCredentialBackend()


def _windows_namespace(home: Path | None) -> str:
    canonical_home = os.path.normcase(os.path.abspath(str(credential_home(home))))
    digest = hashlib.sha256(canonical_home.encode("utf-8", "surrogatepass")).hexdigest()
    return f"{_WINDOWS_TARGET_PREFIX}.{digest}"


def _windows_active_target(home: Path | None) -> str:
    return f"{_windows_namespace(home)}.active"


def _windows_chunk_target(namespace: str, generation: str, index: int) -> str:
    return f"{namespace}.generation.{generation}.chunk.{index}"


def _windows_mutex_name(home: Path | None, *, purpose: str) -> str:
    return f"Local\\{_windows_namespace(home)}.{purpose}"


@contextmanager
def _windows_credential_lock(
    home: Path | None,
    *,
    purpose: str,
    nonblocking: bool,
):
    try:
        backend = _windows_credential_backend()
        with backend.lock(
            _windows_mutex_name(home, purpose=purpose),
            nonblocking=nonblocking,
        ):
            yield backend
    except _WindowsCredentialLockTimeout as exc:
        code = "login_in_progress" if nonblocking else "credential_unreadable"
        raise CredentialError(code) from exc
    except _WindowsCredentialBackendError as exc:
        raise CredentialError("credential_unreadable") from exc


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


def _windows_metadata_bytes(
    *,
    generation: str,
    chunk_count: int,
    token_byte_length: int,
) -> bytes:
    payload = {
        "schema_version": CREDENTIAL_SCHEMA_VERSION,
        "scope": CREDENTIAL_SCOPE,
        "generation": generation,
        "chunk_count": chunk_count,
        "token_byte_length": token_byte_length,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_windows_metadata(raw: object) -> tuple[str, int, int]:
    if not isinstance(raw, bytes) or len(raw) > _WINDOWS_CREDENTIAL_BLOB_BYTES:
        raise CredentialError("credential_invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CredentialError("credential_invalid") from exc
    if not isinstance(parsed, dict) or set(parsed) != set(_WINDOWS_METADATA_KEYS):
        raise CredentialError("credential_invalid")
    if parsed["schema_version"] != CREDENTIAL_SCHEMA_VERSION or isinstance(
        parsed["schema_version"], bool
    ):
        raise CredentialError("credential_invalid")
    _validate_scope(parsed["scope"])
    generation = parsed["generation"]
    chunk_count = parsed["chunk_count"]
    token_byte_length = parsed["token_byte_length"]
    if (
        not isinstance(generation, str)
        or len(generation) != 32
        or any(character not in "0123456789abcdef" for character in generation)
    ):
        raise CredentialError("credential_invalid")
    if (
        isinstance(chunk_count, bool)
        or not isinstance(chunk_count, int)
        or not 1 <= chunk_count <= _WINDOWS_MAX_CHUNKS
    ):
        raise CredentialError("credential_invalid")
    if (
        isinstance(token_byte_length, bool)
        or not isinstance(token_byte_length, int)
        or not 1 <= token_byte_length <= _WINDOWS_MAX_TOKEN_BYTES
    ):
        raise CredentialError("credential_invalid")
    expected_chunks = (
        token_byte_length + _WINDOWS_CREDENTIAL_BLOB_BYTES - 1
    ) // _WINDOWS_CREDENTIAL_BLOB_BYTES
    if chunk_count != expected_chunks:
        raise CredentialError("credential_invalid")
    return generation, chunk_count, token_byte_length


def _load_windows_metadata(
    backend: _WindowsCredentialBackend,
    home: Path | None,
) -> tuple[str, int, int] | None:
    try:
        raw = backend.read(_windows_active_target(home))
    except _WindowsCredentialBackendError as exc:
        raise CredentialError("credential_unreadable") from exc
    if raw is None:
        return None
    return _parse_windows_metadata(raw)


def _delete_windows_generation(
    backend: _WindowsCredentialBackend,
    *,
    namespace: str,
    generation: str,
    chunk_count: int,
) -> None:
    try:
        for index in range(chunk_count):
            backend.delete(_windows_chunk_target(namespace, generation, index))
    except _WindowsCredentialBackendError as exc:
        raise CredentialError("credential_delete_failed") from exc


def _save_windows_credential(credential: StoredCredential, home: Path | None) -> None:
    token_bytes = credential.token.encode("utf-8")
    if not token_bytes or len(token_bytes) > _WINDOWS_MAX_TOKEN_BYTES:
        raise CredentialError("credential_invalid")
    chunks = [
        token_bytes[offset : offset + _WINDOWS_CREDENTIAL_BLOB_BYTES]
        for offset in range(0, len(token_bytes), _WINDOWS_CREDENTIAL_BLOB_BYTES)
    ]
    generation = secrets.token_hex(16)
    namespace = _windows_namespace(home)
    metadata = _windows_metadata_bytes(
        generation=generation,
        chunk_count=len(chunks),
        token_byte_length=len(token_bytes),
    )

    with _windows_credential_lock(
        home,
        purpose="custody",
        nonblocking=False,
    ) as backend:
        previous = _load_windows_metadata(backend, home)
        written_targets: list[str] = []
        try:
            for index, chunk in enumerate(chunks):
                target = _windows_chunk_target(namespace, generation, index)
                backend.write(target, chunk)
                written_targets.append(target)
            backend.write(_windows_active_target(home), metadata)
        except _WindowsCredentialBackendError as exc:
            for target in written_targets:
                try:
                    backend.delete(target)
                except _WindowsCredentialBackendError:
                    pass
            raise CredentialError("credential_write_failed") from exc

        if previous is not None:
            _delete_windows_generation(
                backend,
                namespace=namespace,
                generation=previous[0],
                chunk_count=previous[1],
            )


def _load_windows_credential(home: Path | None) -> StoredCredential | None:
    namespace = _windows_namespace(home)
    with _windows_credential_lock(
        home,
        purpose="custody",
        nonblocking=False,
    ) as backend:
        metadata = _load_windows_metadata(backend, home)
        if metadata is None:
            return None
        generation, chunk_count, token_byte_length = metadata
        chunks: list[bytes] = []
        try:
            for index in range(chunk_count):
                chunk = backend.read(_windows_chunk_target(namespace, generation, index))
                if (
                    chunk is None
                    or not isinstance(chunk, bytes)
                    or len(chunk) > _WINDOWS_CREDENTIAL_BLOB_BYTES
                ):
                    raise CredentialError("credential_invalid")
                chunks.append(chunk)
        except _WindowsCredentialBackendError as exc:
            raise CredentialError("credential_unreadable") from exc
    token_bytes = b"".join(chunks)
    if len(token_bytes) != token_byte_length:
        raise CredentialError("credential_invalid")
    try:
        token = token_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError("credential_invalid") from exc
    return StoredCredential(scope=CREDENTIAL_SCOPE, token=_validate_token(token))


def _delete_windows_credential(home: Path | None) -> bool:
    namespace = _windows_namespace(home)
    with _windows_credential_lock(
        home,
        purpose="custody",
        nonblocking=False,
    ) as backend:
        metadata = _load_windows_metadata(backend, home)
        if metadata is None:
            return False
        try:
            deleted = backend.delete(_windows_active_target(home))
        except _WindowsCredentialBackendError as exc:
            raise CredentialError("credential_delete_failed") from exc
        if not deleted:
            return False
        _delete_windows_generation(
            backend,
            namespace=namespace,
            generation=metadata[0],
            chunk_count=metadata[1],
        )
        return True


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
    """Atomically persist exactly one validated credential."""

    credential = StoredCredential(
        scope=_validate_scope(scope),
        token=_validate_token(token),
    )
    if _uses_windows_credential_manager():
        _save_windows_credential(credential, home)
        return
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

    if _uses_windows_credential_manager():
        return _load_windows_credential(home)
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

    if _uses_windows_credential_manager():
        return _delete_windows_credential(home)
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

    if _uses_windows_credential_manager():
        with _windows_credential_lock(
            home,
            purpose="login",
            nonblocking=True,
        ):
            yield
        return

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
