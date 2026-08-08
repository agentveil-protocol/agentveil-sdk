# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded paid package download, verification, and local install helpers."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import sys
import urllib.error
import zipfile
import urllib.request
from configparser import ConfigParser, DuplicateOptionError
from typing import Any, Callable, Mapping, Protocol

from agentveil_mcp_proxy.evidence.proof import _fsync_parent_directory
from agentveil_mcp_proxy.paid_provider import (
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    InstalledProviderActivationHandoffRequest,
    InstalledProviderActivationHandoffResult,
    MAX_HANDOFF_PROVIDER_ID_LENGTH,
    PAID_PROVIDER_ENTRYPOINT_GROUP,
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    PaidProviderSnapshot,
    assert_handoff_entrypoint_target,
    assert_handoff_request_fields_bounded,
    validate_installed_provider_activation_handoff_response,
    ERROR_HANDOFF_HOOK_EXCEPTION,
    ERROR_HANDOFF_HOOK_IMPORT_FAILED,
    ERROR_HANDOFF_HOOK_MALFORMED,
    ERROR_HANDOFF_HOOK_MISSING,
    ERROR_HANDOFF_HOOK_MULTIPLE,
    ERROR_HANDOFF_METADATA_OVERSIZED,
    ERROR_HANDOFF_RESPONSE_INACTIVE,
    ERROR_HANDOFF_RESPONSE_INVALID,
    contains_private_provider_marker,
)

INSTALL_FILENAME = "install.json"
PROVIDER_ID = "private_v1"
DEFAULT_PACKAGE_NAME = "agentveil-private-policy"
DEFAULT_PACKAGE_VERSION = "0.1.0"
DEFAULT_ARTIFACT_ID = "art_pkg_private_policy_001"
# Packaged zero-config paid backend. Explicit blank AVP_PAID_API_BASE_URL
# disables network (offline/test). Unset env uses this default.
DEFAULT_PAID_API_BASE_URL = "https://agentveil.dev"
ALLOWED_PACKAGE_NAMES = frozenset({DEFAULT_PACKAGE_NAME})
_BOUNDED_PACKAGE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]{0,16})?$")

BOUNDED_INSTALL_KEYS = frozenset(
    {
        "status",
        "provider_id",
        "package_name",
        "package_version",
        "public_fallback_available",
        "error_code",
        "last_installed_at",
        "install_safety_state",
        "install_safety_reason",
    }
)

INSTALL_SAFETY_OPERATION = "install"
INSTALL_SAFETY_SOURCE_REF = "src_private_policy_artifact"
INSTALL_SAFETY_SOURCE_REF_KIND = "workspace_registry"
INSTALL_SAFETY_REQUESTED_PACKAGE = "pkg_agentveil_private_policy"
INSTALL_SAFETY_EXPECTED_PACKAGE = "pkg_agentveil_private_policy"
PROVENANCE_INTENT_SOURCE_USER_DIRECT = "user_direct"
PROVENANCE_TARGET_SOURCE_WORKSPACE_REGISTRY = "workspace_registry"
PROVENANCE_TOOL_SOURCE_APPROVED_REGISTRY = "approved_registry"
PROVENANCE_METADATA_INFLUENCE_NONE = "none"
INSTALL_SAFETY_STATE_VERIFIED = "verified"
INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED = "review_recommended"
# claim-check: allow "blocked" is a bounded backend response state label.
INSTALL_SAFETY_STATE_BLOCKED = "blocked"
INSTALL_SAFETY_STATE_MALFORMED = "malformed"
INSTALL_SAFETY_DECISION_ALLOW = "allow"
INSTALL_SAFETY_DECISION_REDIRECT = "redirect"
INSTALL_SAFETY_DECISION_BLOCK = "block"
INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD = "HOLD"
INSTALL_SAFETY_ALLOWED_REQUEST_KEYS = frozenset(
    {
        "entitlement_token",
        "operation",
        "source_ref",
        "source_ref_kind",
        "user_pinned_source",
        "intent_source",
        "target_source",
        "tool_source",
        "metadata_influence",
        "requested_package",
        "expected_package",
        "package_namespace",
        "expected_hash",
        "resource_hash",
        "payload_hash",
    }
)

FORBIDDEN_LEAK_MARKERS = (
    "install_token",
    "entitlement_token",
    "presigned_url",
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Signature",
    "AmazonS3",
    "arn:aws",
    "s3.amazonaws.com",
    "/Users/",
    "/private/",
    "/var/folders/",
)

ERROR_BACKEND_UNAVAILABLE = "paid_backend_unavailable"
ERROR_ACTIVATION_INVALID = "activation_invalid"
ERROR_ENTITLEMENT_UNAVAILABLE = "entitlement_unavailable"
ERROR_DOWNLOAD_DENIED = "download_denied"
ERROR_HASH_MISMATCH = "artifact_hash_mismatch"
ERROR_PACKAGE_NAME_MISMATCH = "package_name_mismatch"
ERROR_VERSION_MISMATCH = "package_version_mismatch"
ERROR_INSTALL_FAILED = "install_failed"
ERROR_INSTALL_SAFETY_BLOCKED = "install_safety_blocked"
ERROR_INSTALL_SAFETY_MALFORMED = "install_safety_malformed"
ERROR_VENDORED_PROVIDER_MISSING = "vendored_provider_missing"
ERROR_VENDORED_PROVIDER_MULTIPLE = "vendored_provider_multiple"
ERROR_VENDORED_PROVIDER_MALFORMED = "vendored_provider_malformed"

MAX_HANDOFF_ENTRY_POINTS_BYTES = 8192
MAX_HANDOFF_DIST_INFO_METADATA_BYTES = 65536

_HANDOFF_RESPONSE_URL_RE = re.compile(r"(?i)(?:https?://|file://)")
_HANDOFF_RESPONSE_WINDOWS_ABS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\[^\s]+)")
_POSIX_ABS_PATH_BOUNDARY_CHARS = frozenset(" \t\n\r'\"`(,[{<:=;,")
_HANDOFF_RESPONSE_FORBIDDEN_MARKERS = (
    "activation_credential",
    "license_key",
    "entitlement_token",
    "presigned_url",
    "workspace",
    "member_id",
    "team_",
    "policy_release",
    "module_id",
)


def _handoff_response_text_contains_absolute_posix_path(text: str) -> bool:
    """Reject slash starts that indicate absolute or path-like values, not inline ratios."""

    for index, char in enumerate(text):
        if char != "/":
            continue
        if index == 0:
            return True
        if text[index - 1] in _POSIX_ABS_PATH_BOUNDARY_CHARS:
            return True
    return False


def _handoff_response_text_is_public_bounded(
    text: str | None,
    *,
    activation_credential: str,
    resolved_avp_home: str,
) -> bool:
    if text is None:
        return True
    if activation_credential and activation_credential in text:
        return False
    if resolved_avp_home and resolved_avp_home in text:
        return False
    if _HANDOFF_RESPONSE_URL_RE.search(text):
        return False
    if _HANDOFF_RESPONSE_WINDOWS_ABS_PATH_RE.search(text):
        return False
    if _handoff_response_text_contains_absolute_posix_path(text):
        return False
    lowered = text.lower()
    if any(marker in lowered for marker in _HANDOFF_RESPONSE_FORBIDDEN_MARKERS):
        return False
    if contains_private_provider_marker(text):
        return False
    return True


def assert_handoff_response_fields_public_bounded(
    *,
    summary: str | None,
    error_code: str | None,
    activation_credential: str,
    resolved_avp_home: str,
) -> None:
    """Reject hook response strings that would leak secrets, homes, or local URLs."""

    for field in (summary, error_code):
        if not _handoff_response_text_is_public_bounded(
            field,
            activation_credential=activation_credential,
            resolved_avp_home=resolved_avp_home,
        ):
            raise ValueError(ERROR_HANDOFF_RESPONSE_INVALID)


class PaidInstallError(ValueError):
    """Raised when paid install flow inputs or artifacts are invalid."""

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


class FreeBuilderInstallError(ValueError):
    """Bounded free Builder install failure without detail leak."""

    def __init__(self, code: str = "free_builder_install_failed"):
        self.code = str(code)
        super().__init__(self.code)


@dataclass(frozen=True)
class ActivationValidateResult:
    valid: bool
    customer_ref_fingerprint: str | None
    plan: str | None
    license_status: str | None
    subscription_status: str | None
    period_end: str | None
    public_fallback_available: bool
    error_code: str | None
    provider_handoff_required: bool = False


@dataclass(frozen=True)
class EntitlementResult:
    entitlement_token: str
    entitlement_id: str
    expires_at: str | None


@dataclass(frozen=True)
class InstallSafetyResult:
    ok: bool
    decision: str | None
    reason_code: str | None
    install_safety_state: str | None
    live_enforcement: str | None
    public_warning: str | None
    error_code: str | None


@dataclass(frozen=True)
class PackageAuthorizeResult:
    download_authorized: bool
    artifact_id: str | None
    package_name: str | None
    package_version: str | None
    artifact_hash: str | None
    artifact_size_bytes: int | None
    download_authorization_id: str | None
    public_fallback_available: bool
    error_code: str | None


@dataclass(frozen=True)
class WheelMetadata:
    package_name: str
    package_version: str


@dataclass(frozen=True)
class PaidActivateInstallResult:
    provider: PaidProviderSnapshot
    activation_status: str
    install_state: dict[str, Any]
    public_fallback_available: bool
    license_id: str
    install_safety_advisory: str | None = None


@dataclass(frozen=True)
class FreeBuilderWheelExpectations:
    """Optional server-owned wheel expectations when explicitly provided."""

    artifact_hash: str | None = None
    artifact_size_bytes: int | None = None
    package_name: str | None = None
    package_version: str | None = None


@dataclass(frozen=True)
class FreeBuilderInstallResult:
    install_state: dict[str, Any]
    public_fallback_available: bool


MAX_FREE_BUILDER_WHEEL_BYTES = 64 * 1024 * 1024
FREE_BUILDER_PLAN_FAMILY = "free_builder_preview"


class PaidBackendClient(Protocol):
    """HTTP contract client for paid activation and package install."""

    def validate_activation(self, license_key: str) -> ActivationValidateResult:
        ...

    def issue_entitlement(
        self,
        license_key: str,
        validation: ActivationValidateResult,
    ) -> EntitlementResult:
        ...

    def check_install_safety(
        self,
        entitlement_token: str,
    ) -> InstallSafetyResult:
        ...

    def authorize_package(
        self,
        entitlement_token: str,
        *,
        artifact_id: str,
        platform_name: str,
        python_version: str,
    ) -> PackageAuthorizeResult:
        ...

    def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
        ...


_backend_client: PaidBackendClient | None = None


def set_paid_backend_client(client: PaidBackendClient | None) -> None:
    global _backend_client
    _backend_client = client


def resolve_paid_backend_client() -> PaidBackendClient | None:
    """Resolve paid backend client for activation/install.

    - Injected in-process client (tests) wins.
    - ``AVP_PAID_API_BASE_URL`` unset → packaged ``DEFAULT_PAID_API_BASE_URL``.
    - ``AVP_PAID_API_BASE_URL=""`` → offline / no network.
    - Non-empty env → that base URL.
    """

    if _backend_client is not None:
        return _backend_client
    if "AVP_PAID_API_BASE_URL" in os.environ:
        base_url = os.environ.get("AVP_PAID_API_BASE_URL", "").strip()
        if not base_url:
            return None
        return HttpPaidBackendClient(base_url=base_url.rstrip("/"))
    return HttpPaidBackendClient(base_url=DEFAULT_PAID_API_BASE_URL)

def install_state_path(home: Path) -> Path:
    return home.expanduser() / "paid" / INSTALL_FILENAME


def vendor_root(home: Path) -> Path:
    return home.expanduser() / "paid" / "vendor"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def current_platform_name() -> str:
    mapping = {
        "Darwin": "darwin",
        "Linux": "linux",
        "Windows": "windows",
    }
    return mapping.get(platform.system(), "linux")


def current_python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def format_install_safety_advisory_line(reason_code: str | None) -> str:
    code = (reason_code or "unknown").strip() or "unknown"
    return f"Install check: review recommended ({code})"


def format_install_safety_blocked_message(reason_code: str | None) -> str:
    # claim-check: allow "blocked" is user-facing bounded status from backend.
    code = (reason_code or "blocked").strip() or "blocked"
    # claim-check: allow "blocked" is a bounded backend response state label.
    return f"install check blocked ({code})"


def build_install_safety_check_request(entitlement_token: str) -> dict[str, Any]:
    """Bounded request body aligned with private InstallSafetyCheckRequestSchema."""

    return {
        "entitlement_token": entitlement_token,
        "operation": INSTALL_SAFETY_OPERATION,
        "source_ref": INSTALL_SAFETY_SOURCE_REF,
        "source_ref_kind": INSTALL_SAFETY_SOURCE_REF_KIND,
        "user_pinned_source": False,
        "intent_source": PROVENANCE_INTENT_SOURCE_USER_DIRECT,
        "target_source": PROVENANCE_TARGET_SOURCE_WORKSPACE_REGISTRY,
        "tool_source": PROVENANCE_TOOL_SOURCE_APPROVED_REGISTRY,
        "metadata_influence": PROVENANCE_METADATA_INFLUENCE_NONE,
        "requested_package": INSTALL_SAFETY_REQUESTED_PACKAGE,
        "expected_package": INSTALL_SAFETY_EXPECTED_PACKAGE,
    }


def parse_install_safety_result(payload: Mapping[str, Any]) -> InstallSafetyResult:
    if not isinstance(payload, Mapping):
        raise PaidInstallError(ERROR_INSTALL_SAFETY_MALFORMED, exit_code=1)
    decision = _optional_str(payload.get("decision"))
    install_safety_state = _optional_str(payload.get("install_safety_state"))
    reason_code = _optional_str(payload.get("reason_code"))
    if not decision or not install_safety_state or not reason_code:
        raise PaidInstallError(ERROR_INSTALL_SAFETY_MALFORMED, exit_code=1)
    return InstallSafetyResult(
        ok=bool(payload.get("ok", True)),
        decision=decision,
        reason_code=reason_code,
        install_safety_state=install_safety_state,
        live_enforcement=_optional_str(payload.get("live_enforcement")),
        public_warning=_optional_str(payload.get("public_warning")),
        error_code=_optional_str(payload.get("error_code")),
    )


def evaluate_install_safety(result: InstallSafetyResult) -> tuple[str | None, str | None, str | None]:
    """Return advisory line, persisted state, persisted reason; or raise on deny."""

    state = (result.install_safety_state or "").strip().lower()
    decision = (result.decision or "").strip().lower()
    if not state:
        raise PaidInstallError(ERROR_INSTALL_SAFETY_MALFORMED, exit_code=1)

    if state in {INSTALL_SAFETY_STATE_BLOCKED, INSTALL_SAFETY_STATE_MALFORMED}:
        reason = result.reason_code or result.error_code or state
        raise PaidInstallError(format_install_safety_blocked_message(reason), exit_code=1)
    if decision == INSTALL_SAFETY_DECISION_BLOCK:
        # claim-check: allow "blocked" is a bounded fallback reason label.
        reason = result.reason_code or result.error_code or "blocked"
        raise PaidInstallError(format_install_safety_blocked_message(reason), exit_code=1)

    if state == INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED:
        advisory = result.public_warning or format_install_safety_advisory_line(result.reason_code)
        return advisory, state, result.reason_code

    if state == INSTALL_SAFETY_STATE_VERIFIED:
        return None, state, result.reason_code

    raise PaidInstallError(ERROR_INSTALL_SAFETY_MALFORMED, exit_code=1)


def assert_install_metadata_bounded(data: Mapping[str, Any]) -> None:
    extra = set(data) - BOUNDED_INSTALL_KEYS
    if extra:
        raise PaidInstallError(f"install metadata contains unexpected keys: {sorted(extra)}")


def load_install_state(path: Path) -> dict[str, Any] | None:
    """Load bounded install.json, or None when missing/unreadable/malformed.

    Corrupt on-disk state returns None. Callers treat None as Core-fallback /
    no active install and do not include host paths in the returned state.
    """

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        assert_install_metadata_bounded(payload)
    except PaidInstallError:
        return None
    status = payload.get("status")
    if not isinstance(status, str) or not status:
        return None
    return dict(payload)

def write_install_state(path: Path, data: Mapping[str, Any]) -> None:
    assert_install_metadata_bounded(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except PermissionError as exc:
        raise PaidInstallError(f"cannot set private directory permissions for {path.parent}") from exc
    tmp_path = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(tmp_path, flags, 0o600), "w", encoding="utf-8") as fh:
        json.dump(dict(data), fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)
    _fsync_parent_directory(path)


def scan_paid_output_for_leaks(text: str, *, secrets: tuple[str, ...] = ()) -> None:
    for secret in secrets:
        if secret and secret in text:
            raise PaidInstallError("paid output leaked forbidden secret marker")
    lowered = text.lower()
    for marker in FORBIDDEN_LEAK_MARKERS:
        if marker.lower() in lowered:
            raise PaidInstallError(f"paid output leaked forbidden marker: {marker}")


def validate_bounded_package_name(name: str) -> str:
    """Accept only the allowlisted private package distribution name."""

    normalized = name.strip()
    if normalized not in ALLOWED_PACKAGE_NAMES:
        raise PaidInstallError(ERROR_PACKAGE_NAME_MISMATCH, exit_code=1)
    if any(separator in normalized for separator in ("/", "\\", "..")):
        raise PaidInstallError(ERROR_PACKAGE_NAME_MISMATCH, exit_code=1)
    return normalized


def validate_bounded_package_version(version: str) -> str:
    """Accept only a bounded semver-like package version."""

    normalized = version.strip()
    if not _BOUNDED_PACKAGE_VERSION_RE.fullmatch(normalized):
        raise PaidInstallError(ERROR_VERSION_MISMATCH, exit_code=1)
    return normalized


def _parse_metadata_text(text: str) -> WheelMetadata:
    package_name: str | None = None
    package_version: str | None = None
    for line in text.splitlines():
        if line.startswith("Name: "):
            package_name = line.removeprefix("Name: ").strip()
        elif line.startswith("Version: "):
            package_version = line.removeprefix("Version: ").strip()
    if not package_name or not package_version:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    return WheelMetadata(
        package_name=validate_bounded_package_name(package_name),
        package_version=validate_bounded_package_version(package_version),
    )


def _metadata_entry_name(archive: zipfile.ZipFile) -> str:
    matches = [
        name
        for name in archive.namelist()
        if name.endswith(".dist-info/METADATA") and _is_safe_zip_member(name)
    ]
    if len(matches) != 1:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    return matches[0]


def parse_wheel_metadata(wheel_bytes: bytes) -> WheelMetadata:
    """Read package name/version from wheel ``METADATA``."""

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            metadata_name = _metadata_entry_name(archive)
            metadata_text = archive.read(metadata_name).decode("utf-8")
    except (zipfile.BadZipFile, UnicodeDecodeError, KeyError) as exc:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1) from exc
    return _parse_metadata_text(metadata_text)


def _is_safe_zip_member(name: str) -> bool:
    if not name or name.startswith(("/", "\\")):
        return False
    return ".." not in Path(name).parts


def _validated_wheel_members(archive: zipfile.ZipFile) -> list[str]:
    members = archive.namelist()
    if len(members) != len(set(members)):
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    return members


def _resolved_home_root(home: Path) -> Path:
    return home.expanduser().resolve()


def _assert_trusted_home_path(home: Path, path: Path) -> Path:
    """Reject symlink components between AVP home and the target path."""

    home_path = home.expanduser()
    if home_path.is_symlink():
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    home_root = home_path.resolve()
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(home_root)
    except ValueError as exc:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1) from exc

    walk = home_root
    for part in resolved.relative_to(home_root).parts:
        walk = walk / part
        if walk.is_symlink():
            raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    return resolved


def _assert_non_symlink_vendor_path(home: Path, path: Path) -> None:
    _assert_trusted_home_path(home, path)


def _vendor_live_dir(home: Path, *, package_name: str, package_version: str) -> Path:
    return vendor_root(home) / f"{package_name}-{package_version}"


def _vendor_stage_dir(home: Path, *, package_name: str, package_version: str) -> Path:
    token = secrets.token_hex(8)
    return vendor_root(home) / f".staging-{package_name}-{package_version}-{token}"


def _discard_staged_vendor(stage_dir: Path) -> None:
    if stage_dir.exists():
        shutil.rmtree(stage_dir, ignore_errors=True)


@dataclass(frozen=True)
class _VendorPublishRollback:
    backup_dir: Path | None
    created_live: bool


def _publish_staged_vendor(*, home: Path, stage_dir: Path, live_dir: Path) -> _VendorPublishRollback:
    _assert_non_symlink_vendor_path(home, stage_dir)
    if live_dir.exists():
        _assert_non_symlink_vendor_path(home, live_dir)
        backup_dir = live_dir.with_name(f"{live_dir.name}.backup")
        _discard_staged_vendor(backup_dir)
        os.replace(live_dir, backup_dir)
        try:
            os.replace(stage_dir, live_dir)
        except OSError:
            if live_dir.exists():
                shutil.rmtree(live_dir, ignore_errors=True)
            os.replace(backup_dir, live_dir)
            raise
        return _VendorPublishRollback(backup_dir=backup_dir, created_live=False)
    live_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(stage_dir, live_dir)
    return _VendorPublishRollback(backup_dir=None, created_live=True)


def _rollback_published_vendor(*, live_dir: Path, rollback: _VendorPublishRollback) -> None:
    if rollback.backup_dir is not None and rollback.backup_dir.exists():
        if live_dir.exists():
            shutil.rmtree(live_dir, ignore_errors=True)
        os.replace(rollback.backup_dir, live_dir)
        return
    if rollback.created_live and live_dir.exists():
        shutil.rmtree(live_dir, ignore_errors=True)


@dataclass(frozen=True)
class _WheelCacheRollback:
    backup_path: Path | None
    created_live: bool


def _rollback_wheel_cache(*, wheel_path: Path, rollback: _WheelCacheRollback) -> None:
    if rollback.backup_path is not None and rollback.backup_path.exists():
        if wheel_path.exists():
            wheel_path.unlink(missing_ok=True)
        os.replace(rollback.backup_path, wheel_path)
        return
    if rollback.created_live and wheel_path.exists():
        wheel_path.unlink(missing_ok=True)


def _commit_wheel_cache(*, wheel_stage_path: Path, wheel_path: Path) -> None:
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    if wheel_path.exists():
        backup_path = wheel_path.with_name(f"{wheel_path.name}.backup")
        if backup_path.exists():
            backup_path.unlink(missing_ok=True)
        os.replace(wheel_path, backup_path)
        rollback = _WheelCacheRollback(backup_path=backup_path, created_live=False)
        try:
            os.replace(wheel_stage_path, wheel_path)
            os.chmod(wheel_path, 0o600)
            backup_path.unlink(missing_ok=True)
        except OSError:
            _rollback_wheel_cache(wheel_path=wheel_path, rollback=rollback)
            raise
        return
    rollback = _WheelCacheRollback(backup_path=None, created_live=True)
    try:
        os.replace(wheel_stage_path, wheel_path)
        os.chmod(wheel_path, 0o600)
    except OSError:
        _rollback_wheel_cache(wheel_path=wheel_path, rollback=rollback)
        raise


def _restore_install_state_bytes(path: Path, prior_bytes: bytes | None) -> None:
    if prior_bytes is None:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(prior_bytes)


def verify_free_builder_wheel_artifact(
    wheel_bytes: bytes,
    *,
    expectations: FreeBuilderWheelExpectations | None = None,
) -> WheelMetadata:
    if len(wheel_bytes) > MAX_FREE_BUILDER_WHEEL_BYTES:
        raise FreeBuilderInstallError("wheel_too_large")
    bounded = expectations or FreeBuilderWheelExpectations()
    if not bounded.artifact_hash:
        raise FreeBuilderInstallError("artifact_hash_required")
    if bounded.artifact_size_bytes is None:
        raise FreeBuilderInstallError("artifact_size_required")
    try:
        metadata = parse_wheel_metadata(wheel_bytes)
        expected_package_name = validate_bounded_package_name(metadata.package_name)
        expected_package_version = validate_bounded_package_version(metadata.package_version)
        if bounded.package_name is not None:
            bounded_name = validate_bounded_package_name(bounded.package_name)
            if metadata.package_name != bounded_name:
                raise FreeBuilderInstallError(ERROR_PACKAGE_NAME_MISMATCH)
            expected_package_name = bounded_name
        if bounded.package_version is not None:
            bounded_version = validate_bounded_package_version(bounded.package_version)
            if metadata.package_version != bounded_version:
                raise FreeBuilderInstallError(ERROR_VERSION_MISMATCH)
            expected_package_version = bounded_version
        verify_wheel_artifact(
            wheel_bytes,
            expected_hash=bounded.artifact_hash,
            expected_size=bounded.artifact_size_bytes,
            expected_package_name=expected_package_name,
            expected_package_version=expected_package_version,
        )
    except PaidInstallError as exc:
        raise FreeBuilderInstallError(str(exc.args[0])) from exc
    return WheelMetadata(
        package_name=expected_package_name,
        package_version=expected_package_version,
    )


def verify_wheel_artifact(
    wheel_bytes: bytes,
    *,
    expected_hash: str,
    expected_size: int | None,
    expected_package_name: str,
    expected_package_version: str,
) -> WheelMetadata:
    if expected_size is not None and len(wheel_bytes) != expected_size:
        raise PaidInstallError("downloaded artifact size mismatch", exit_code=1)
    digest = sha256_hex(wheel_bytes)
    if digest != expected_hash.lower():
        raise PaidInstallError(ERROR_HASH_MISMATCH, exit_code=1)
    bounded_name = validate_bounded_package_name(expected_package_name)
    bounded_version = validate_bounded_package_version(expected_package_version)
    metadata = parse_wheel_metadata(wheel_bytes)
    if metadata.package_name != bounded_name:
        raise PaidInstallError(ERROR_PACKAGE_NAME_MISMATCH, exit_code=1)
    if metadata.package_version != bounded_version:
        raise PaidInstallError(ERROR_VERSION_MISMATCH, exit_code=1)
    return metadata


def install_wheel_to_vendor(
    *,
    home: Path,
    wheel_path: Path,
    target_dir: Path,
    expected_package_name: str,
    expected_package_version: str,
    require_empty_target: bool = False,
) -> None:
    _assert_non_symlink_vendor_path(home, target_dir)
    if target_dir.exists():
        if target_dir.is_symlink() or not target_dir.is_dir():
            raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
        if require_empty_target and any(target_dir.iterdir()):
            raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        _assert_non_symlink_vendor_path(home, target_dir)

    resolved_target = target_dir.resolve()
    bounded_name = validate_bounded_package_name(expected_package_name)
    bounded_version = validate_bounded_package_version(expected_package_version)
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            metadata = parse_wheel_metadata(wheel_path.read_bytes())
            if metadata.package_name != bounded_name:
                raise PaidInstallError(ERROR_PACKAGE_NAME_MISMATCH, exit_code=1)
            if metadata.package_version != bounded_version:
                raise PaidInstallError(ERROR_VERSION_MISMATCH, exit_code=1)
            _metadata_entry_name(archive)
            members = _validated_wheel_members(archive)
            for member in members:
                if not _is_safe_zip_member(member):
                    raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
                destination = (target_dir / member).resolve()
                if destination != resolved_target and resolved_target not in destination.parents:
                    raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
            for member in members:
                if member.endswith("/"):
                    continue
                destination = target_dir / member
                if destination.exists() and destination.is_symlink():
                    raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
    except zipfile.BadZipFile:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)


class HttpPaidBackendClient:
    """Minimal HTTP client for bounded paid backend contract paths."""

    def __init__(self, *, base_url: str, timeout_seconds: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps(dict(payload)).encode("utf-8")
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except OSError:
                detail = ""
            if detail:
                scan_paid_output_for_leaks(detail)
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        except urllib.error.URLError as exc:
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        if not isinstance(parsed, dict):
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1)
        return parsed

    def _post_bytes(self, path: str, payload: Mapping[str, Any]) -> bytes:
        body = json.dumps(dict(payload)).encode("utf-8")
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/octet-stream"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            scan_paid_output_for_leaks(detail)
            raise PaidInstallError(ERROR_DOWNLOAD_DENIED, exit_code=1) from exc
        except urllib.error.URLError as exc:
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc

    def _post_install_safety_json(
        self,
        payload: Mapping[str, Any],
        *,
        entitlement_token: str,
    ) -> dict[str, Any]:
        body = json.dumps(dict(payload)).encode("utf-8")
        request = urllib.request.Request(
            # claim-check: allow "safety" is the private advisory endpoint name.
            f"{self._base_url}/v1/paid/install/safety-check",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read()
            except OSError:
                raw = b""
            if raw and exc.code in {403, 422}:
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError as decode_exc:
                    raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from decode_exc
                if isinstance(parsed, dict):
                    scan_paid_output_for_leaks(json.dumps(parsed), secrets=(entitlement_token,))
                    return parsed
            if exc.code in {403, 422}:
                raise PaidInstallError(ERROR_INSTALL_SAFETY_BLOCKED, exit_code=1) from exc
            detail = raw.decode("utf-8", errors="replace") if raw else ""
            if detail:
                scan_paid_output_for_leaks(detail)
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        except urllib.error.URLError as exc:
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1) from exc
        if not isinstance(parsed, dict):
            raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1)
        scan_paid_output_for_leaks(json.dumps(parsed), secrets=(entitlement_token,))
        return parsed

    def validate_activation(self, license_key: str) -> ActivationValidateResult:
        payload = self._post_json("/v1/paid/activate/validate", {"license_key": license_key})
        handoff_required = payload.get("provider_handoff_required")
        if handoff_required is None:
            provider_handoff_required = False
        elif isinstance(handoff_required, bool):
            provider_handoff_required = handoff_required
        else:
            raise PaidInstallError(ERROR_ACTIVATION_INVALID, exit_code=1)
        return ActivationValidateResult(
            valid=bool(payload.get("valid")),
            customer_ref_fingerprint=_optional_str(payload.get("customer_ref_fingerprint")),
            plan=_optional_str(payload.get("plan")),
            license_status=_optional_str(payload.get("license_status")),
            subscription_status=_optional_str(payload.get("subscription_status")),
            period_end=_optional_str(payload.get("period_end")),
            public_fallback_available=bool(payload.get("public_fallback_available", True)),
            error_code=_optional_str(payload.get("error_code")),
            provider_handoff_required=provider_handoff_required,
        )

    def issue_entitlement(
        self,
        license_key: str,
        validation: ActivationValidateResult,
    ) -> EntitlementResult:
        del validation
        payload = self._post_json(
            "/v1/paid/activate/entitlement",
            {"license_key": license_key},
        )
        token = _optional_str(payload.get("entitlement_token"))
        entitlement_id = _optional_str(payload.get("entitlement_id"))
        if not token or not entitlement_id:
            raise PaidInstallError(ERROR_ENTITLEMENT_UNAVAILABLE, exit_code=1)
        return EntitlementResult(
            entitlement_token=token,
            entitlement_id=entitlement_id,
            expires_at=_optional_str(payload.get("expires_at")),
        )

    def check_install_safety(
        self,
        entitlement_token: str,
    ) -> InstallSafetyResult:
        request_payload = build_install_safety_check_request(entitlement_token)
        response_payload = self._post_install_safety_json(
            request_payload,
            entitlement_token=entitlement_token,
        )
        return parse_install_safety_result(response_payload)

    def authorize_package(
        self,
        entitlement_token: str,
        *,
        artifact_id: str,
        platform_name: str,
        python_version: str,
    ) -> PackageAuthorizeResult:
        payload = self._post_json(
            "/v1/paid/packages/authorize",
            {
                "entitlement_token": entitlement_token,
                "artifact_id": artifact_id,
                "platform": platform_name,
                "python_version": python_version,
            },
        )
        return PackageAuthorizeResult(
            download_authorized=bool(payload.get("download_authorized")),
            artifact_id=_optional_str(payload.get("artifact_id")),
            package_name=_optional_str(payload.get("package_name")) or DEFAULT_PACKAGE_NAME,
            package_version=_optional_str(payload.get("package_version")) or DEFAULT_PACKAGE_VERSION,
            artifact_hash=_optional_str(payload.get("artifact_hash")),
            artifact_size_bytes=_optional_int(payload.get("artifact_size_bytes")),
            download_authorization_id=_optional_str(payload.get("download_authorization_id")),
            public_fallback_available=bool(payload.get("public_fallback_available", True)),
            error_code=_optional_str(payload.get("error_code")),
        )

    def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
        if not authorization.download_authorized or not authorization.download_authorization_id:
            raise PaidInstallError(ERROR_DOWNLOAD_DENIED, exit_code=1)
        return self._post_bytes(
            "/v1/paid/packages/download",
            {"download_authorization_id": authorization.download_authorization_id},
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def activation_reference_from_credential(license_key: str) -> str:
    digest = hashlib.sha256(license_key.encode("utf-8")).hexdigest()
    return f"act_ref_{digest}"


def _normalized_dist_info_prefix(package_name: str, package_version: str) -> str:
    module_name = package_name.replace("-", "_")
    return f"{module_name}-{package_version}.dist-info"


def _find_exact_dist_info_dir(vendor_dir: Path, *, package_name: str, package_version: str) -> Path:
    expected_prefix = _normalized_dist_info_prefix(package_name, package_version)
    matches = [
        path
        for path in vendor_dir.iterdir()
        if path.is_dir() and path.name == expected_prefix and _is_safe_zip_member(path.name)
    ]
    if len(matches) != 1:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MISSING, exit_code=1)
    return matches[0]


def _read_bounded_dist_info_file(dist_info_dir: Path, filename: str, *, max_bytes: int) -> str:
    path = dist_info_dir / filename
    if not path.is_file():
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MISSING, exit_code=1)
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise PaidInstallError(ERROR_HANDOFF_METADATA_OVERSIZED, exit_code=1)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MALFORMED, exit_code=1) from exc


def parse_vendored_entry_points(text: str) -> dict[str, list[tuple[str, str]]]:
    parser = ConfigParser()
    parser.optionxform = str  # preserve case for entry-point names
    try:
        parser.read_string(text)
    except DuplicateOptionError as exc:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MULTIPLE, exit_code=1) from exc
    except Exception as exc:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MALFORMED, exit_code=1) from exc
    grouped: dict[str, list[tuple[str, str]]] = {}
    for section in parser.sections():
        entries: list[tuple[str, str]] = []
        for name, target in parser.items(section):
            entries.append((name.strip(), target.strip()))
        grouped[section.strip()] = entries
    return grouped


def discover_exact_installed_activation_hook(
    vendor_dir: Path,
    *,
    package_name: str,
    package_version: str,
) -> tuple[str, str]:
    """Discover one compatible hook from the exact vendored distribution only."""

    dist_info_dir = _find_exact_dist_info_dir(
        vendor_dir,
        package_name=package_name,
        package_version=package_version,
    )
    _read_bounded_dist_info_file(
        dist_info_dir,
        "METADATA",
        max_bytes=MAX_HANDOFF_DIST_INFO_METADATA_BYTES,
    )
    entry_points_text = _read_bounded_dist_info_file(
        dist_info_dir,
        "entry_points.txt",
        max_bytes=MAX_HANDOFF_ENTRY_POINTS_BYTES,
    )
    grouped = parse_vendored_entry_points(entry_points_text)
    candidates = grouped.get(INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP, [])
    compatible = [
        (name, target)
        for name, target in candidates
        if name == INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME and target
    ]
    if not compatible:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MISSING, exit_code=1)
    if len(compatible) > 1:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MULTIPLE, exit_code=1)
    _, target = compatible[0]
    try:
        return assert_handoff_entrypoint_target(target)
    except ValueError:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_MALFORMED, exit_code=1)


def discover_exact_vendored_paid_provider_entry(
    vendor_dir: Path,
    *,
    package_name: str,
    package_version: str,
    provider_id: str,
) -> tuple[str, str]:
    """Discover one compatible paid provider entry from the exact vendored wheel."""

    dist_info_dir = _find_exact_dist_info_dir(
        vendor_dir,
        package_name=package_name,
        package_version=package_version,
    )
    _read_bounded_dist_info_file(
        dist_info_dir,
        "METADATA",
        max_bytes=MAX_HANDOFF_DIST_INFO_METADATA_BYTES,
    )
    entry_points_text = _read_bounded_dist_info_file(
        dist_info_dir,
        "entry_points.txt",
        max_bytes=MAX_HANDOFF_ENTRY_POINTS_BYTES,
    )
    grouped = parse_vendored_entry_points(entry_points_text)
    candidates = grouped.get(PAID_PROVIDER_ENTRYPOINT_GROUP, [])
    compatible = [
        (name, target)
        for name, target in candidates
        if name == provider_id and target
    ]
    if not compatible:
        raise PaidInstallError(ERROR_VENDORED_PROVIDER_MISSING, exit_code=1)
    if len(compatible) > 1:
        raise PaidInstallError(ERROR_VENDORED_PROVIDER_MULTIPLE, exit_code=1)
    _, target = compatible[0]
    try:
        return assert_handoff_entrypoint_target(target)
    except ValueError:
        raise PaidInstallError(ERROR_VENDORED_PROVIDER_MALFORMED, exit_code=1)


def resolve_vendored_paid_provider(*, home: Path | None = None) -> Any | None:
    """Load a trusted vendored paid provider from bounded install state."""

    resolved_home = (home or Path(os.environ.get("AVP_HOME", "~/.avp"))).expanduser()
    try:
        _assert_trusted_home_path(resolved_home, resolved_home / "paid")
    except PaidInstallError:
        return None

    install_state = load_install_state(install_state_path(resolved_home))
    if install_state is None or install_state.get("status") != STATUS_ACTIVE:
        return None

    provider_id = install_state.get("provider_id")
    package_name = install_state.get("package_name")
    package_version = install_state.get("package_version")
    if not isinstance(provider_id, str) or not provider_id.strip():
        return None
    if not isinstance(package_name, str) or not isinstance(package_version, str):
        return None
    if len(provider_id) > MAX_HANDOFF_PROVIDER_ID_LENGTH:
        return None

    try:
        expected_package_name = validate_bounded_package_name(package_name)
        expected_package_version = validate_bounded_package_version(package_version)
    except PaidInstallError:
        return None

    vendor_dir = _vendor_live_dir(
        resolved_home,
        package_name=expected_package_name,
        package_version=expected_package_version,
    )
    if not vendor_dir.is_dir():
        return None

    try:
        _assert_non_symlink_vendor_path(resolved_home, vendor_dir)
        module_path, attr_name = discover_exact_vendored_paid_provider_entry(
            vendor_dir,
            package_name=expected_package_name,
            package_version=expected_package_version,
            provider_id=provider_id,
        )
        factory = load_vendored_hook_callable(
            vendor_dir,
            home=resolved_home,
            module_path=module_path,
            attr_name=attr_name,
        )
        loaded = factory()
        provider = loaded() if callable(loaded) else loaded
        if provider is None:
            return None
        discovered_id = getattr(provider, "provider_id", None)
        if discovered_id is not None and str(discovered_id) != provider_id:
            return None
        return provider
    except Exception:
        return None


def _module_origin_under_vendor(module: Any, vendor_root: Path) -> bool:
    file_path = getattr(module, "__file__", None)
    if isinstance(file_path, str) and file_path:
        try:
            Path(file_path).resolve().relative_to(vendor_root)
            return True
        except ValueError:
            return False
    module_paths = getattr(module, "__path__", None)
    if module_paths is None:
        return False
    entries = [entry for entry in module_paths if isinstance(entry, str)]
    if not entries:
        return False
    for entry in entries:
        try:
            Path(entry).resolve().relative_to(vendor_root)
        except ValueError:
            return False
    return True


def _assert_vendored_import_origins(
    *,
    vendor_dir: Path,
    package_root: str,
    package_prefix: str,
) -> None:
    vendor_root = vendor_dir.resolve()
    for key, module in sys.modules.items():
        if key != package_root and not key.startswith(package_prefix):
            continue
        if module is None or not _module_origin_under_vendor(module, vendor_root):
            raise PaidInstallError(ERROR_HANDOFF_HOOK_IMPORT_FAILED, exit_code=1)


def load_vendored_hook_callable(
    vendor_dir: Path,
    *,
    home: Path,
    module_path: str,
    attr_name: str,
) -> Callable[[InstalledProviderActivationHandoffRequest], Mapping[str, Any]]:
    _assert_non_symlink_vendor_path(home, vendor_dir)
    package_root = module_path.split(".", 1)[0]
    package_prefix = f"{package_root}."
    package_dir = vendor_dir / package_root.replace(".", "/")
    module_file = vendor_dir.joinpath(*module_path.split(".")).with_suffix(".py")
    if not package_dir.is_dir() and not module_file.is_file():
        raise PaidInstallError(ERROR_HANDOFF_HOOK_IMPORT_FAILED, exit_code=1)

    original_modules = {
        key: value
        for key, value in sys.modules.items()
        if key == package_root or key.startswith(package_prefix)
    }
    vendor_str = str(vendor_dir.resolve())
    inserted = False
    imported_module = None
    try:
        if vendor_str not in sys.path:
            sys.path.insert(0, vendor_str)
            inserted = True
        for key in list(sys.modules):
            if key == package_root or key.startswith(package_prefix):
                sys.modules.pop(key, None)
        imported_module = importlib.import_module(module_path)
        _assert_vendored_import_origins(
            vendor_dir=vendor_dir,
            package_root=package_root,
            package_prefix=package_prefix,
        )
    except Exception:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_IMPORT_FAILED, exit_code=1) from None
    finally:
        if inserted:
            with contextlib.suppress(ValueError):
                sys.path.remove(vendor_str)
        for key in list(sys.modules):
            if (key == package_root or key.startswith(package_prefix)) and key not in original_modules:
                sys.modules.pop(key, None)
        sys.modules.update(original_modules)

    hook = getattr(imported_module, attr_name, None)
    if not callable(hook):
        raise PaidInstallError(ERROR_HANDOFF_HOOK_IMPORT_FAILED, exit_code=1)
    return hook


def invoke_installed_provider_activation_handoff(
    *,
    license_key: str,
    validation: ActivationValidateResult,
    home: Path,
    package_name: str,
    package_version: str,
    provider_id: str,
    vendor_dir: Path,
) -> InstalledProviderActivationHandoffResult:
    module_path, attr_name = discover_exact_installed_activation_hook(
        vendor_dir,
        package_name=package_name,
        package_version=package_version,
    )
    hook = load_vendored_hook_callable(
        vendor_dir,
        home=home,
        module_path=module_path,
        attr_name=attr_name,
    )
    resolved_home = str(home.expanduser().resolve())
    assert_handoff_request_fields_bounded(
        contract_version=INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION,
        activation_credential=license_key,
        activation_reference=activation_reference_from_credential(license_key),
        plan_family=validation.plan,
        package_name=package_name,
        package_version=package_version,
        provider_id=provider_id,
        avp_home=resolved_home,
    )
    request = InstalledProviderActivationHandoffRequest(
        contract_version=INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION,
        activation_credential=license_key,
        activation_reference=activation_reference_from_credential(license_key),
        plan_family=validation.plan,
        package_name=package_name,
        package_version=package_version,
        provider_id=provider_id,
        avp_home=resolved_home,
    )
    try:
        raw_response = hook(request)
    except Exception:
        raise PaidInstallError(ERROR_HANDOFF_HOOK_EXCEPTION, exit_code=1) from None
    try:
        result = validate_installed_provider_activation_handoff_response(raw_response)
    except ValueError as exc:
        raise PaidInstallError(str(exc), exit_code=1) from None
    try:
        assert_handoff_response_fields_public_bounded(
            summary=result.summary,
            error_code=result.error_code,
            activation_credential=license_key,
            resolved_avp_home=resolved_home,
        )
    except ValueError:
        raise PaidInstallError(ERROR_HANDOFF_RESPONSE_INVALID, exit_code=1) from None
    if result.status != STATUS_ACTIVE:
        raise PaidInstallError(
            result.error_code or ERROR_HANDOFF_RESPONSE_INACTIVE,
            exit_code=1,
        )
    return result


def run_paid_activate_install_flow(
    *,
    license_key: str,
    home: Path,
    client: PaidBackendClient | None = None,
    artifact_id: str | None = None,
) -> PaidActivateInstallResult:
    """Run validate -> entitlement -> authorize -> download -> verify -> install."""

    backend = client or resolve_paid_backend_client()
    if backend is None:
        raise PaidInstallError(ERROR_BACKEND_UNAVAILABLE, exit_code=1)

    validation = backend.validate_activation(license_key)
    if not validation.valid:
        raise PaidInstallError(
            validation.error_code or ERROR_ACTIVATION_INVALID,
            exit_code=1,
        )

    entitlement = backend.issue_entitlement(license_key, validation)
    resolved_artifact_id = artifact_id or os.environ.get("AVP_PAID_ARTIFACT_ID", DEFAULT_ARTIFACT_ID)
    # claim-check: allow "safety" is advisory-only; install still verifies hash/metadata.
    install_check = backend.check_install_safety(entitlement.entitlement_token)
    install_safety_advisory, install_safety_state, install_safety_reason = evaluate_install_safety(
        install_check,
    )
    authorization = backend.authorize_package(
        entitlement.entitlement_token,
        artifact_id=resolved_artifact_id,
        platform_name=current_platform_name(),
        python_version=current_python_version(),
    )
    if not authorization.download_authorized:
        raise PaidInstallError(authorization.error_code or ERROR_DOWNLOAD_DENIED, exit_code=1)
    if not authorization.artifact_hash:
        raise PaidInstallError(ERROR_DOWNLOAD_DENIED, exit_code=1)

    wheel_bytes = backend.download_package(authorization)
    expected_package_name = validate_bounded_package_name(
        authorization.package_name or DEFAULT_PACKAGE_NAME,
    )
    expected_package_version = validate_bounded_package_version(
        authorization.package_version or DEFAULT_PACKAGE_VERSION,
    )
    verify_wheel_artifact(
        wheel_bytes,
        expected_hash=authorization.artifact_hash,
        expected_size=authorization.artifact_size_bytes,
        expected_package_name=expected_package_name,
        expected_package_version=expected_package_version,
    )

    wheel_dir = home / "paid" / "cache"
    wheel_path = wheel_dir / f"{expected_package_name}-{expected_package_version}.whl"
    wheel_stage_path = wheel_dir / f".staging-{expected_package_name}-{expected_package_version}-{secrets.token_hex(8)}.whl"

    target_dir = _vendor_live_dir(
        home,
        package_name=expected_package_name,
        package_version=expected_package_version,
    )
    stage_dir = _vendor_stage_dir(
        home,
        package_name=expected_package_name,
        package_version=expected_package_version,
    )
    _assert_trusted_home_path(home, home / "paid")
    _assert_trusted_home_path(home, vendor_root(home))
    if target_dir.exists():
        _assert_non_symlink_vendor_path(home, target_dir)

    from agentveil_mcp_proxy.paid_activation import synthetic_license_id, utc_now_iso

    install_path = install_state_path(home)
    prior_install_bytes = install_path.read_bytes() if install_path.is_file() else None
    public_fallback_available = authorization.public_fallback_available
    try:
        wheel_stage_path.parent.mkdir(parents=True, exist_ok=True)
        wheel_stage_path.write_bytes(wheel_bytes)
        os.chmod(wheel_stage_path, 0o600)

        install_wheel_to_vendor(
            home=home,
            wheel_path=wheel_stage_path,
            target_dir=stage_dir,
            expected_package_name=expected_package_name,
            expected_package_version=expected_package_version,
            require_empty_target=True,
        )
        if validation.provider_handoff_required:
            handoff = invoke_installed_provider_activation_handoff(
                license_key=license_key,
                validation=validation,
                home=home,
                package_name=expected_package_name,
                package_version=expected_package_version,
                provider_id=PROVIDER_ID,
                vendor_dir=stage_dir,
            )
            public_fallback_available = handoff.public_fallback_available

        install_state = {
            "status": STATUS_ACTIVE,
            "provider_id": PROVIDER_ID,
            "package_name": expected_package_name,
            "package_version": expected_package_version,
            "public_fallback_available": public_fallback_available,
            "error_code": None,
            "last_installed_at": utc_now_iso(),
            "install_safety_state": install_safety_state,
            "install_safety_reason": install_safety_reason,
        }
        write_install_state(install_path, install_state)
        vendor_publish_rollback: _VendorPublishRollback | None = None
        try:
            vendor_publish_rollback = _publish_staged_vendor(
                home=home,
                stage_dir=stage_dir,
                live_dir=target_dir,
            )
            _commit_wheel_cache(wheel_stage_path=wheel_stage_path, wheel_path=wheel_path)
        except Exception:
            _restore_install_state_bytes(install_path, prior_install_bytes)
            if vendor_publish_rollback is not None:
                _rollback_published_vendor(live_dir=target_dir, rollback=vendor_publish_rollback)
            raise
        finally:
            if (
                vendor_publish_rollback is not None
                and vendor_publish_rollback.backup_dir is not None
            ):
                _discard_staged_vendor(vendor_publish_rollback.backup_dir)
    except Exception:
        _discard_staged_vendor(stage_dir)
        if wheel_stage_path.exists():
            wheel_stage_path.unlink()
        raise

    provider = PaidProviderSnapshot(
        provider_present=True,
        provider_id=PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=public_fallback_available,
        summary=(
            f"Installed {install_state['package_name']} "
            f"{install_state['package_version']} for paid preview."
        ),
        error_code=None,
    )
    return PaidActivateInstallResult(
        provider=provider,
        activation_status=STATUS_ACTIVE,
        install_state=install_state,
        public_fallback_available=public_fallback_available,
        license_id=synthetic_license_id(license_key),
        install_safety_advisory=install_safety_advisory,
    )


def clear_install_state(home: Path) -> None:
    path = install_state_path(home)
    if path.exists():
        path.unlink()


def invoke_console_free_builder_activation_handoff(
    *,
    activation_credential: str,
    home: Path,
    package_name: str,
    package_version: str,
    provider_id: str,
    vendor_dir: Path,
) -> InstalledProviderActivationHandoffResult:
    """Run the installed-provider handoff for Console free Builder preview."""

    # claim-check: allow valid=True is synthetic handoff input, not a license proof claim.
    validation = ActivationValidateResult(
        valid=True,  # claim-check: allow synthetic handoff input, not license proof
        customer_ref_fingerprint=None,
        plan=FREE_BUILDER_PLAN_FAMILY,
        license_status=None,
        subscription_status=None,
        period_end=None,
        public_fallback_available=True,
        error_code=None,
        provider_handoff_required=True,
    )
    return invoke_installed_provider_activation_handoff(
        license_key=activation_credential,
        validation=validation,
        home=home,
        package_name=package_name,
        package_version=package_version,
        provider_id=provider_id,
        vendor_dir=vendor_dir,
    )


def run_free_builder_install_flow(
    *,
    wheel_bytes: bytes,
    home: Path,
    activation_credential: str,
    expectations: FreeBuilderWheelExpectations | None = None,
    discover_paid_provider_fn: Callable[[], PaidProviderSnapshot] | None = None,
) -> FreeBuilderInstallResult:
    """Verify, install, and hand off a Console-delivered free Builder wheel."""

    from agentveil_mcp_proxy.console_project_status_client import (
        resolve_private_guardrails_status,
    )
    from agentveil_mcp_proxy.paid_activation import utc_now_iso
    from agentveil_mcp_proxy.paid_provider import discover_paid_provider

    metadata = verify_free_builder_wheel_artifact(
        wheel_bytes,
        expectations=expectations,
    )
    expected_package_name = metadata.package_name
    expected_package_version = metadata.package_version

    wheel_dir = home / "paid" / "cache"
    wheel_path = wheel_dir / f"{expected_package_name}-{expected_package_version}.whl"
    wheel_stage_path = wheel_dir / (
        f".staging-{expected_package_name}-{expected_package_version}-{secrets.token_hex(8)}.whl"
    )
    target_dir = _vendor_live_dir(
        home,
        package_name=expected_package_name,
        package_version=expected_package_version,
    )
    stage_dir = _vendor_stage_dir(
        home,
        package_name=expected_package_name,
        package_version=expected_package_version,
    )
    _assert_trusted_home_path(home, home / "paid")
    _assert_trusted_home_path(home, vendor_root(home))
    if target_dir.exists():
        _assert_non_symlink_vendor_path(home, target_dir)

    install_path = install_state_path(home)
    prior_install_bytes = install_path.read_bytes() if install_path.is_file() else None
    public_fallback_available = True
    discover = discover_paid_provider_fn or discover_paid_provider
    try:
        wheel_stage_path.parent.mkdir(parents=True, exist_ok=True)
        wheel_stage_path.write_bytes(wheel_bytes)
        os.chmod(wheel_stage_path, 0o600)

        install_wheel_to_vendor(
            home=home,
            wheel_path=wheel_stage_path,
            target_dir=stage_dir,
            expected_package_name=expected_package_name,
            expected_package_version=expected_package_version,
            require_empty_target=True,
        )
        handoff = invoke_console_free_builder_activation_handoff(
            activation_credential=activation_credential,
            home=home,
            package_name=expected_package_name,
            package_version=expected_package_version,
            provider_id=PROVIDER_ID,
            vendor_dir=stage_dir,
        )
        public_fallback_available = handoff.public_fallback_available

        install_state = {
            "status": STATUS_ACTIVE,
            "provider_id": PROVIDER_ID,
            "package_name": expected_package_name,
            "package_version": expected_package_version,
            "public_fallback_available": public_fallback_available,
            "error_code": None,
            "last_installed_at": utc_now_iso(),
            "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
            "install_safety_reason": None,
        }
        write_install_state(install_path, install_state)
        vendor_publish_rollback: _VendorPublishRollback | None = None
        try:
            vendor_publish_rollback = _publish_staged_vendor(
                home=home,
                stage_dir=stage_dir,
                live_dir=target_dir,
            )
            _commit_wheel_cache(wheel_stage_path=wheel_stage_path, wheel_path=wheel_path)
        except Exception as exc:
            _restore_install_state_bytes(install_path, prior_install_bytes)
            if vendor_publish_rollback is not None:
                _rollback_published_vendor(live_dir=target_dir, rollback=vendor_publish_rollback)
            raise FreeBuilderInstallError("install_publish_failed") from exc
        finally:
            if (
                vendor_publish_rollback is not None
                and vendor_publish_rollback.backup_dir is not None
            ):
                _discard_staged_vendor(vendor_publish_rollback.backup_dir)
    except PaidInstallError as exc:
        _discard_staged_vendor(stage_dir)
        if wheel_stage_path.exists():
            wheel_stage_path.unlink()
        _restore_install_state_bytes(install_path, prior_install_bytes)
        raise FreeBuilderInstallError(exc.args[0]) from exc
    except Exception:
        _discard_staged_vendor(stage_dir)
        if wheel_stage_path.exists():
            wheel_stage_path.unlink()
        _restore_install_state_bytes(install_path, prior_install_bytes)
        raise

    try:
        if resolve_private_guardrails_status(discover()) != "active":
            _restore_install_state_bytes(install_path, prior_install_bytes)
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            raise FreeBuilderInstallError("provider_not_active")
    except FreeBuilderInstallError:
        raise
    except Exception as exc:
        _restore_install_state_bytes(install_path, prior_install_bytes)
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        raise FreeBuilderInstallError("provider_not_active") from exc

    return FreeBuilderInstallResult(
        install_state=install_state,
        public_fallback_available=public_fallback_available,
    )
