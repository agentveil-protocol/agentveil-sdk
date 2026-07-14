"""Bounded paid package download, verification, and local install helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import urllib.error
import zipfile
import urllib.request
from typing import Any, Mapping, Protocol

from agentveil_mcp_proxy.evidence.proof import _fsync_parent_directory
from agentveil_mcp_proxy.paid_provider import (
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_ERROR,
    PaidProviderSnapshot,
)

INSTALL_FILENAME = "install.json"
PROVIDER_ID = "private_v1"
DEFAULT_PACKAGE_NAME = "agentveil-private-policy"
DEFAULT_PACKAGE_VERSION = "0.1.0"
DEFAULT_ARTIFACT_ID = "art_pkg_private_policy_001"
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


class PaidInstallError(ValueError):
    """Raised when paid install flow inputs or artifacts are invalid."""

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


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
    if _backend_client is not None:
        return _backend_client
    base_url = os.environ.get("AVP_PAID_API_BASE_URL", "").strip()
    if base_url:
        return HttpPaidBackendClient(base_url=base_url.rstrip("/"))
    return None


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
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PaidInstallError(f"{path} must contain a JSON object")
    assert_install_metadata_bounded(payload)
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
    wheel_path: Path,
    target_dir: Path,
    expected_package_name: str,
    expected_package_version: str,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
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
            members = archive.namelist()
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
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
    except zipfile.BadZipFile as exc:
        raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1) from exc


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
        return ActivationValidateResult(
            valid=bool(payload.get("valid")),
            customer_ref_fingerprint=_optional_str(payload.get("customer_ref_fingerprint")),
            plan=_optional_str(payload.get("plan")),
            license_status=_optional_str(payload.get("license_status")),
            subscription_status=_optional_str(payload.get("subscription_status")),
            period_end=_optional_str(payload.get("period_end")),
            public_fallback_available=bool(payload.get("public_fallback_available", True)),
            error_code=_optional_str(payload.get("error_code")),
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
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = wheel_dir / f"{expected_package_name}-{expected_package_version}.whl"
    wheel_path.write_bytes(wheel_bytes)
    os.chmod(wheel_path, 0o600)

    target_dir = vendor_root(home) / f"{expected_package_name}-{expected_package_version}"
    install_wheel_to_vendor(
        wheel_path=wheel_path,
        target_dir=target_dir,
        expected_package_name=expected_package_name,
        expected_package_version=expected_package_version,
    )

    from agentveil_mcp_proxy.paid_activation import synthetic_license_id, utc_now_iso

    install_state = {
        "status": STATUS_ACTIVE,
        "provider_id": PROVIDER_ID,
        "package_name": expected_package_name,
        "package_version": expected_package_version,
        "public_fallback_available": authorization.public_fallback_available,
        "error_code": None,
        "last_installed_at": utc_now_iso(),
        "install_safety_state": install_safety_state,
        "install_safety_reason": install_safety_reason,
    }
    write_install_state(install_state_path(home), install_state)

    provider = PaidProviderSnapshot(
        provider_present=True,
        provider_id=PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=authorization.public_fallback_available,
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
        public_fallback_available=authorization.public_fallback_available,
        license_id=synthetic_license_id(license_key),
        install_safety_advisory=install_safety_advisory,
    )


def clear_install_state(home: Path) -> None:
    path = install_state_path(home)
    if path.exists():
        path.unlink()
