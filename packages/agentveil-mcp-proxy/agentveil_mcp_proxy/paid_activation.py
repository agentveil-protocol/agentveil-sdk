"""Public bounded paid activation CLI for agentveil-mcp-proxy."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, TextIO

from agentveil_mcp_proxy.evidence.proof import _fsync_parent_directory
from agentveil_mcp_proxy.paid_install import (
    PaidInstallError,
    clear_install_state,
    install_state_path,
    load_install_state,
    resolve_paid_backend_client,
    run_paid_activate_install_flow,
)
from agentveil_mcp_proxy.paid_provider import (
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_INVALID,
    STATUS_MISSING,
    STATUS_REVOKED,
    PaidProviderSnapshot,
    absent_provider_snapshot,
    activate_with_paid_provider,
    deactivate_with_paid_provider,
    discover_paid_provider,
)

ACTIVATION_FILENAME = "activation.json"
BOUNDED_ACTIVATION_KEYS = frozenset(
    {
        "status",
        "provider_present",
        "license_id",
        "customer_id",
        "expires_at",
        "last_checked_at",
        "public_fallback_available",
        "error_code",
    }
)
# Terminal activation statuses that must not be promoted back to active by
# install.json alone (private Runtime Gate Core-fallback contract).
TERMINAL_INACTIVE_ACTIVATION_STATUSES = frozenset(
    {
        STATUS_EXPIRED,
        STATUS_REVOKED,
        STATUS_DISABLED,
        STATUS_INVALID,
        STATUS_ERROR,
    }
)
ERROR_PROVIDER_ABSENT = "provider_absent"
ERROR_ACTIVATION_STATE_UNREADABLE = "activation_state_unreadable"
FORBIDDEN_OVERCLAIM_MARKERS = (
    "activation succeeded",
    "paid activation successful",
    "license activated",
    "paid provider verified",
    "paid activation finalized",
)


class PaidActivationError(ValueError):
    """Raised when paid activation inputs or persisted metadata are invalid."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


def default_home() -> Path:
    return Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()


def activation_path(home: Path | None = None) -> Path:
    root = (home or default_home()).expanduser()
    return root / "paid" / ACTIVATION_FILENAME


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def synthetic_license_id(license_key: str) -> str:
    digest = hashlib.sha256(license_key.encode("utf-8")).hexdigest()[:16]
    return f"lic_{digest}"


def assert_activation_metadata_bounded(data: Mapping[str, Any]) -> None:
    extra = set(data) - BOUNDED_ACTIVATION_KEYS
    if extra:
        raise PaidActivationError(f"activation metadata contains unexpected keys: {sorted(extra)}")
    if not isinstance(data.get("status"), str):
        raise PaidActivationError("activation metadata requires string status")
    if not isinstance(data.get("provider_present"), bool):
        raise PaidActivationError("activation metadata requires bool provider_present")
    if not isinstance(data.get("public_fallback_available"), bool):
        raise PaidActivationError("activation metadata requires bool public_fallback_available")


def assert_paid_human_output_no_overclaim(text: str) -> None:
    lowered = text.lower()
    for marker in FORBIDDEN_OVERCLAIM_MARKERS:
        if marker in lowered:
            raise PaidActivationError(f"paid CLI output must not claim {marker!r}")


def assert_license_key_redacted(*, text: str, license_key: str) -> None:
    if license_key and license_key in text:
        raise PaidActivationError("raw license key leaked into CLI output")


def load_activation_state(path: Path) -> dict[str, Any] | None:
    """Load bounded activation.json.

    Missing file → ``None``. Unreadable / malformed / unexpected keys → bounded
    ``error`` Core-fallback state (no traceback, no host path in the result).
    """

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _unreadable_activation_state()
    if not isinstance(payload, dict):
        return _unreadable_activation_state()
    try:
        assert_activation_metadata_bounded(payload)
    except PaidActivationError:
        return _unreadable_activation_state()
    return dict(payload)


def _unreadable_activation_state(*, checked_at: str | None = None) -> dict[str, Any]:
    return {
        "status": STATUS_ERROR,
        "provider_present": False,
        "license_id": None,
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": checked_at or utc_now_iso(),
        "public_fallback_available": True,
        "error_code": ERROR_ACTIVATION_STATE_UNREADABLE,
    }

def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError as exc:
        raise PaidActivationError(f"cannot set private directory permissions for {path}") from exc


def write_activation_state(path: Path, data: Mapping[str, Any]) -> None:
    assert_activation_metadata_bounded(data)
    _mkdir_private(path.parent)
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


def inactive_activation_state(*, checked_at: str | None = None) -> dict[str, Any]:
    return {
        "status": STATUS_MISSING,
        "provider_present": False,
        "license_id": None,
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": checked_at or utc_now_iso(),
        "public_fallback_available": True,
        "error_code": None,
    }


def _provider_absent_activation_state(*, license_key: str) -> dict[str, Any]:
    return _activation_state_from_provider(
        absent_provider_snapshot(error_code=ERROR_PROVIDER_ABSENT),
        license_key=license_key,
    )


def _activation_state_from_provider(
    provider: PaidProviderSnapshot,
    *,
    license_key: str | None = None,
    checked_at: str | None = None,
) -> dict[str, Any]:
    license_id = synthetic_license_id(license_key) if license_key else None
    if provider.status != STATUS_ACTIVE:
        license_id = license_id if license_key else None
    return {
        "status": provider.status,
        "provider_present": provider.provider_present,
        "license_id": license_id,
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": checked_at or utc_now_iso(),
        "public_fallback_available": provider.public_fallback_available,
        "error_code": provider.error_code,
    }


def _activation_state_from_install(
    *,
    install_state: Mapping[str, Any],
    license_id: str,
    checked_at: str | None = None,
) -> dict[str, Any]:
    return {
        "status": install_state.get("status", STATUS_ACTIVE),
        "provider_present": True,
        "license_id": license_id,
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": checked_at or utc_now_iso(),
        "public_fallback_available": bool(install_state.get("public_fallback_available", True)),
        "error_code": install_state.get("error_code"),
    }


def _paid_activation_available(provider: PaidProviderSnapshot) -> bool:
    return provider.provider_present and provider.status == STATUS_ACTIVE and provider.error_code is None


def map_public_paid_enablement(
    activation: Mapping[str, Any] | None,
    install: Mapping[str, Any] | None,
) -> tuple[str, bool]:
    """Map durable public files to enablement (private B1-compatible).

    Returns ``(entitlement_status, provider_enabled)``. Private Runtime Gate
    enables paid only when both activation and install are ``active``.
    """

    activation_status = str((activation or {}).get("status") or STATUS_MISSING)
    install_status = str((install or {}).get("status") or STATUS_MISSING)

    if activation_status == STATUS_REVOKED or install_status == STATUS_REVOKED:
        return STATUS_REVOKED, False
    if activation_status == STATUS_EXPIRED or install_status == STATUS_EXPIRED:
        return STATUS_EXPIRED, False
    if activation_status == STATUS_DISABLED or install_status == STATUS_DISABLED:
        return STATUS_DISABLED, False
    if activation_status == "within_grace":
        return "within_grace", install_status == STATUS_ACTIVE
    if activation_status == STATUS_ACTIVE and install_status == STATUS_ACTIVE:
        return STATUS_ACTIVE, True
    if activation_status in {STATUS_INVALID, STATUS_ERROR} or install_status in {
        STATUS_INVALID,
        STATUS_ERROR,
    }:
        return STATUS_ERROR, False
    return STATUS_MISSING, False


def public_install_hints(install: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Bounded package/provider hints private Runtime Gate reads from install.json."""

    if install is None:
        return None
    package_name = install.get("package_name")
    package_version = install.get("package_version")
    provider_id = install.get("provider_id")
    if not isinstance(package_name, str) or not package_name:
        return None
    hints: dict[str, Any] = {
        "package_name": package_name,
        "package_version": package_version if isinstance(package_version, str) else "",
    }
    if isinstance(provider_id, str) and provider_id:
        hints["provider_id"] = provider_id
    return hints


def _envelope(
    *,
    action: str,
    activation: Mapping[str, Any],
    provider: PaidProviderSnapshot,
    install_state: Mapping[str, Any] | None = None,
    install_safety_advisory: str | None = None,
) -> dict[str, Any]:
    payload = {
        "ok": True,
        "action": action,
        "paid_provider_present": provider.provider_present,
        "paid_activation_available": _paid_activation_available(provider),
        "public_fallback_active": bool(activation.get("public_fallback_available")),
        "provider": provider.to_dict(),
        "activation": dict(activation),
    }
    if install_state is not None:
        payload["install"] = {
            "provider_id": install_state.get("provider_id"),
            "package_name": install_state.get("package_name"),
            "package_version": install_state.get("package_version"),
            "status": install_state.get("status"),
            "public_fallback_available": install_state.get("public_fallback_available"),
            "error_code": install_state.get("error_code"),
            "last_installed_at": install_state.get("last_installed_at"),
            "install_safety_state": install_state.get("install_safety_state"),
            "install_safety_reason": install_state.get("install_safety_reason"),
        }
    if install_safety_advisory:
        payload["install_safety_advisory"] = install_safety_advisory
    return payload


def format_paid_human_output(payload: Mapping[str, Any]) -> str:
    activation = payload["activation"]
    provider = payload.get("provider") or {}
    install = payload.get("install") or {}
    if activation.get("status") == STATUS_ACTIVE and install:
        fallback = "available" if activation.get("public_fallback_available") else "unavailable"
        lines = [
            f"Status: {activation['status']}",
            f"Provider: {install.get('provider_id') or provider.get('provider_id') or 'private_v1'}",
            f"Installed package: {install.get('package_name')}",
            f"Installed version: {install.get('package_version')}",
            f"Public fallback: {fallback}",
        ]
        advisory = payload.get("install_safety_advisory")
        if advisory:
            lines.insert(0, str(advisory))
        return "\n".join(lines)

    lines = [
        f"Paid provider: {'present' if payload['paid_provider_present'] else 'absent'}",
        f"Public fallback: {'active' if payload['public_fallback_active'] else 'inactive'}",
    ]
    if payload["paid_activation_available"]:
        lines.append("Paid activation: available")
    else:
        lines.append("Paid activation: unavailable (no paid provider installed)")
    lines.append(f"Status: {activation['status']}")
    summary = provider.get("summary")
    if summary:
        lines.append(f"Provider summary: {summary}")
    license_id = activation.get("license_id")
    if license_id:
        lines.append(f"License reference: {license_id}")
    error_code = activation.get("error_code")
    if error_code:
        lines.append(f"Error code: {error_code}")
    checked_at = activation.get("last_checked_at")
    if checked_at:
        lines.append(f"Last checked: {checked_at}")
    return "\n".join(lines)


def resolve_paid_activate_license_key(
    *,
    license_key: str | None,
    license_key_stdin: bool,
    stdin: TextIO | None = None,
) -> str:
    """Resolve a license key from argv or stdin without accepting both sources."""

    if license_key_stdin and license_key is not None:
        raise PaidActivationError(
            "pass license key via positional argument or --license-key-stdin, not both",
        )
    if license_key_stdin:
        stream = stdin if stdin is not None else sys.stdin
        raw = stream.read()
        value = raw.strip()
        if not value:
            raise PaidActivationError("license key read from stdin must not be empty")
        return value
    if license_key is None:
        raise PaidActivationError(
            "license key is required (positional argument or --license-key-stdin)",
        )
    return license_key


def build_paid_activate_payload(*, license_key: str, home: Path | None) -> dict[str, Any]:
    if not license_key or not license_key.strip():
        raise PaidActivationError("license key must not be empty")
    resolved_home = (home or default_home()).expanduser()
    backend = resolve_paid_backend_client()
    if backend is not None:
        try:
            result = run_paid_activate_install_flow(
                license_key=license_key.strip(),
                home=resolved_home,
                client=backend,
            )
        except PaidInstallError as exc:
            raise PaidActivationError(str(exc), exit_code=exc.exit_code) from exc
        activation = _activation_state_from_install(
            install_state=result.install_state,
            license_id=result.license_id,
        )
        write_activation_state(activation_path(resolved_home), activation)
        return _envelope(
            action="activate",
            activation=activation,
            provider=result.provider,
            install_state=result.install_state,
            install_safety_advisory=result.install_safety_advisory,
        )

    provider = activate_with_paid_provider(license_key=license_key.strip())
    if not provider.provider_present:
        activation = _provider_absent_activation_state(license_key=license_key.strip())
    else:
        activation = _activation_state_from_provider(provider, license_key=license_key.strip())
    write_activation_state(activation_path(resolved_home), activation)
    return _envelope(action="activate", activation=activation, provider=provider)


def build_paid_status_payload(*, home: Path | None) -> dict[str, Any]:
    resolved_home = (home or default_home()).expanduser()
    install_state = load_install_state(install_state_path(resolved_home))
    provider = discover_paid_provider()
    path = activation_path(resolved_home)
    activation = load_activation_state(path)
    checked_at = utc_now_iso()

    if install_state and install_state.get("status") == STATUS_ACTIVE:
        existing_status = str((activation or {}).get("status") or STATUS_MISSING)
        if existing_status in TERMINAL_INACTIVE_ACTIVATION_STATUSES:
            # Keep terminal activation for private Core-fallback compatibility.
            preserved = dict(activation or inactive_activation_state(checked_at=checked_at))
            preserved["last_checked_at"] = checked_at
            preserved["public_fallback_available"] = True
            if preserved.get("provider_present") is not False:
                preserved["provider_present"] = bool(preserved.get("provider_present"))
            write_activation_state(path, preserved)
            provider = PaidProviderSnapshot(
                provider_present=True,
                provider_id=install_state.get("provider_id"),
                provider_contract_version="1",
                status=existing_status,
                private_provider_enabled=False,
                public_fallback_available=True,
                summary=f"Paid state {existing_status}; public Core fallback active.",
                error_code=preserved.get("error_code") or existing_status,
            )
            return _envelope(
                action="status",
                activation=preserved,
                provider=provider,
                install_state=install_state,
            )

        provider = PaidProviderSnapshot(
            provider_present=True,
            provider_id=install_state.get("provider_id"),
            provider_contract_version="1",
            status=STATUS_ACTIVE,
            private_provider_enabled=True,
            public_fallback_available=bool(install_state.get("public_fallback_available", True)),
            summary=(
                f"Installed {install_state.get('package_name')} "
                f"{install_state.get('package_version')}."
            ),
            error_code=install_state.get("error_code"),
        )
        activation = _activation_state_from_install(
            install_state=install_state,
            license_id=(activation or {}).get("license_id") or synthetic_license_id("status-only"),
            checked_at=checked_at,
        )
        write_activation_state(path, activation)
        return _envelope(
            action="status",
            activation=activation,
            provider=provider,
            install_state=install_state,
        )

    if activation is None:
        activation = _activation_state_from_provider(provider)
    else:
        activation = dict(activation)
        activation["last_checked_at"] = checked_at
        write_activation_state(path, activation)
    return _envelope(
        action="status",
        activation=activation,
        provider=provider,
        install_state=install_state,
    )


def build_paid_deactivate_payload(*, home: Path | None) -> dict[str, Any]:
    resolved_home = (home or default_home()).expanduser()
    provider = deactivate_with_paid_provider()
    activation = inactive_activation_state()
    write_activation_state(activation_path(resolved_home), activation)
    clear_install_state(resolved_home)
    return _envelope(action="deactivate", activation=activation, provider=provider)


def _emit_paid_payload(payload: Mapping[str, Any], *, output_json: bool, out: TextIO) -> None:
    if output_json:
        from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe

        assert_proxy_cli_json_is_privacy_safe(payload)
        print(json.dumps(dict(payload), sort_keys=True), file=out)
        return
    text = format_paid_human_output(payload)
    assert_paid_human_output_no_overclaim(text)
    print(text, file=out)


def run_paid_activate_cli(
    *,
    license_key: str | None,
    license_key_stdin: bool = False,
    home: Path | None,
    output_json: bool = False,
    out: TextIO | None = None,
    stdin: TextIO | None = None,
) -> int:
    resolved = resolve_paid_activate_license_key(
        license_key=license_key,
        license_key_stdin=license_key_stdin,
        stdin=stdin,
    )
    payload = build_paid_activate_payload(license_key=resolved, home=home)
    _emit_paid_payload(payload, output_json=output_json, out=out or sys.stdout)
    # Offline / provider-absent path is an explicit unavailable result, not
    # success. Backend install success returns paid_activation_available=True.
    if not payload.get("paid_activation_available"):
        return 1
    return 0


def run_paid_status_cli(
    *,
    home: Path | None,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    payload = build_paid_status_payload(home=home)
    _emit_paid_payload(payload, output_json=output_json, out=out or sys.stdout)
    return 0


def run_paid_deactivate_cli(
    *,
    home: Path | None,
    output_json: bool = False,
    out: TextIO | None = None,
) -> int:
    payload = build_paid_deactivate_payload(home=home)
    _emit_paid_payload(payload, output_json=output_json, out=out or sys.stdout)
    return 0
