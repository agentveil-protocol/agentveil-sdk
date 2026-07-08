"""Public bounded paid provider discovery bridge for the MCP proxy CLI.

Optional paid providers expose only a bounded public contract. This module does
not import private policy modules or activation APIs.

Discovery order for real CLI use:

1. In-process loader from :func:`set_paid_provider_loader` (tests/integration).
2. Installed optional providers registered under the
   ``agentveil_mcp_proxy.paid_providers`` packaging entry-point group.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Callable, Mapping, Protocol

PUBLIC_PAID_PROVIDER_CONTRACT_VERSION = "1"
PAID_PROVIDER_ENTRYPOINT_GROUP = "agentveil_mcp_proxy.paid_providers"

STATUS_ACTIVE = "active"
STATUS_MISSING = "missing"
STATUS_EXPIRED = "expired"
STATUS_WITHIN_GRACE = "within_grace"
STATUS_INVALID = "invalid"
STATUS_REVOKED = "revoked"
STATUS_DISABLED = "disabled"
STATUS_ERROR = "error"

ALLOWED_PROVIDER_STATUSES = frozenset(
    {
        STATUS_ACTIVE,
        STATUS_MISSING,
        STATUS_EXPIRED,
        STATUS_WITHIN_GRACE,
        STATUS_INVALID,
        STATUS_REVOKED,
        STATUS_DISABLED,
        STATUS_ERROR,
    }
)

BOUNDED_PROVIDER_KEYS = frozenset(
    {
        "provider_present",
        "provider_id",
        "provider_contract_version",
        "status",
        "private_provider_enabled",
        "public_fallback_available",
        "summary",
        "error_code",
    }
)

ERROR_CONTRACT_INCOMPATIBLE = "provider_contract_incompatible"
ERROR_PROVIDER_RESPONSE_INVALID = "provider_response_invalid"
ERROR_PROVIDER_RESPONSE_UNSAFE = "provider_response_unsafe"
ERROR_PROVIDER_STATUS_INVALID = "provider_status_invalid"

FORBIDDEN_PRIVATE_MARKERS = (
    "agentveil_private_policy",
    "private_policy_internal",
    "internal_provider_state",
)


class PaidActivationProvider(Protocol):
    """Bounded optional provider plugin surface for paid activation."""

    provider_id: str
    provider_contract_version: str

    def activate(self, *, license_key: str) -> Mapping[str, Any]:
        ...

    def status(self) -> Mapping[str, Any]:
        ...

    def deactivate(self) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class PaidProviderSnapshot:
    """Bounded public provider discovery/activation snapshot."""

    provider_present: bool
    provider_id: str | None = None
    provider_contract_version: str | None = None
    status: str = STATUS_MISSING
    private_provider_enabled: bool = False
    public_fallback_available: bool = True
    summary: str | None = None
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        sanitized = _finalize_provider_snapshot(
            provider_present=self.provider_present,
            provider_id=self.provider_id,
            provider_contract_version=self.provider_contract_version,
            status=self.status,
            private_provider_enabled=self.private_provider_enabled,
            public_fallback_available=self.public_fallback_available,
            summary=self.summary,
            error_code=self.error_code,
        )
        return {
            "provider_present": sanitized.provider_present,
            "provider_id": sanitized.provider_id,
            "provider_contract_version": sanitized.provider_contract_version,
            "status": sanitized.status,
            "private_provider_enabled": sanitized.private_provider_enabled,
            "public_fallback_available": sanitized.public_fallback_available,
            "summary": sanitized.summary,
            "error_code": sanitized.error_code,
        }


PaidProviderDiscovery = PaidProviderSnapshot

_provider_loader: Callable[[], PaidActivationProvider | None] | None = None


def set_paid_provider_loader(loader: Callable[[], PaidActivationProvider | None] | None) -> None:
    """Install or clear a test/runtime provider loader."""

    global _provider_loader
    _provider_loader = loader


def absent_provider_snapshot(*, error_code: str | None = None) -> PaidProviderSnapshot:
    return PaidProviderSnapshot(
        provider_present=False,
        status=STATUS_MISSING,
        public_fallback_available=True,
        error_code=error_code,
    )


def contains_private_provider_marker(text: str | None) -> bool:
    if text is None:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in FORBIDDEN_PRIVATE_MARKERS)


def assert_no_private_provider_markers(text: str) -> None:
    if contains_private_provider_marker(text):
        raise ValueError("output must not include private provider markers")


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _unsafe_provider_strings(*values: str | None) -> bool:
    return any(contains_private_provider_marker(value) for value in values)


def _finalize_provider_snapshot(
    *,
    provider_present: bool,
    provider_id: str | None = None,
    provider_contract_version: str | None = None,
    status: str = STATUS_MISSING,
    private_provider_enabled: bool = False,
    public_fallback_available: bool = True,
    summary: str | None = None,
    error_code: str | None = None,
) -> PaidProviderSnapshot:
    """Return a bounded snapshot, rejecting forbidden markers in any string field."""

    if _unsafe_provider_strings(provider_id, provider_contract_version, status, summary, error_code):
        return PaidProviderSnapshot(
            provider_present=provider_present,
            provider_id=None if contains_private_provider_marker(provider_id) else provider_id,
            provider_contract_version=(
                None if contains_private_provider_marker(provider_contract_version) else provider_contract_version
            ),
            status=STATUS_ERROR,
            private_provider_enabled=False,
            public_fallback_available=True,
            summary=None,
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )

    return PaidProviderSnapshot(
        provider_present=provider_present,
        provider_id=provider_id,
        provider_contract_version=provider_contract_version,
        status=status,
        private_provider_enabled=private_provider_enabled,
        public_fallback_available=public_fallback_available,
        summary=summary,
        error_code=error_code,
    )


def _provider_error_snapshot(
    *,
    provider_present: bool,
    provider_id: str | None = None,
    provider_contract_version: str | None = None,
    error_code: str,
) -> PaidProviderSnapshot:
    return _finalize_provider_snapshot(
        provider_present=provider_present,
        provider_id=provider_id,
        provider_contract_version=provider_contract_version,
        status=STATUS_ERROR,
        public_fallback_available=True,
        summary=None,
        error_code=error_code,
    )


def normalize_provider_response(raw: Mapping[str, Any]) -> PaidProviderSnapshot:
    """Map a provider payload onto the bounded public contract."""

    if not isinstance(raw, Mapping):
        return _provider_error_snapshot(
            provider_present=False,
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )

    extra = set(raw) - BOUNDED_PROVIDER_KEYS
    if extra:
        return _provider_error_snapshot(
            provider_present=bool(raw.get("provider_present", False)),
            provider_id=_optional_str(raw.get("provider_id")),
            provider_contract_version=_optional_str(raw.get("provider_contract_version")),
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )

    contract = _optional_str(raw.get("provider_contract_version"))
    provider_id = _optional_str(raw.get("provider_id"))
    summary = _optional_str(raw.get("summary"))
    error_code = _optional_str(raw.get("error_code"))
    status = _optional_str(raw.get("status")) or STATUS_MISSING

    if _unsafe_provider_strings(provider_id, contract, status, summary, error_code):
        return _finalize_provider_snapshot(
            provider_present=bool(raw.get("provider_present", False)),
            provider_id=provider_id,
            provider_contract_version=contract,
            status=status,
            summary=summary,
            error_code=error_code,
        )

    if contract != PUBLIC_PAID_PROVIDER_CONTRACT_VERSION:
        return _provider_error_snapshot(
            provider_present=bool(raw.get("provider_present", False)),
            provider_id=provider_id,
            provider_contract_version=contract,
            error_code=ERROR_CONTRACT_INCOMPATIBLE,
        )

    if status not in ALLOWED_PROVIDER_STATUSES:
        status = STATUS_ERROR
        error_code = error_code or ERROR_PROVIDER_STATUS_INVALID

    return _finalize_provider_snapshot(
        provider_present=bool(raw.get("provider_present", False)),
        provider_id=provider_id,
        provider_contract_version=contract,
        status=status,
        private_provider_enabled=bool(raw.get("private_provider_enabled", False)),
        public_fallback_available=bool(raw.get("public_fallback_available", True)),
        summary=summary,
        error_code=error_code,
    )


def _load_provider_from_entry_points() -> PaidActivationProvider | None:
    """Load the first compatible optional provider from packaging entry points."""

    try:
        discovered = entry_points(group=PAID_PROVIDER_ENTRYPOINT_GROUP)
    except TypeError:
        discovered = entry_points().get(PAID_PROVIDER_ENTRYPOINT_GROUP, ())
    for entry in discovered:
        try:
            loaded = entry.load()
            provider = loaded() if callable(loaded) else loaded
        except Exception:
            continue
        if provider is None:
            continue
        return provider
    return None


def _resolve_provider() -> PaidActivationProvider | None:
    if _provider_loader is not None:
        try:
            loaded = _provider_loader()
            if loaded is not None:
                return loaded
        except Exception:
            return None
    return _load_provider_from_entry_points()


def discover_paid_provider() -> PaidProviderSnapshot:
    """Discover an optional local paid provider using the bounded public contract."""

    provider = _resolve_provider()
    if provider is None:
        return absent_provider_snapshot()
    try:
        return normalize_provider_response(provider.status())
    except Exception:
        return _provider_error_snapshot(
            provider_present=True,
            provider_id=_optional_str(getattr(provider, "provider_id", None)),
            provider_contract_version=_optional_str(getattr(provider, "provider_contract_version", None)),
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )


def activate_with_paid_provider(*, license_key: str) -> PaidProviderSnapshot:
    """Ask an optional provider to activate and return a bounded snapshot."""

    provider = _resolve_provider()
    if provider is None:
        return absent_provider_snapshot(error_code="provider_absent")
    try:
        return normalize_provider_response(provider.activate(license_key=license_key))
    except Exception:
        return _provider_error_snapshot(
            provider_present=True,
            provider_id=_optional_str(getattr(provider, "provider_id", None)),
            provider_contract_version=_optional_str(getattr(provider, "provider_contract_version", None)),
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )


def deactivate_with_paid_provider() -> PaidProviderSnapshot:
    """Ask an optional provider to deactivate and return a bounded snapshot."""

    provider = _resolve_provider()
    if provider is None:
        return absent_provider_snapshot()
    deactivate = getattr(provider, "deactivate", None)
    if not callable(deactivate):
        try:
            return normalize_provider_response(provider.status())
        except Exception:
            return _provider_error_snapshot(
                provider_present=True,
                provider_id=_optional_str(getattr(provider, "provider_id", None)),
                provider_contract_version=_optional_str(getattr(provider, "provider_contract_version", None)),
                error_code=ERROR_PROVIDER_RESPONSE_INVALID,
            )
    try:
        return normalize_provider_response(deactivate())
    except Exception:
        return _provider_error_snapshot(
            provider_present=True,
            provider_id=_optional_str(getattr(provider, "provider_id", None)),
            provider_contract_version=_optional_str(getattr(provider, "provider_contract_version", None)),
            error_code=ERROR_PROVIDER_RESPONSE_INVALID,
        )
