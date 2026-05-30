"""Headless approval policy for non-interactive MCP Proxy runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.classification import ClassifiedToolCall


HEADLESS_POLICY_SCHEMA_VERSION = 1
_HIGH_RISK = {"destructive", "production", "financial"}


class HeadlessPolicyError(ValueError):
    """Raised when a headless approval policy is invalid."""


@dataclass(frozen=True)
class HeadlessPreApproval:
    """One bounded headless pre-approval rule."""

    server: str
    tool: str
    risk_class: str
    expires_at: int
    resource_hash: str | None = None
    resource: str | None = None
    environment: str = "mcp_proxy"
    max_payload_hash: str | None = None
    allow_narrow_match: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HeadlessPreApproval":
        allowed = {
            "server",
            "tool",
            "resource_hash",
            "resource",
            "environment",
            "risk_class",
            "max_payload_hash",
            "expires_at",
            "allow_narrow_match",
        }
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise HeadlessPolicyError(f"headless pre-approval has unknown field(s): {', '.join(unknown)}")
        server = _required_str(data.get("server"), "server")
        tool = _required_str(data.get("tool"), "tool")
        risk_class = _required_str(data.get("risk_class"), "risk_class")
        expires_at = _parse_iso_timestamp(_required_str(data.get("expires_at"), "expires_at"))
        resource_hash = _optional_str(data.get("resource_hash"), "resource_hash")
        if resource_hash is not None:
            resource_hash = _require_sha256_hash(resource_hash, "resource_hash")
        resource = _optional_str(data.get("resource"), "resource")
        max_payload_hash = _optional_str(data.get("max_payload_hash"), "max_payload_hash")
        if max_payload_hash is not None:
            max_payload_hash = _require_sha256_hash(max_payload_hash, "max_payload_hash")
        allow_narrow_match = data.get("allow_narrow_match", False)
        if not isinstance(allow_narrow_match, bool):
            raise HeadlessPolicyError("allow_narrow_match must be a boolean")
        if risk_class in _HIGH_RISK and resource_hash is None and resource is None:
            raise HeadlessPolicyError(
                "destructive, production, and financial pre-approvals require resource or resource_hash"
            )
        if risk_class in _HIGH_RISK and max_payload_hash is None and not allow_narrow_match:
            raise HeadlessPolicyError(
                "destructive, production, and financial pre-approvals require max_payload_hash"
            )
        return cls(
            server=server,
            tool=tool,
            risk_class=risk_class,
            expires_at=expires_at,
            resource_hash=resource_hash,
            resource=resource,
            environment=_optional_str(data.get("environment"), "environment") or "mcp_proxy",
            max_payload_hash=max_payload_hash,
            allow_narrow_match=allow_narrow_match,
        )

    def matches(
        self,
        classification: ClassifiedToolCall,
        *,
        environment: str,
        now_timestamp: int,
    ) -> bool:
        """Return whether this bounded rule approves the classified call."""

        if self.expires_at <= now_timestamp:
            return False
        if self.server != classification.server or self.tool != classification.tool:
            return False
        if self.environment != environment:
            return False
        if self.risk_class != classification.risk_class.value:
            return False
        if self.risk_class in _HIGH_RISK and self.resource_hash is None and self.resource is None:
            return False
        if self.resource_hash is not None and self.resource_hash != classification.resource_hash:
            return False
        if self.resource is not None and self.resource != classification.resource_plain:
            return False
        if self.max_payload_hash is not None:
            return self.max_payload_hash == classification.payload_hash
        return self.allow_narrow_match


@dataclass(frozen=True)
class HeadlessPolicy:
    """Versioned headless approval policy."""

    pre_approvals: tuple[HeadlessPreApproval, ...]
    headless_policy_schema_version: int = HEADLESS_POLICY_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HeadlessPolicy":
        allowed = {"headless_policy_schema_version", "pre_approvals"}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise HeadlessPolicyError(f"headless policy has unknown field(s): {', '.join(unknown)}")
        version = data.get("headless_policy_schema_version")
        if version != HEADLESS_POLICY_SCHEMA_VERSION:
            raise HeadlessPolicyError("headless_policy_schema_version must be 1")
        entries = data.get("pre_approvals", [])
        if not isinstance(entries, list):
            raise HeadlessPolicyError("pre_approvals must be a list")
        return cls(
            pre_approvals=tuple(HeadlessPreApproval.from_dict(entry) for entry in entries),
        )

    @classmethod
    def from_file(cls, path: Path) -> "HeadlessPolicy":
        """Load a JSON headless policy file."""

        expanded = path.expanduser()
        _require_owner_only_file(expanded)
        try:
            data = json.loads(expanded.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HeadlessPolicyError(f"headless policy JSON unavailable: {path}") from exc
        if not isinstance(data, Mapping):
            raise HeadlessPolicyError("headless policy must be a JSON object")
        return cls.from_dict(data)

    def match(
        self,
        classification: ClassifiedToolCall,
        *,
        environment: str = "mcp_proxy",
        now_timestamp: int | None = None,
    ) -> HeadlessPreApproval | None:
        """Return the first matching pre-approval rule, if any."""

        now = int(datetime.now(timezone.utc).timestamp()) if now_timestamp is None else now_timestamp
        for rule in self.pre_approvals:
            if rule.matches(classification, environment=environment, now_timestamp=now):
                return rule
        return None


def _required_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise HeadlessPolicyError(f"{field} must be a non-empty string")
    return value


def _optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise HeadlessPolicyError(f"{field} must be a non-empty string")
    return value


def _require_sha256_hash(value: str, field: str) -> str:
    prefix = "sha256:"
    digest = value[len(prefix):] if value.startswith(prefix) else ""
    digest = digest.lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise HeadlessPolicyError(f"{field} must be a sha256: hash")
    return prefix + digest


def _require_owner_only_file(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise HeadlessPolicyError(f"headless policy JSON unavailable: {path}") from exc
    if mode & 0o077:
        raise HeadlessPolicyError(
            "headless policy file permissions must be owner-only (0o600 or 0o400)"
        )


def _parse_iso_timestamp(value: str) -> int:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HeadlessPolicyError("expires_at must be YYYY-MM-DDTHH:MM:SSZ") from exc
    return int(parsed.timestamp())


__all__ = [
    "HEADLESS_POLICY_SCHEMA_VERSION",
    "HeadlessPolicy",
    "HeadlessPolicyError",
    "HeadlessPreApproval",
]
