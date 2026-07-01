"""Agent runtime profile definitions for the public launcher.

Runtime profiles are thin adapters: they describe how to start a managed child
process under AgentVeil-controlled MCP routing. Policy, approval, redirect, and
proof remain in the shared MCP proxy backend — not here.
"""

from __future__ import annotations

from dataclasses import dataclass


class RuntimeProfileError(ValueError):
    """Bounded error for invalid or unsupported runtime profile ids."""


@dataclass(frozen=True)
class RuntimeProfileSpec:
    """One supported managed runtime profile."""

    profile_id: str
    display_name: str
    default_status: str  # configured | verify_only
    child_detach: bool
    requires_child_command: bool

    def summary(self) -> dict[str, str | bool]:
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "default_status": self.default_status,
            "child_detach": self.child_detach,
        }


GENERIC_PROCESS_PROFILE = RuntimeProfileSpec(
    profile_id="generic-process",
    display_name="Generic local process",
    default_status="configured",
    child_detach=True,
    requires_child_command=True,
)

_KNOWN_PROFILES: dict[str, RuntimeProfileSpec] = {
    GENERIC_PROCESS_PROFILE.profile_id: GENERIC_PROCESS_PROFILE,
}


def known_profile_ids() -> tuple[str, ...]:
    return tuple(_KNOWN_PROFILES.keys())


def resolve_runtime_profile(profile_id: str) -> RuntimeProfileSpec:
    """Return a validated profile spec or raise RuntimeProfileError."""

    trimmed = str(profile_id or "").strip()
    if not trimmed:
        raise RuntimeProfileError("profile id required")
    spec = _KNOWN_PROFILES.get(trimmed)
    if spec is None:
        raise RuntimeProfileError(
            f"unsupported runtime profile {trimmed!r}; "
            f"known profiles: {', '.join(known_profile_ids())}"
        )
    return spec


__all__ = [
    "GENERIC_PROCESS_PROFILE",
    "RuntimeProfileError",
    "RuntimeProfileSpec",
    "known_profile_ids",
    "resolve_runtime_profile",
]
