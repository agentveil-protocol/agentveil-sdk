"""Least Agency role presets for MCP proxy init without hand-edited JSON."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping

from dataclasses import replace

from agentveil_mcp_proxy.policy import ProxyConfig, RoleAuthorityConfig, RoleAuthorityMode


class RolePresetError(ValueError):
    """Raised when a role preset name or env override is invalid."""


ROLE_PRESET_NAMES: tuple[str, ...] = ("reviewer", "readonly", "implementer", "build")
ROLE_PRESET_ENV_VAR = "AVP_PROXY_ROLE"
SAFE_AUTOPILOT_SETUP_PROFILE = "safe_autopilot"
PRODUCT_ROUTE_SETUP_PROFILE = "product_route"
ADVANCED_ROLE_SETUP_PROFILE = "advanced_role"
# claim-check: allow product label; behavior is bounded by first-run tests.
SAFE_AUTOPILOT_USER_LABEL = "Safe Autopilot"
PRODUCT_ROUTE_USER_LABEL = "Product route"
DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET = "reviewer"


@dataclass(frozen=True)
class RolePreset:
    """One operator-facing role preset mapped to role_authority config."""

    name: str
    role: str
    authority: str

    def to_role_authority_dict(self) -> dict[str, str]:
        return {
            "mode": RoleAuthorityMode.ENFORCE.value,
            "role": self.role,
            "authority": self.authority,
        }

    def to_role_authority_config(self) -> RoleAuthorityConfig:
        return RoleAuthorityConfig.from_dict(self.to_role_authority_dict())


_ROLE_PRESETS: dict[str, RolePreset] = {
    "reviewer": RolePreset(
        name="reviewer",
        role="reviewer",
        authority="review_only",
    ),
    "readonly": RolePreset(
        name="readonly",
        role="readonly",
        authority="read_only",
    ),
    "implementer": RolePreset(
        name="implementer",
        role="implementer",
        authority="implement",
    ),
    "build": RolePreset(
        name="build",
        role="build",
        authority="build",
    ),
}


def normalize_role_preset_name(name: str) -> str:
    """Return a validated preset name."""

    trimmed = name.strip().lower()
    if trimmed not in _ROLE_PRESETS:
        supported = ", ".join(ROLE_PRESET_NAMES)
        raise RolePresetError(f"unsupported role preset {name!r}; expected one of: {supported}")
    return trimmed


def resolve_role_preset(name: str) -> RolePreset:
    """Return the preset definition for ``name``."""

    return _ROLE_PRESETS[normalize_role_preset_name(name)]


def role_authority_dict_for_preset(name: str) -> dict[str, str]:
    """Return the ``role_authority`` object for one preset name."""

    return resolve_role_preset(name).to_role_authority_dict()


def apply_role_preset_to_config_payload(
    payload: Mapping[str, object],
    *,
    preset_name: str,
) -> dict[str, object]:
    """Attach preset ``role_authority`` and metadata to a proxy config payload."""

    data = dict(payload)
    preset = resolve_role_preset(preset_name)
    data["role_authority"] = preset.to_role_authority_dict()
    data["role_preset"] = preset.name
    return data


def apply_env_role_override_to_config(config: ProxyConfig) -> ProxyConfig:
    """Override role_authority when ``AVP_PROXY_ROLE`` is set."""

    env_value = os.environ.get(ROLE_PRESET_ENV_VAR, "").strip()
    if not env_value:
        return config
    preset = resolve_role_preset(env_value)
    return replace(
        config,
        role_authority=preset.to_role_authority_config(),
        role_preset=preset.name,
    )


def resolve_init_role_preset(role: str | None) -> tuple[str, bool]:
    """Return preset name and whether the operator explicitly chose a role."""

    if role is None or not str(role).strip():
        return DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET, False
    return normalize_role_preset_name(role), True


def init_setup_profile(*, explicit_role: bool) -> str:
    if explicit_role:
        return "advanced_role"
    return SAFE_AUTOPILOT_SETUP_PROFILE


def user_facing_setup_label(*, role_preset: str, explicit_role: bool, setup_profile: str | None = None) -> str:
    if setup_profile == PRODUCT_ROUTE_SETUP_PROFILE:
        return PRODUCT_ROUTE_USER_LABEL
    if not explicit_role:
        return SAFE_AUTOPILOT_USER_LABEL
    return f"Advanced role preset: {role_preset}"


__all__ = [
    "ADVANCED_ROLE_SETUP_PROFILE",
    "DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET",
    "PRODUCT_ROUTE_SETUP_PROFILE",
    "PRODUCT_ROUTE_USER_LABEL",
    "ROLE_PRESET_ENV_VAR",
    "ROLE_PRESET_NAMES",
    "SAFE_AUTOPILOT_SETUP_PROFILE",
    "SAFE_AUTOPILOT_USER_LABEL",
    "RolePreset",
    "RolePresetError",
    "apply_env_role_override_to_config",
    "apply_role_preset_to_config_payload",
    "init_setup_profile",
    "normalize_role_preset_name",
    "resolve_init_role_preset",
    "resolve_role_preset",
    "role_authority_dict_for_preset",
    "user_facing_setup_label",
]
