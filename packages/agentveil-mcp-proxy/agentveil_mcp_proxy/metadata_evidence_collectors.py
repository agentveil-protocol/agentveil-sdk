"""Bounded metadata-influence evidence collectors for install/clone tools.

Scans locally available MCP tool-argument surfaces for install/clone influence
signals and emits only private-schema evidence slots. Raw README text, tool
output, paths, URLs, package names, and secrets are excluded from returned
slots; regression coverage lives in test_mcp_proxy_metadata_evidence_collectors.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from agentveil.runtime_install_clone import (
    EVIDENCE_CHANNEL_FILE_METADATA,
    EVIDENCE_CHANNEL_README,
    EVIDENCE_CHANNEL_TOOL_OUTPUT,
    validate_metadata_evidence_slot,
)
from agentveil.exceptions import AVPValidationError

COLLECTOR_ID = "mcp_proxy_metadata_v1"

_README_SURFACE_KEYS = (
    "readme",
    "readme_text",
    "readme_excerpt",
    "metadata_readme",
)
_TOOL_OUTPUT_SURFACE_KEYS = (
    "tool_output",
    "prior_tool_output",
    "command_output",
    "suggested_command",
)
_FILE_METADATA_KIND_KEYS = (
    "file_kind",
    "manifest_kind",
    "lockfile_kind",
    "config_kind",
)
_FILE_BASENAME_KEYS = (
    "file_name",
    "manifest_name",
    "lockfile_name",
    "config_name",
)

_README_SIGNAL_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("install_hint", "kw_install_hint", re.compile(
        r"\b(?:pip|npm|yarn|pnpm|uv)\s+install\b|\bto install\b|\binstall via\b",
        re.IGNORECASE,
    )),
    ("clone_hint", "kw_clone_hint", re.compile(
        r"\bgit\s+clone\b|\bclone the (?:repo|repository)\b",
        re.IGNORECASE,
    )),
    ("package_name_hint", "kw_package_name_hint", re.compile(
        r"\bpackage name\b|\bpypi\b|\bnpm package\b",
        re.IGNORECASE,
    )),
    ("dependency_hint", "kw_dependency_hint", re.compile(
        r"\bdependenc(?:y|ies)\b|\brequirements?\b",
        re.IGNORECASE,
    )),
)

_TOOL_OUTPUT_SIGNAL_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("install_command", "kw_install_command", re.compile(
        r"\b(?:pip|npm|yarn|pnpm|uv)\s+install\b",
        re.IGNORECASE,
    )),
    ("clone_command", "kw_clone_command", re.compile(
        r"\bgit\s+clone\b",
        re.IGNORECASE,
    )),
    ("package_reference", "kw_package_reference", re.compile(
        r"\b(?:successfully installed|requirement already satisfied|from\s+\w+\s+import)\b",
        re.IGNORECASE,
    )),
    ("repo_reference", "kw_repo_reference", re.compile(
        r"\b(?:repository|repo)\s+(?:url|clone|at)\b|\bcloned into\b",
        re.IGNORECASE,
    )),
)

_FILE_KIND_TO_SIGNAL: Mapping[str, tuple[str, str]] = {
    "requirements": ("manifest_install_target", "kind_requirements"),
    "manifest": ("manifest_install_target", "kind_manifest"),
    "pyproject": ("manifest_install_target", "kind_pyproject"),
    "setup_cfg": ("manifest_install_target", "kind_setup_cfg"),
    "package_json": ("manifest_install_target", "kind_package_json"),
    "lockfile": ("lockfile_dependency", "kind_lockfile"),
    "poetry_lock": ("lockfile_dependency", "kind_poetry_lock"),
    "pipfile_lock": ("lockfile_dependency", "kind_pipfile_lock"),
    "package_lock": ("lockfile_dependency", "kind_package_lock"),
    "config": ("config_package_ref", "kind_config"),
    "setup_cfg_config": ("config_package_ref", "kind_setup_cfg_config"),
}

_BASENAME_TO_SIGNAL: Mapping[str, tuple[str, str]] = {
    "requirements.txt": ("manifest_install_target", "base_requirements_txt"),
    "pyproject.toml": ("manifest_install_target", "base_pyproject_toml"),
    "setup.cfg": ("config_package_ref", "base_setup_cfg"),
    "setup.py": ("manifest_install_target", "base_setup_py"),
    "package.json": ("manifest_install_target", "base_package_json"),
    "poetry.lock": ("lockfile_dependency", "base_poetry_lock"),
    "pipfile.lock": ("lockfile_dependency", "base_pipfile_lock"),
    "package-lock.json": ("lockfile_dependency", "base_package_lock_json"),
    "yarn.lock": ("lockfile_dependency", "base_yarn_lock"),
    "pnpm-lock.yaml": ("lockfile_dependency", "base_pnpm_lock"),
}

_PATH_MARKERS = ("/", "\\", "..")
_MAX_SCAN_CHARS = 8_192


def collect_install_metadata_evidence(
    *,
    tool: str,
    arguments: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, str]]:
    """Return bounded evidence slots derived from tool-argument surfaces.

    Empty dict when no channel signals are available. Returned slots contain
    bounded signal/ref/hash fields rather than raw input.
    """

    if not isinstance(arguments, Mapping) or not arguments:
        return {}

    slots: dict[str, dict[str, str]] = {}

    readme_text = _first_surface_text(arguments, _README_SURFACE_KEYS)
    if readme_text is not None:
        match = _match_signal(readme_text, _README_SIGNAL_PATTERNS)
        if match is not None:
            signal_code, basis_code = match
            slot = _bounded_slot(
                channel=EVIDENCE_CHANNEL_README,
                signal_code=signal_code,
                evidence_ref=f"ev_readme_{signal_code}",
                basis_code=basis_code,
            )
            if slot is not None:
                slots[EVIDENCE_CHANNEL_README] = slot

    tool_output_text = _first_surface_text(arguments, _TOOL_OUTPUT_SURFACE_KEYS)
    if tool_output_text is not None:
        match = _match_signal(tool_output_text, _TOOL_OUTPUT_SIGNAL_PATTERNS)
        if match is not None:
            signal_code, basis_code = match
            slot = _bounded_slot(
                channel=EVIDENCE_CHANNEL_TOOL_OUTPUT,
                signal_code=signal_code,
                evidence_ref=f"ev_tool_output_{signal_code}",
                basis_code=basis_code,
            )
            if slot is not None:
                slots[EVIDENCE_CHANNEL_TOOL_OUTPUT] = slot

    file_signal = _detect_file_metadata_signal(arguments)
    if file_signal is not None:
        signal_code, basis_code, evidence_ref = file_signal
        slot = _bounded_slot(
            channel=EVIDENCE_CHANNEL_FILE_METADATA,
            signal_code=signal_code,
            evidence_ref=evidence_ref,
            basis_code=basis_code,
        )
        if slot is not None:
            slots[EVIDENCE_CHANNEL_FILE_METADATA] = slot

    return slots


def _first_surface_text(
    arguments: Mapping[str, Any],
    keys: tuple[str, ...],
) -> str | None:
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if len(text) > _MAX_SCAN_CHARS:
                text = text[:_MAX_SCAN_CHARS]
            return text
    return None


def _match_signal(
    text: str,
    patterns: tuple[tuple[str, str, re.Pattern[str]], ...],
) -> tuple[str, str] | None:
    for signal_code, basis_code, pattern in patterns:
        if pattern.search(text):
            return signal_code, basis_code
    return None


def _detect_file_metadata_signal(
    arguments: Mapping[str, Any],
) -> tuple[str, str, str] | None:
    for key in _FILE_METADATA_KIND_KEYS:
        value = arguments.get(key)
        if not isinstance(value, str):
            continue
        kind = value.strip().lower()
        mapped = _FILE_KIND_TO_SIGNAL.get(kind)
        if mapped is None:
            continue
        signal_code, basis_code = mapped
        return signal_code, basis_code, f"ev_file_metadata_{signal_code}"

    for key in _FILE_BASENAME_KEYS:
        value = arguments.get(key)
        if not isinstance(value, str):
            continue
        name = value.strip()
        if not name or any(marker in name for marker in _PATH_MARKERS):
            # Path-like values are ignored; basename tests cover this boundary.
            continue
        mapped = _BASENAME_TO_SIGNAL.get(name.lower())
        if mapped is None:
            continue
        signal_code, basis_code = mapped
        return signal_code, basis_code, f"ev_file_metadata_{signal_code}"
    return None


def _bounded_slot(
    *,
    channel: str,
    signal_code: str,
    evidence_ref: str,
    basis_code: str,
) -> dict[str, str] | None:
    basis = {
        "collector": COLLECTOR_ID,
        "channel": channel,
        "signal_code": signal_code,
        "evidence_ref": evidence_ref,
        "basis_code": basis_code,
    }
    digest = hashlib.sha256(
        json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload = {
        "signal_code": signal_code,
        "evidence_ref": evidence_ref,
        "content_hash": f"sha256:{digest}",
    }
    try:
        return validate_metadata_evidence_slot(channel, payload)
    except AVPValidationError:
        return None


__all__ = [
    "COLLECTOR_ID",
    "collect_install_metadata_evidence",
]
