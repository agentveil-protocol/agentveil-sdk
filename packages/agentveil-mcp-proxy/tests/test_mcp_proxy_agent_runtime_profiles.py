"""Unit tests for managed agent runtime profiles."""

from __future__ import annotations

import pytest

from agentveil_mcp_proxy.agent_runtime_profiles import (
    GENERIC_PROCESS_PROFILE,
    RuntimeProfileError,
    known_profile_ids,
    resolve_runtime_profile,
)


def test_known_profile_ids_includes_generic_process():
    assert "generic-process" in known_profile_ids()


def test_resolve_runtime_profile_generic_process():
    spec = resolve_runtime_profile("generic-process")
    assert spec.profile_id == "generic-process"
    assert spec.default_status == "configured"
    assert spec.child_detach is True


def test_resolve_runtime_profile_rejects_empty():
    with pytest.raises(RuntimeProfileError, match="profile id required"):
        resolve_runtime_profile("")


def test_resolve_runtime_profile_rejects_unknown():
    with pytest.raises(RuntimeProfileError, match="unsupported runtime profile"):
        resolve_runtime_profile("hermes-server")


def test_generic_process_summary():
    summary = GENERIC_PROCESS_PROFILE.summary()
    assert summary["profile_id"] == "generic-process"
    assert summary["default_status"] == "configured"
