"""Tests for client compatibility pack metadata."""

from __future__ import annotations

import json

import pytest

from agentveil_mcp_proxy.client_packs import (
    CLIENT_PACK_IDS,
    ClientPackError,
    assert_client_packs_payload_is_privacy_safe,
    build_client_packs_payload,
    get_client_pack,
    normalize_client_pack_ids,
)
from agentveil_mcp_proxy.cli import main


def test_client_pack_ids_cover_required_clients():
    assert set(CLIENT_PACK_IDS) == {"cursor", "claude_code", "codex"}


def test_build_client_packs_payload_includes_required_metadata():
    payload = build_client_packs_payload()
    assert payload["ok"] is True
    assert payload["privacy_bounded"] is True
    assert set(payload["packs"]) == set(CLIENT_PACK_IDS)
    for client_id in CLIENT_PACK_IDS:
        pack = payload["packs"][client_id]
        assert pack["client_id"] == client_id
        assert pack["display_name"]
        assert pack["config_surface"]
        assert pack["guidance_summary"]
        assert pack["health_check_capabilities"]
        assert pack["known_limitations"]
        assert pack["support_status"] in {"supported", "manual", "unsupported"}
    assert payload["packs"]["codex"]["support_status"] == "supported"
    assert_client_packs_payload_is_privacy_safe(payload)


def test_normalize_client_pack_ids_rejects_unknown():
    with pytest.raises(ClientPackError, match="unsupported client pack"):
        normalize_client_pack_ids(["cursor", "unknown-client"])


def test_get_client_pack_returns_cursor_pack():
    pack = get_client_pack("cursor")
    assert pack.client_id == "cursor"
    assert pack.renders_runnable_config is True


def test_cli_client_config_packs_json_output(capsys):
    assert main(["client-config", "packs", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["pack_count"] == 3
    assert set(payload["packs"]) == set(CLIENT_PACK_IDS)
