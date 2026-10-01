# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Public AV-02 per-agent runtime binding client matrix proofs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from agentveil_mcp_proxy.console_agent_binding_client import (
    CONSOLE_ORIGIN,
    AgentBindingClientError,
    ConsoleAgentBindingClient,
    RawResponse,
    _REQUEST_BODY,
)
from agentveil_mcp_proxy.console_credentials import (
    RUNTIME_BINDING_SCOPE,
    credential_directory,
    delete_scoped_runtime_binding_credential,
    load_runtime_binding_credential,
    load_scoped_runtime_binding_credential,
    resolve_runtime_binding_for_context,
    save_credential,
    save_runtime_binding_credential,
    save_scoped_runtime_binding_credential,
    scoped_runtime_binding_namespace_hash,
)
from agentveil_mcp_proxy.controlled_alternatives_transport import (
    bind_installed_runtime_context,
    build_controlled_alternative_context,
    read_cached_av02_runtime_installation_id,
)

SUMMARY_TOKEN = "bounded-summary-upload-token"
SUMMARY_TOKEN_B = "bounded-summary-upload-token-b0123456789ab"
CANARY_SUMMARY = "console-device-token-canary-secret-value"
_BINDING_PATH = "/v1/controlled-alternatives/av02/runtime/binding"
_BINDING_REQUEST = {"schema_version": "runtime/binding-request/1"}
_VALID_TOKEN = "issued-runtime-binding-token-0123456789ab"


def _scan(*values: object) -> None:
    blob = "".join(str(value) for value in values)
    for canary in (SUMMARY_TOKEN, CANARY_SUMMARY, "/Users/"):
        assert canary not in blob


def _agent(key: SigningKey, *, suffix: str = "a") -> SimpleNamespace:
    return SimpleNamespace(
        private_key_hex=bytes(key).hex(),
        did=f"did:key:z6Mkagent{suffix}",
    )


def _ok_binding_response(*, token: str, result: str = "issued") -> bytes:
    payload = {
        "schema_version": "runtime/binding-response/1",
        "runtime_binding_token": token,
        "scope": RUNTIME_BINDING_SCOPE,
        "result": result,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _raw_response(body: bytes, *, status: int = 200) -> RawResponse:
    return RawResponse(
        status=status,
        content_types=("application/json",),
        body=body,
        cache_control=("no-store",),
    )


def _parse_auth_v2(headers: dict[str, str]) -> dict[str, str]:
    authorization = headers["Authorization"]
    return dict(re.findall(r'(\w+)="([^"]+)"', authorization))


def _verify_auth_v2(
    key: SigningKey,
    *,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
) -> None:
    parsed = _parse_auth_v2(headers)
    assert parsed.get("v") == "2"
    message = (
        f"v2:{method}:{path}::{parsed['ts']}:{parsed['nonce']}:"
        f"{hashlib.sha256(body).hexdigest()}"
    )
    key.verify_key.verify(message.encode(), bytes.fromhex(parsed["sig"]))


def test_agent_binding_wire_contract() -> None:
    captured: list[tuple[str, dict[str, str], bytes]] = []

    def transport(method, url, *, headers, body, timeout):
        captured.append((method, dict(headers), body))
        assert url == CONSOLE_ORIGIN + _BINDING_PATH
        return _raw_response(_ok_binding_response(token=_VALID_TOKEN))

    key = SigningKey.generate()
    client = ConsoleAgentBindingClient(transport=transport)
    result = client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)
    assert result.scope == RUNTIME_BINDING_SCOPE
    assert result.result == "issued"
    assert result.token == _VALID_TOKEN
    assert len(captured) == 1
    method, headers, body = captured[0]
    assert method == "POST"
    assert body == _REQUEST_BODY
    assert headers["X-AgentVeil-Console-Credential"] == SUMMARY_TOKEN
    assert "X-AVP-CA-Runtime-Binding" not in headers
    _verify_auth_v2(key, method="POST", path=_BINDING_PATH, body=body, headers=headers)
    _scan(repr(result))


def test_agent_binding_signed_bytes() -> None:
    key = SigningKey.generate()
    agent = _agent(key)
    captured: list[dict[str, str]] = []

    def issuer_transport(method, url, *, headers, body, timeout):
        header_map = dict(headers)
        captured.append(header_map)
        try:
            _verify_auth_v2(key, method="POST", path=_BINDING_PATH, body=body, headers=header_map)
        except Exception:
            return RawResponse(
                status=401,
                content_types=("application/json",),
                body=b'{"error":"invalid_signature"}',
                cache_control=("no-store",),
            )
        return _raw_response(_ok_binding_response(token=_VALID_TOKEN))

    client = ConsoleAgentBindingClient(transport=issuer_transport)
    result = client.issue(agent=agent, summary_token=SUMMARY_TOKEN)
    assert result.result == "issued"
    assert captured

    from agentveil.auth import build_auth_header as real_build_auth_header

    def corrupt_build_auth_header(*args, **kwargs):
        headers = real_build_auth_header(*args, **kwargs)
        authorization = headers["Authorization"]
        parsed = dict(re.findall(r'(\w+)="([^"]+)"', authorization))
        bad_sig = parsed["sig"][:-1] + ("0" if parsed["sig"][-1] != "0" else "1")
        headers["Authorization"] = authorization.replace(parsed["sig"], bad_sig)
        return headers

    import agentveil.auth as auth_mod

    original = auth_mod.build_auth_header
    auth_mod.build_auth_header = corrupt_build_auth_header
    try:
        with pytest.raises(AgentBindingClientError):
            ConsoleAgentBindingClient(transport=issuer_transport).issue(
                agent=agent,
                summary_token=SUMMARY_TOKEN,
            )
    finally:
        auth_mod.build_auth_header = original
    _scan(result)


def test_agent_binding_two_agents() -> None:
    key_a = SigningKey.generate()
    key_b = SigningKey.generate()
    seen_dids: list[str] = []

    def transport(method, url, *, headers, body, timeout):
        header_map = dict(headers)
        parsed = _parse_auth_v2(header_map)
        if parsed["did"] == _agent(key_a).did:
            _verify_auth_v2(key_a, method="POST", path=_BINDING_PATH, body=body, headers=header_map)
        elif parsed["did"] == _agent(key_b, suffix="b").did:
            _verify_auth_v2(key_b, method="POST", path=_BINDING_PATH, body=body, headers=header_map)
        else:
            return RawResponse(
                status=403,
                content_types=("application/json",),
                body=b'{"error":"wrong_audience"}',
                cache_control=("no-store",),
            )
        seen_dids.append(parsed["did"])
        token = _VALID_TOKEN if parsed["did"] == _agent(key_a).did else "second-agent-binding-token-0123456789ab"
        return _raw_response(_ok_binding_response(token=token))

    client = ConsoleAgentBindingClient(transport=transport)
    first = client.issue(agent=_agent(key_a), summary_token=SUMMARY_TOKEN)
    second = client.issue(agent=_agent(key_b, suffix="b"), summary_token=SUMMARY_TOKEN)
    assert first.token != second.token
    assert len(set(seen_dids)) == 2
    _scan(seen_dids)


def test_agent_binding_retry_idempotent() -> None:
    key = SigningKey.generate()
    calls = {"count": 0}
    nonces: list[str] = []

    def transport(method, url, *, headers, body, timeout):
        nonces.append(_parse_auth_v2(headers)["nonce"])
        calls["count"] += 1
        result = "issued" if calls["count"] == 1 else "existing"
        return _raw_response(_ok_binding_response(token=_VALID_TOKEN, result=result))

    client = ConsoleAgentBindingClient(transport=transport)
    first = client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)
    second = client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)
    assert first.result == "issued"
    assert second.result == "existing"
    assert first.token == second.token
    assert len(nonces) == 2
    assert nonces[0] != nonces[1]
    _scan(nonces)


def test_agent_binding_custody_lifecycle(tmp_path: Path) -> None:
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary_a = "summary-token-a-0123456789abcdef0123456789ab"
    summary_b = "summary-token-b-0123456789abcdef0123456789ab"
    token_a = "scoped-runtime-binding-token-a-0123456789ab"
    save_scoped_runtime_binding_credential(
        token_a,
        agent_did=agent_did,
        summary_token=summary_a,
        home=tmp_path,
    )
    loaded = load_scoped_runtime_binding_credential(
        agent_did,
        summary_a,
        home=tmp_path,
    )
    assert loaded is not None
    assert loaded.token == token_a
    assert delete_scoped_runtime_binding_credential(agent_did, summary_a, home=tmp_path)
    assert load_scoped_runtime_binding_credential(agent_did, summary_a, home=tmp_path) is None

    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    assert load_runtime_binding_credential(home=tmp_path).token == legacy
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-b-0123456789ab",
        agent_did=agent_did,
        summary_token=summary_b,
        home=tmp_path,
    )
    resolved = resolve_runtime_binding_for_context(agent_did, summary_b, tmp_path)
    assert resolved is not None and resolved.token != legacy
    assert resolve_runtime_binding_for_context(agent_did, summary_a, tmp_path) is None
    assert load_runtime_binding_credential(home=tmp_path).token == legacy

    import agentveil_mcp_proxy.controlled_alternatives_transport as transport_mod

    save_credential(SUMMARY_TOKEN, home=tmp_path)
    key = SigningKey.generate()
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-live-0123456789ab",
        agent_did=_agent(key).did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    namespace = scoped_runtime_binding_namespace_hash(_agent(key).did, SUMMARY_TOKEN)
    bad_file = credential_directory(tmp_path) / f"runtime-binding-scoped-{namespace}.json"
    bad_file.write_text("{", encoding="utf-8")
    os.chmod(bad_file, 0o600)
    exchanges: list[str] = []
    transport_mod._run_bounded_exchange = lambda _url, _headers, body, method="POST": (
        exchanges.append(body) or (200, {"schema_version": "1"})
    )
    bound = build_controlled_alternative_context(
        agent=_agent(key),
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []

    _scan(token_a, legacy, resolved.token)


def test_agent_binding_source_change_fails_closed(tmp_path: Path) -> None:
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary_a = "summary-token-a-0123456789abcdef0123456789ab"
    summary_b = "summary-token-b-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-a-0123456789ab",
        agent_did=agent_did,
        summary_token=summary_a,
        home=tmp_path,
    )
    assert resolve_runtime_binding_for_context(agent_did, summary_b, tmp_path) is None
    assert load_runtime_binding_credential(home=tmp_path).token == legacy

    key = SigningKey.generate()
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-live-0123456789ab",
        agent_did=_agent(key).did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    context = build_controlled_alternative_context(
        agent=_agent(key),
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        canonical_project_root=tmp_path,
    )
    assert context is not None and context.heartbeat is not None
    save_credential(SUMMARY_TOKEN_B, home=tmp_path)
    assert context.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})

    save_credential(SUMMARY_TOKEN_B, home=tmp_path)
    fresh = build_controlled_alternative_context(
        agent=_agent(key),
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        canonical_project_root=tmp_path,
    )
    assert fresh is not None and fresh.heartbeat is not None
    exchanges: list[str] = []
    import agentveil_mcp_proxy.controlled_alternatives_transport as transport_mod

    transport_mod._run_bounded_exchange = lambda _url, _headers, body, method="POST": (
        exchanges.append(body) or (200, {"schema_version": "1"})
    )
    assert fresh.heartbeat(SUMMARY_TOKEN_B, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []
    _scan(legacy)


def test_agent_binding_privacy(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.console_credentials import (
        scoped_runtime_binding_namespace_hash,
        credential_directory,
    )
    from agentveil_mcp_proxy.cli import issue_and_store_scoped_runtime_binding
    from agentveil_mcp_proxy.console_project_status_client import build_project_status_summary

    key = SigningKey.generate()
    agent = _agent(key)

    def transport(method, url, *, headers, body, timeout):
        return _raw_response(_ok_binding_response(token=_VALID_TOKEN))

    client = ConsoleAgentBindingClient(transport=transport)
    result = client.issue(agent=agent, summary_token=SUMMARY_TOKEN)
    text = repr(result)
    assert result.token not in text
    assert agent.did not in text
    assert SUMMARY_TOKEN not in text

    issue_and_store_scoped_runtime_binding(
        agent=agent,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
        client=client,
    )
    namespace = scoped_runtime_binding_namespace_hash(agent.did, SUMMARY_TOKEN)
    for path in credential_directory(tmp_path).iterdir():
        assert agent.did not in path.name
        assert SUMMARY_TOKEN not in path.name
        assert namespace in path.name or path.name.startswith("runtime-binding-scoped-source-")

    from dataclasses import asdict

    ref = "a" * 64
    summary_payload = build_project_status_summary(
        connector="codex",
        connector_status={
            "status": "protected",
            "mcp_route": {"state": "active"},
        },
        project_dir=tmp_path,
        package_version="0.0.0",
        private_guardrails_status="unavailable",
        client_installation_ref=ref,
    )
    assert summary_payload is not None
    summary_text = json.dumps(asdict(summary_payload))
    assert SUMMARY_TOKEN not in summary_text
    assert agent.did not in summary_text
    _scan(text, summary_text)


def test_agent_binding_legacy_upgrade_compatibility(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.cli import issue_and_store_scoped_runtime_binding

    from agentveil_mcp_proxy.console_credentials import runtime_binding_credential_path

    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    legacy_path = runtime_binding_credential_path(tmp_path)
    before = legacy_path.read_bytes()
    key = SigningKey.generate()
    scoped_token = "scoped-runtime-binding-token-0123456789ab"

    def transport(method, url, *, headers, body, timeout):
        return _raw_response(_ok_binding_response(token=scoped_token))

    issue_and_store_scoped_runtime_binding(
        agent=_agent(key),
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
        client=ConsoleAgentBindingClient(transport=transport),
    )
    assert legacy_path.read_bytes() == before
    assert load_runtime_binding_credential(home=tmp_path).token == legacy
    loaded = load_scoped_runtime_binding_credential(_agent(key).did, SUMMARY_TOKEN, home=tmp_path)
    assert loaded is not None and loaded.token == scoped_token
    _scan(scoped_token)


def test_agent_binding_rejects_duplicate_json_keys() -> None:
    duplicate_body = (
        b'{"schema_version":"runtime/binding-response/1",'
        b'"runtime_binding_token":"issued-runtime-binding-token-0123456789ab",'
        b'"scope":"controlled_alternatives_runtime_binding",'
        b'"result":"issued","runtime_binding_token":"duplicate-token-0123456789ab"}'
    )

    def transport(method, url, *, headers, body, timeout):
        assert body == _REQUEST_BODY
        return _raw_response(duplicate_body)

    key = SigningKey.generate()
    client = ConsoleAgentBindingClient(transport=transport)
    with pytest.raises(AgentBindingClientError):
        client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)


def test_agent_binding_accepts_valid_response_control() -> None:
    def transport(method, url, *, headers, body, timeout):
        assert body == _REQUEST_BODY
        return _raw_response(_ok_binding_response(token=_VALID_TOKEN))

    key = SigningKey.generate()
    client = ConsoleAgentBindingClient(transport=transport)
    result = client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)
    assert result.token == _VALID_TOKEN


@pytest.mark.parametrize("bad_result", [["issued"], {"result": "issued"}])
def test_agent_binding_rejects_invalid_result_types(bad_result) -> None:
    payload = {
        "schema_version": "runtime/binding-response/1",
        "runtime_binding_token": _VALID_TOKEN,
        "scope": RUNTIME_BINDING_SCOPE,
        "result": bad_result,
    }
    response_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def transport(method, url, *, headers, body, timeout):
        assert body == _REQUEST_BODY
        return _raw_response(response_body)

    key = SigningKey.generate()
    client = ConsoleAgentBindingClient(transport=transport)
    with pytest.raises(AgentBindingClientError):
        client.issue(agent=_agent(key), summary_token=SUMMARY_TOKEN)


def test_agent_binding_recovers_cached_runtime_id(tmp_path: Path) -> None:
    runtime_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    state_dir = tmp_path / "controlled-alternatives"
    state_dir.mkdir(parents=True)
    os.chmod(state_dir, 0o700)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "runtime_version": "1.0.0",
                "contract_range": "av02.v1",
                "catalog_digest": "aa" * 32,
                "declared_executor_capabilities": [
                    "filesystem.stage_delete.v1",
                    "filesystem.restore_staged.v1",
                    "filesystem.cleanup_staged.v1",
                    "protected_write.prepare_patch.v1",
                    "git.prepare_local_change.v1",
                    "protected_write.apply_prepared_patch.v1",
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    payload = {
        "schema_version": "av02-runtime-state/1",
        "runtime_installation_id": runtime_id,
        "registration_fingerprint": fingerprint,
    }
    state_file = state_dir / "av02-runtime-state.json"
    state_file.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(state_file, stat.S_IRUSR | stat.S_IWUSR)
    assert read_cached_av02_runtime_installation_id(tmp_path) == runtime_id


def test_legacy_context_without_summary_file_uses_legacy_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentveil_mcp_proxy.controlled_alternatives_transport as transport_mod

    exchanges: list[str] = []

    def exchange(url, headers, body, method="POST"):
        exchanges.append(url)
        return 200, {
            "schema_version": "runtime/register-response/1",
            "runtime_installation_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }

    monkeypatch.setattr(transport_mod, "_run_bounded_exchange", exchange)
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    key = SigningKey.generate()
    context = build_controlled_alternative_context(
        agent=_agent(key),
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=None,
    )
    assert context is not None
    assert context.contract_version == transport_mod.CONTEXT_VERSION_V2
    assert callable(context.runtime_register)
    status, _payload = context.runtime_register(
        {
            "schema_version": "runtime/register/1",
            "runtime_version": "1.0.0",
            "contract_range": "av02.v1",
            "catalog_digest": "aa" * 32,
            "declared_executor_capabilities": [
                "filesystem.stage_delete.v1",
                "filesystem.restore_staged.v1",
                "filesystem.cleanup_staged.v1",
                "protected_write.prepare_patch.v1",
                "git.prepare_local_change.v1",
                "protected_write.apply_prepared_patch.v1",
            ],
        }
    )
    assert status == 200
    assert exchanges and "/av02/runtime/register" in exchanges[0]

    class LegacyAv02Consumer:
        def bind_runtime_context(self, bound):
            assert bound is context
            assert callable(bound.runtime_register)
            return self

    assert bind_installed_runtime_context(LegacyAv02Consumer(), context) is not None


def test_read_cached_runtime_id_rejects_foreign_namespace(tmp_path: Path) -> None:
    foreign_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    foreign_dir = tmp_path / "foreign-agent"
    foreign_dir.mkdir()
    ca_dir = foreign_dir / "controlled-alternatives"
    ca_dir.mkdir()
    state_file = ca_dir / "av02-runtime-state.json"
    state_file.write_text(
        json.dumps(
            {
                "schema_version": "av02-runtime-state/1",
                "runtime_installation_id": foreign_id,
                "registration_fingerprint": "aa" * 64,
            }
        ),
        encoding="utf-8",
    )
    assert read_cached_av02_runtime_installation_id(tmp_path) is None


def test_legacy_agent_unaffected_by_other_agent_scoped_entry(tmp_path: Path) -> None:
    agent_a = "did:key:z6MkagentA0123456789012345678901234567890"
    agent_b = "did:key:z6MkagentB0123456789012345678901234567890"
    summary = "summary-token-a-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-b-0123456789ab",
        agent_did=agent_b,
        summary_token=summary,
        home=tmp_path,
    )
    resolved = resolve_runtime_binding_for_context(agent_a, summary, tmp_path)
    assert resolved is not None
    assert resolved.token == legacy
