"""Stale Approval Center cards and replay protection (slice 3)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.server import (
    ERROR_CLASS_GENERATION_CHANGED,
    ERROR_CLASS_OWNER_GONE,
    ApprovalServer,
    approval_owner_is_actionable,
    approval_owner_process_alive,
    build_owner_client_id,
    enrich_owner_client_id,
    owner_instance_from_client_id,
    owner_pid_from_client_id,
    publish_owner_claim,
    clear_owner_claim,
    redact_owner_client_id_for_display,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.policy import ProxyConfig

from test_mcp_proxy_approval import _post_decision
from test_mcp_proxy_approval_nonblocking import (
    _TrackingTextIO,
    _ThreadSafeClientOut,
    _approve,
    _build_passthrough,
    _path_logging_downstream,
    _run_stdio_session,
    _shutdown_stdio_session,
    _wait_until,
    _write_file_call,
)


def test_owner_pid_helpers(tmp_path: Path) -> None:
    assert owner_pid_from_client_id("filesystem:pid:12345") == 12345
    assert owner_pid_from_client_id("filesystem:pid:12345:inst:abc") == 12345
    assert owner_pid_from_client_id("no-pid-here") is None
    assert owner_instance_from_client_id("filesystem:pid:1:inst:tok") == "tok"
    assert owner_instance_from_client_id("filesystem:pid:1") is None

    claim_dir = tmp_path / "owner_claims"
    token = "live-token"
    session_id = "session-live"
    client_id = build_owner_client_id("filesystem", instance_token=token)
    lease = publish_owner_claim(
        claim_dir,
        pid=os.getpid(),
        instance_token=token,
        session_id=session_id,
    )
    try:
        assert approval_owner_is_actionable(
            client_id,
            session_id=session_id,
            claim_dir=claim_dir,
        ) is True
    # Legacy / unprovable owners are treated as non-actionable.
        assert approval_owner_process_alive("filesystem:pid:999999999") is False
        assert approval_owner_is_actionable(
            "filesystem:pid:999999999",
            session_id=session_id,
            claim_dir=claim_dir,
        ) is False
        assert approval_owner_is_actionable(
            f"filesystem:pid:{os.getpid()}",
            session_id=session_id,
            claim_dir=claim_dir,
        ) is False
        # PID-reuse spoof: live pid but wrong instance token.
        assert approval_owner_is_actionable(
            enrich_owner_client_id(f"filesystem:pid:{os.getpid()}", instance_token="other"),
            session_id=session_id,
            claim_dir=claim_dir,
        ) is False
    finally:
        clear_owner_claim(lease)


def test_stale_claim_with_reused_pid_is_not_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unlocked crash leftover + live reused PID must not prove ownership."""

    import agentveil_mcp_proxy.approval.persistent as persistent_module

    claim_dir = tmp_path / "owner_claims"
    claim_dir.mkdir(parents=True)
    token = "crash-leftover-token"
    session_id = "crash-session"
    pid = 424242
    path = claim_dir / f"{pid}-{token}.claim"
    path.write_text(
        json.dumps(
            {
                "pid": pid,
                "instance_token": token,
                "session_id": session_id,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(persistent_module, "is_process_alive", lambda _pid: True)
    client_id = build_owner_client_id("filesystem", pid=pid, instance_token=token)
    assert approval_owner_is_actionable(
        client_id,
        session_id=session_id,
        claim_dir=claim_dir,
    ) is False


def test_owner_claim_cleared_on_clean_stop(tmp_path: Path) -> None:
    """Normal stop releases the live claim lease and removes the claim file."""

    passthrough, manager, store, server = _build_passthrough(tmp_path)
    claim_path = manager._owner_claim_path
    assert claim_path.exists()
    assert approval_owner_is_actionable(
        manager.client_id,
        session_id=manager.session_id,
        claim_dir=store.db_path.parent / "owner_claims",
    ) is True
    passthrough.stop()
    assert manager._owner_claim_lease is None
    assert not claim_path.exists()
    assert approval_owner_is_actionable(
        manager.client_id,
        session_id=manager.session_id,
        claim_dir=store.db_path.parent / "owner_claims",
    ) is False
    server.stop()
    store.close()


def test_instance_token_not_exposed_on_approval_surfaces(tmp_path: Path) -> None:
    """User-visible Approval Center / CLI text must not include the raw instance token."""

    import io

    cli_out = io.StringIO()
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=tmp_path / "downstream.log",
        downstream_script=_path_logging_downstream(tmp_path),
    )
    manager.cli_out = cli_out
    token = manager._instance_token
    assert token
    assert token not in redact_owner_client_id_for_display(manager.client_id)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-privacy", path="privacy.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        assert token in prompt.client_id
        row = server.pending_row_dict(prompt)
        assert token not in json.dumps(row)
        assert token not in row["client_id"]
        with httpx.Client() as client:
            page = client.get(server.approval_url(prompt.request_id))
            assert page.status_code == 200
            assert token not in page.text
            api = client.get(f"{server.base_url}/approval/{server.session_token}/api/approvals")
            assert api.status_code == 200
            assert token not in api.text
        assert token not in cli_out.getvalue()
    finally:
        client_in.close()
        worker.join(timeout=5)
        passthrough.stop()
        server.stop()
        store.close()


def test_generation_invalidate_makes_card_terminal_and_blocks_post(tmp_path: Path) -> None:
    """Reconnect generation bump retires only the bound pending card."""

    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-a", path="stale-a.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt_a = server.pending_prompts()[0]
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.PENDING.value
        assert manager._approval_generations.get(prompt_a.request_id) == 0

        now = int(time.time())
        unrelated_id = "unrelated-live-pending"
        unrelated_token = "unrelated-token"
        unrelated_session = "other-session"
        unrelated_client = build_owner_client_id(
            "other",
            instance_token=unrelated_token,
        )
        unrelated_lease = publish_owner_claim(
            store.db_path.parent / "owner_claims",
            pid=os.getpid(),
            instance_token=unrelated_token,
            session_id=unrelated_session,
        )
        # Unrelated live row uses its own session identity; generation invalidation
        # must not touch it. Owner claim for that session is asserted separately.
        store.write_pending(
            PendingApproval(
                request_id=unrelated_id,
                session_id=unrelated_session,
                client_id=unrelated_client,
                downstream_server="other",
                tool_name="other_tool",
                action_class="write",
                risk_class="write",
                resource_hash="sha256:" + ("a" * 64),
                payload_hash="sha256:" + ("b" * 64),
                policy_id="other",
                policy_rule_id="other",
                policy_context_hash="c" * 64,
                status=ApprovalStatus.PENDING.value,
                created_at=now,
                expires_at=now + 3600,
            )
        )

        passthrough._downstream_generation = 1
        invalidated = manager.publish_downstream_generation(1)
        assert prompt_a.request_id in invalidated
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.INVALIDATED.value
        assert store.get_pending(prompt_a.request_id).error_class == ERROR_CLASS_GENERATION_CHANGED
        assert store.get_pending(unrelated_id).status == ApprovalStatus.PENDING.value
        assert server.prompt_for(prompt_a.request_id) is None

        with httpx.Client() as client:
            url = server.approval_url(prompt_a.request_id)
            stale_get = client.get(url)
            assert stale_get.status_code == 410
            assert "Approve" not in stale_get.text
            assert "Deny" not in stale_get.text
            late = _post_decision(client, url, decision="approve", csrf="missing")
            assert late.status_code == 410
            assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.INVALIDATED.value

        assert (not log_path.exists()) or ("tools/call" not in log_path.read_text(encoding="utf-8"))

        client_in.write_line(_write_file_call(call_id="write-b", path="fresh-b.txt"))
        assert _wait_until(
            lambda: any(p.request_id != prompt_a.request_id for p in server.pending_prompts()),
            timeout=2.0,
        )
        prompt_b = next(p for p in server.pending_prompts() if p.request_id != prompt_a.request_id)
        assert prompt_b.request_id != prompt_a.request_id
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        response_b = client_out.response_by_id("write-b")
        assert response_b is not None
        assert "result" in response_b
        calls = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        tool_calls = [row for row in calls if row.get("method") == "tools/call"]
        assert len(tool_calls) == 1
        assert tool_calls[0]["path"] == "fresh-b.txt"
        assert store.get_pending(unrelated_id).status == ApprovalStatus.PENDING.value
    finally:
        clear_owner_claim(locals().get("unrelated_lease"))
        client_in.close()
        worker.join(timeout=5)
        passthrough.stop()
        server.stop()
        store.close()


def test_register_binds_generation_before_card_is_actionable(tmp_path: Path) -> None:
    """Generation is bound before register; stale generation is rejected."""

    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        wait_for_decision=False,
    )
    classification = ToolCallClassifier(
        ProxyConfig.from_dict({
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": "https://agentveil.dev",
                "agent_name": "stale-bind",
                "trusted_signer_dids": ["did:key:zStale"],
            },
            "mode": "protect",
            "privacy": {
                "action": "redacted",
                "resource": "hash",
                "payload": "hash_only",
                "evidence_upload": False,
            },
            "approval": {"approval_timeout_seconds": 30, "on_timeout": "deny"},
            "policy": {
                "id": "stale-bind",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "write",
                "rules": [],
            },
            "downstream": {},
        }),
        server_name="filesystem",
    ).classify(tool="write_file", arguments={"path": "a.txt", "content": "x"})

    seen_bound = threading.Event()
    original_register = server.register

    def _assert_bound_register(prompt):
        assert manager._approval_generations.get(prompt.request_id) == 0
        seen_bound.set()
        return original_register(prompt)

    server.register = _assert_bound_register  # type: ignore[method-assign]
    manager.note_downstream_generation(0)
    outcome_live = manager.request_approval(
        classification,
        reason="local_approval_required",
        downstream_generation=0,
    )
    assert seen_bound.is_set()
    assert outcome_live.status == ApprovalStatus.PENDING.value
    live_id = outcome_live.request_id
    assert server.prompt_for(live_id) is not None

    # Reconnect publishes generation 1 before a stale caller can register.
    manager.publish_downstream_generation(1)
    outcome_stale = manager.request_approval(
        classification,
        reason="local_approval_required",
        downstream_generation=0,
    )
    assert outcome_stale.status == ApprovalStatus.INVALIDATED.value
    assert outcome_stale.reason == ERROR_CLASS_GENERATION_CHANGED
    assert server.prompt_for(outcome_stale.request_id) is None
    stale_record = store.get_pending(outcome_stale.request_id)
    assert stale_record is not None
    assert stale_record.status == ApprovalStatus.INVALIDATED.value
    with httpx.Client() as client:
        response = client.get(server.approval_url(outcome_stale.request_id))
        assert response.status_code == 410
    server.stop()
    store.close()


def test_dead_owner_pending_not_actionable_after_restart(tmp_path: Path) -> None:
    """Durable pending without live owner rejects late Approve and creates no grant."""

    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-orphan", path="orphan.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        request_id = prompt.request_id
        assert store.get_pending(request_id).status == ApprovalStatus.PENDING.value

        # Drop the live owner claim without rewriting the evidence client_id.
        clear_owner_claim(manager._owner_claim_lease)
        manager._owner_claim_lease = None
        assert approval_owner_is_actionable(
            store.get_pending(request_id).client_id,
            session_id=store.get_pending(request_id).session_id,
            claim_dir=store.db_path.parent / "owner_claims",
        ) is False

        assert server.prompt_for(request_id) is None
        retired = store.get_pending(request_id)
        assert retired is not None
        assert retired.status == ApprovalStatus.INVALIDATED.value
        assert retired.error_class == ERROR_CLASS_OWNER_GONE

        with httpx.Client() as client:
            url = server.approval_url(request_id)
            stale_get = client.get(url)
            assert stale_get.status_code == 410
            assert "Approve" not in stale_get.text
            late = _post_decision(client, url, decision="approve", csrf="x")
            assert late.status_code == 410

        final = store.get_pending(request_id)
        assert final is not None
        assert final.status == ApprovalStatus.INVALIDATED.value
        assert store.find_active_exact_grant(
            downstream_server="filesystem",
            tool_name="write_file",
            policy_rule_id=final.policy_rule_id,
            risk_class="write",
            policy_context_hash=final.policy_context_hash,
            resource_hash=final.resource_hash,
            payload_hash=final.payload_hash,
            now_timestamp=int(time.time()),
        ) is None
        assert (not log_path.exists()) or ("tools/call" not in log_path.read_text(encoding="utf-8"))

        # Retiring the owner invalidates evidence, while the approval waiter
        # continues waiting until the decision event is signaled.
        server.notify_cancelled(request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-orphan") is not None,
            timeout=3.0,
        )
    finally:
        _shutdown_stdio_session(worker, client_in, passthrough)
        server.stop()
        store.close()


def test_process_restart_stale_card_e2e(tmp_path: Path) -> None:
    """Real child proxy process leaves a non-actionable card; successor executes once."""

    evidence_path = tmp_path / "evidence.sqlite"
    log_path = tmp_path / "downstream.log"
    child_out = tmp_path / "child.json"
    store = ApprovalEvidenceStore(evidence_path)
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    script = tmp_path / "child_proxy.py"
    script.write_text(
        f"""
import json
import os
import sys
from pathlib import Path

from agentveil_mcp_proxy.approval.client import RemoteApprovalServer
from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.persistent import ApprovalCenterManifest
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
from agentveil_mcp_proxy.policy import ProxyConfig

evidence_path = Path({str(evidence_path)!r})
out_path = Path({str(child_out)!r})
store = ApprovalEvidenceStore(evidence_path)
manifest = ApprovalCenterManifest(
    schema_version=2,
    host="127.0.0.1",
    port={server.port},
    session_token={server.session_token!r},
    token_hash={server.token_hash!r},
    internal_register_token={server.internal_register_token!r},
    pid=0,
    started_at=0,
)
remote = RemoteApprovalServer(manifest, evidence_store=store)
config = ProxyConfig.from_dict({{
    "proxy_config_schema_version": 1,
    "avp": {{
        "base_url": "https://agentveil.dev",
        "agent_name": "child",
        "trusted_signer_dids": ["did:key:zChild"],
    }},
    "mode": "protect",
    "privacy": {{
        "action": "redacted",
        "resource": "hash",
        "payload": "hash_only",
        "evidence_upload": False,
    }},
    "approval": {{
        "approval_timeout_seconds": 30,
        "on_timeout": "deny",
        "ui_open_mode": "browser",
    }},
    "policy": {{
        "id": "child",
        "policy_schema_version": 1,
        "default_decision": "approval",
        "default_risk_class": "write",
        "rules": [],
    }},
    "downstream": {{}},
}})
manager = ApprovalManager(
    evidence_store=store,
    approval_server=remote,
    config=config,
    client_id="child:pid:" + str(os.getpid()),
    wait_for_decision=False,
    browser_open=lambda _url: True,
)
classification = ToolCallClassifier(config, server_name="filesystem").classify(
    tool="write_file",
    arguments={{"path": "old.txt", "content": "old"}},
)
outcome = manager.request_approval(
    classification,
    reason="local_approval_required",
    downstream_generation=0,
)
out_path.write_text(json.dumps({{
    "request_id": outcome.request_id,
    "client_id": manager.client_id,
    "session_id": manager.session_id,
}}), encoding="utf-8")
sys.exit(0)
""".lstrip(),
        encoding="utf-8",
    )
    try:
        completed = subprocess.run(
            [sys.executable, str(script)],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env={
                **os.environ,
                "PYTHONPATH": (
                    f"{Path(__file__).resolve().parents[2]}:"
                    f"{Path(__file__).resolve().parents[3]}:"
                    + os.environ.get("PYTHONPATH", "")
                ),
            },
        )
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(child_out.read_text(encoding="utf-8"))
        request_id = payload["request_id"]
        record = store.get_pending(request_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING.value

        with httpx.Client() as client:
            url = server.approval_url(request_id)
            stale_get = client.get(url)
            assert stale_get.status_code == 410
            late = _post_decision(client, url, decision="approve", csrf="x")
            assert late.status_code == 410
        retired = store.get_pending(request_id)
        assert retired is not None
        assert retired.status == ApprovalStatus.INVALIDATED.value
        assert retired.error_class == ERROR_CLASS_OWNER_GONE

        successor = tmp_path / "successor"
        successor.mkdir(parents=True, exist_ok=True)
        passthrough, _manager_b, store_b, server_b = _build_passthrough(
            successor,
            log_path=log_path,
            downstream_script=_path_logging_downstream(successor),
        )
        client_in = _TrackingTextIO()
        client_out = _ThreadSafeClientOut()
        worker = _run_stdio_session(passthrough, client_in, client_out)
        worker.start()
        try:
            client_in.write_line(_write_file_call(call_id="write-new", path="new.txt"))
            assert _wait_until(lambda: bool(server_b.pending_prompts()), timeout=2.0)
            prompt = server_b.pending_prompts()[0]
            _approve(server_b, prompt.request_id)
            assert _wait_until(lambda: client_out.response_by_id("write-new") is not None, timeout=3.0)
            assert "result" in client_out.response_by_id("write-new")
            calls = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            tool_calls = [row for row in calls if row.get("method") == "tools/call"]
            assert len(tool_calls) == 1
            assert tool_calls[0]["path"] == "new.txt"
        finally:
            client_in.close()
            worker.join(timeout=5)
            passthrough.stop()
            server_b.stop()
            store_b.close()
    finally:
        server.stop()
        store.close()


def test_late_decision_vs_invalidation_single_winner(tmp_path: Path) -> None:
    """Concurrent approve POST and generation invalidation produce one terminal winner."""

    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=tmp_path / "downstream.log",
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-race", path="race.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        request_id = prompt.request_id
        url = server.approval_url(request_id)

        start = threading.Barrier(2)
        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def _post() -> None:
            try:
                start.wait(timeout=5)
                with httpx.Client() as client:
                    results["post"] = _post_decision(
                        client,
                        url,
                        decision="approve",
                        csrf=prompt.csrf_token,
                    )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def _invalidate() -> None:
            try:
                start.wait(timeout=5)
                results["invalidated"] = manager.publish_downstream_generation(
                    manager._downstream_generation + 1
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=_post),
            threading.Thread(target=_invalidate),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert not errors
        final = store.get_pending(request_id)
        assert final is not None
        assert final.status in {
            ApprovalStatus.APPROVED.value,
            ApprovalStatus.INVALIDATED.value,
        }
        if final.status == ApprovalStatus.INVALIDATED.value:
            post = results["post"]
            assert getattr(post, "status_code") == 410
            assert store.find_active_exact_grant(
                downstream_server="filesystem",
                tool_name="write_file",
                policy_rule_id=final.policy_rule_id,
                risk_class="write",
                policy_context_hash=final.policy_context_hash,
                resource_hash=final.resource_hash,
                payload_hash=final.payload_hash,
                now_timestamp=int(time.time()),
            ) is None
            assert (not (tmp_path / "downstream.log").exists()) or (
                "tools/call" not in (tmp_path / "downstream.log").read_text(encoding="utf-8")
            )
        else:
            assert getattr(results["post"], "status_code") == 200
            assert _wait_until(lambda: client_out.response_by_id("write-race") is not None, timeout=3.0)
    finally:
        client_in.close()
        worker.join(timeout=5)
        passthrough.stop()
        server.stop()
        store.close()


def test_repeated_stale_post_is_idempotent(tmp_path: Path) -> None:
    """Repeated POST on a terminal card does not change evidence or execute."""

    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-repeat", path="repeat.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        request_id = prompt.request_id
        manager.publish_downstream_generation(manager._downstream_generation + 1)
        assert store.get_pending(request_id).status == ApprovalStatus.INVALIDATED.value
        url = server.approval_url(request_id)
        with httpx.Client() as client:
            first = _post_decision(client, url, decision="approve", csrf=prompt.csrf_token)
            second = _post_decision(client, url, decision="approve", csrf=prompt.csrf_token)
        assert first.status_code == 410
        assert second.status_code == 410
        assert store.get_pending(request_id).status == ApprovalStatus.INVALIDATED.value
        assert (not log_path.exists()) or ("tools/call" not in log_path.read_text(encoding="utf-8"))
    finally:
        client_in.close()
        worker.join(timeout=5)
        passthrough.stop()
        server.stop()
        store.close()
