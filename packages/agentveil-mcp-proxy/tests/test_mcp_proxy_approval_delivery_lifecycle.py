"""Approval Center delivery + managed lifecycle corrective proofs."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentveil_mcp_proxy.approval.client import (
    RemoteApprovalServer,
    reconcile_managed_approval_center_for_runtime,
    resolve_approval_server,
)
from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.notification import (
    deliver_approval_browser_url,
    open_approval_url_webbrowser,
)
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    _approval_center_code_fingerprint,
    current_approval_center_runtime_identity,
    load_manifest,
    manifest_runtime_matches_current,
    save_manifest,
    token_hash_for,
)
from agentveil_mcp_proxy.approval.server import (
    ApprovalServer,
    ensure_managed_approval_center_running,
    inspect_managed_approval_center,
    prepare_stale_managed_approval_center,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.policy import ProxyConfig


def _config(*, approval_timeout_seconds: int = 300) -> ProxyConfig:
    return ProxyConfig.from_dict(
        {
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": "https://agentveil.dev",
                "agent_name": "agentveil-mcp-proxy",
                "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
            },
            "mode": "protect",
            "privacy": {
                "action": "redacted",
                "resource": "hash",
                "payload": "hash_only",
                "evidence_upload": False,
            },
            "fallback": {
                "read": "allow",
                "write": "approval",
                "destructive": "block",
                "production": "block",  # claim-check: allow fallback risk_class enum value
                "financial": "block",
                "unknown": "approval",
            },
            "approval": {
                "approval_timeout_seconds": approval_timeout_seconds,
                "on_timeout": "deny",
                "ui_open_mode": "browser",
            },
            "policy": {
                "id": "delivery",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "write",
                "rules": [
                    {
                        "id": "write",
                        "match": {"tool": "write_file"},
                        "decision": "approval",
                        "risk_class": "write",
                    }
                ],
            },
            "downstream": {},
        }
    )


def _classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": "ops/canary.json", "content": "x"},
    )


def _manager(tmp_path: Path, *, browser_open, wait_for_decision: bool = True):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id=f"cursor:pid:{os.getpid()}",
        session_id="session-delivery-123456",
        cli_out=io.StringIO(),
        browser_open=browser_open,
        wait_for_decision=wait_for_decision,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    return manager, store, server


def test_browser_opener_false_is_not_success_and_retries():
    calls: list[str] = []

    def opener(url: str) -> bool:
        calls.append(url)
        return False

    first = open_approval_url_webbrowser("http://127.0.0.1:9/approval/x", opener=opener)
    second = open_approval_url_webbrowser("http://127.0.0.1:9/approval/y", opener=opener)
    assert first.delivered is False
    assert second.delivered is False
    assert calls == [
        "http://127.0.0.1:9/approval/x",
        "http://127.0.0.1:9/approval/y",
    ]


def test_browser_opener_exception_is_not_success():
    def opener(_url: str) -> bool:
        raise RuntimeError("no display")

    result = open_approval_url_webbrowser("http://127.0.0.1:9/approval/x", opener=opener)
    assert result.attempted is True
    assert result.delivered is False


@pytest.mark.allow_approval_browser_delivery
def test_macos_native_fallback_used_when_webbrowser_fails(monkeypatch):
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.notification.shutil.which",
        lambda name: "/usr/bin/open" if name == "open" else None,
    )
    runs: list[list[str]] = []

    def runner(args, **_kwargs):
        runs.append(list(args))
        return SimpleNamespace(returncode=0)

    result = deliver_approval_browser_url(
        "http://127.0.0.1:9/approval/token",
        webbrowser_opener=lambda _url: False,
        native_runner=runner,
        platform="darwin",
    )
    assert result.delivered is True
    assert result.channel == "macos-open"
    assert runs == [["/usr/bin/open", "http://127.0.0.1:9/approval/token"]]


def test_failed_browser_delivery_returns_approval_required_without_full_timeout(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return False

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    try:
        started = time.monotonic()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        elapsed = time.monotonic() - started
        assert elapsed < 5.0
        assert outcome.status == ApprovalStatus.PENDING.value
        assert outcome.approval_url is not None
        assert outcome.approval_url.startswith(f"http://{server.host}:{server.port}/")
        assert outcome.delivery_status == "not_delivered"
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING.value
        assert record.delivery_status == "not_delivered"
        assert outcome.request_id not in manager._browser_opened_request_ids
        outcome2 = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome2.status == ApprovalStatus.PENDING.value
        assert len(opened) >= 2
        assert outcome.request_id in opened[0]
        assert any(outcome2.request_id in url for url in opened)
        assert outcome2.request_id not in manager._browser_opened_request_ids
    finally:
        server.stop()
        store.close()


def test_per_request_browser_opens_distinct_pending_cards(tmp_path):
    """First and second pending approvals each open their own card URL."""

    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=False)
    try:
        first = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        second = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert first.request_id != second.request_id
        assert len(opened) == 2
        assert opened[0] == server.approval_url(first.request_id)
        assert opened[1] == server.approval_url(second.request_id)
        assert first.request_id in opened[0]
        assert second.request_id in opened[1]
        assert opened[0] != opened[1]
        assert "/pending/" in opened[0]
        assert "/pending/" in opened[1]
        assert server.approval_center_url() not in opened
        assert first.request_id in manager._browser_opened_request_ids
        assert second.request_id in manager._browser_opened_request_ids
        assert store.get_pending(first.request_id).delivery_status == "delivered"
        assert store.get_pending(second.request_id).delivery_status == "delivered"
    finally:
        server.stop()
        store.close()


def test_same_request_id_does_not_reopen_browser_after_successful_delivery(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=False)
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert len(opened) == 1
        again = manager._maybe_open_approval_browser(
            request_id=outcome.request_id,
            url=server.approval_url(outcome.request_id),
        )
        assert again is True
        assert len(opened) == 1
    finally:
        server.stop()
        store.close()


def test_non_tty_fallback_omits_session_token(tmp_path):
    opened: list[str] = []
    cli = io.StringIO()
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda url: opened.append(url) or True,
        wait_for_decision=False,
    )
    manager.cli_out = cli
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
            client_request_id="cli-1",
        )
        text = cli.getvalue()
        assert server.session_token not in text
        assert "session token omitted" in text
        assert outcome.approval_url is not None
        assert server.session_token in outcome.approval_url
        assert server.session_token in opened[0]
    finally:
        server.stop()
        store.close()


def test_successful_browser_delivery_keeps_synchronous_wait(tmp_path):
    """Truthy browser delivery must keep the synchronous wait path."""

    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    try:
        def approve_when_pending() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                rows = [
                    row
                    for row in store.list_records()
                    if row.status == ApprovalStatus.PENDING.value
                ]
                if rows:
                    server.submit_decision(rows[-1].request_id, "approve", "exact")
                    return
                time.sleep(0.02)

        threading.Thread(target=approve_when_pending, daemon=True).start()
        started = time.monotonic()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        elapsed = time.monotonic() - started
        assert outcome.status == ApprovalStatus.APPROVED.value
        assert elapsed < 5.0
        assert outcome.request_id in manager._browser_opened_request_ids
        assert len(opened) == 1
        assert outcome.request_id in opened[0]
        assert "/pending/" in opened[0]
        assert opened[0] == server.approval_url(outcome.request_id)
    finally:
        server.stop()
        store.close()


def test_explicit_deny_is_user_denied_not_timeout(tmp_path):
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda _url: True,
        wait_for_decision=True,
    )
    try:
        def deny_when_pending() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                rows = [
                    row
                    for row in store.list_records()
                    if row.status == ApprovalStatus.PENDING.value
                ]
                if rows:
                    server.submit_decision(rows[-1].request_id, "deny", "exact")
                    return
                time.sleep(0.02)

        threading.Thread(target=deny_when_pending, daemon=True).start()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.DENIED.value
        assert outcome.reason == "user_denied"
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.DENIED.value
        assert record.error_class != "approval_timeout"
    finally:
        server.stop()
        store.close()


def test_stale_foreign_runtime_manifest_is_not_reused(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=os.getpid(),
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("f" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    status = inspect_managed_approval_center(home)
    assert status.state == "stale"
    assert not manifest_runtime_matches_current(load_manifest(proxy_dir))


def test_matching_runtime_manifest_is_reused(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    token = "fixture-session-token-not-real"
    identity = current_approval_center_runtime_identity()
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=os.getpid(),
            started_at=int(time.time()),
            runtime_identity=identity,
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    status = inspect_managed_approval_center(home)
    assert status.state == "running"
    assert manifest_runtime_matches_current(load_manifest(proxy_dir))


def test_runtime_identity_changes_when_version_or_code_drifts(monkeypatch):
    """Same interpreter/package root must still diverge after in-place upgrade."""

    baseline = current_approval_center_runtime_identity()
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._package_version_token",
        lambda: "9.9.9-fixture-not-real",
    )
    version_drifted = current_approval_center_runtime_identity()
    assert version_drifted != baseline
    assert version_drifted.startswith("sha256:")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._package_version_token",
        lambda: "0.0.0-fixture",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._approval_center_code_fingerprint",
        lambda _root: "a" * 64,
    )
    code_drifted = current_approval_center_runtime_identity()
    assert code_drifted != baseline
    assert code_drifted != version_drifted
    assert code_drifted.startswith("sha256:")
    assert len(code_drifted) == len("sha256:") + 64
    assert not any(marker in code_drifted for marker in ("/", "\\", "Users", "home"))


def test_runtime_fingerprint_changes_when_evidence_dependency_drifts(tmp_path):
    """A detached center must not survive an in-place evidence contract update."""

    package_root = tmp_path / "agentveil_mcp_proxy"
    approval = package_root / "approval"
    evidence = package_root / "evidence"
    approval.mkdir(parents=True)
    evidence.mkdir(parents=True)
    (approval / "server.py").write_text("SERVER = 1\n", encoding="utf-8")
    store = evidence / "store.py"
    store.write_text("SCHEMA = 5\n", encoding="utf-8")

    before = _approval_center_code_fingerprint(package_root)
    store.write_text("SCHEMA = 6\n", encoding="utf-8")
    after = _approval_center_code_fingerprint(package_root)

    assert before != after


def test_lifecycle_lock_serializes_concurrent_processes(tmp_path):
    home = tmp_path / "home"
    (home / "mcp-proxy").mkdir(parents=True)
    log_path = tmp_path / "lock-log.txt"
    log_path.write_text("", encoding="utf-8")
    worker = tmp_path / "lock_worker.py"
    worker.write_text(
        """
import sys
import time
from pathlib import Path

from agentveil_mcp_proxy.approval.server import _ManagedCenterLifecycleLock

home = Path(sys.argv[1])
log_path = Path(sys.argv[2])
slot = sys.argv[3]
hold_seconds = float(sys.argv[4])

with _ManagedCenterLifecycleLock(home, timeout_seconds=10.0):
    previous = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    log_path.write_text(previous + f"enter-{slot}\\n", encoding="utf-8")
    time.sleep(hold_seconds)
    previous = log_path.read_text(encoding="utf-8")
    log_path.write_text(previous + f"exit-{slot}\\n", encoding="utf-8")
""",
        encoding="utf-8",
    )

    command = [sys.executable, str(worker), str(home), str(log_path)]
    proc_a = subprocess.Popen([*command, "a", "0.4"])
    proc_b = subprocess.Popen([*command, "b", "0.4"])
    assert proc_a.wait(timeout=15) == 0
    assert proc_b.wait(timeout=15) == 0

    log = log_path.read_text(encoding="utf-8").splitlines()
    assert len(log) == 4
    assert log[0].startswith("enter-")
    assert log[1].startswith("exit-")
    assert log[2].startswith("enter-")
    assert log[3].startswith("exit-")
    lock_path = home / "mcp-proxy" / "approval-center.lifecycle.lock"
    assert lock_path.exists()


def test_stale_lifecycle_lock_recovers(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    lock_path = proxy_dir / "approval-center.lifecycle.lock"
    lock_path.write_text("99999999\n", encoding="utf-8")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )

    spawned = {"count": 0}

    def spawn():
        spawned["count"] += 1
        token = "fixture-session-token-not-real"
        save_manifest(
            proxy_dir,
            ApprovalCenterManifest(
                schema_version=2,
                host="127.0.0.1",
                port=9,
                session_token=token,
                token_hash=token_hash_for(token),
                internal_register_token="fixture-internal-token-not-real",
                pid=os.getpid(),
                started_at=int(time.time()),
                runtime_identity=current_approval_center_runtime_identity(),
            ),
        )
        return SimpleNamespace(poll=lambda: None)

    def wait_for_running(home_path: Path, _deadline: float):
        return inspect_managed_approval_center(home_path)

    result = ensure_managed_approval_center_running(
        home=home,
        spawn=spawn,
        wait_for_running=wait_for_running,
    )
    assert result.started is True
    assert spawned["count"] == 1
    assert lock_path.exists()


def test_runtime_mismatch_reconcile_avoids_ephemeral_fallback(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=99999999,
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("f" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_owns_pid",
        lambda _home, _pid: False,
    )
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    held_servers: list[ApprovalServer] = []

    def fake_spawn(**_kwargs):
        replacement = ApprovalServer(
            port=0,
            evidence_store=store,
            internal_register_token="fixture-internal-token-not-real",
        )
        replacement.start()
        save_manifest(
            proxy_dir,
            ApprovalCenterManifest(
                schema_version=2,
                host=replacement.host,
                port=replacement.port,
                session_token=replacement.session_token,
                token_hash=token_hash_for(replacement.session_token),
                internal_register_token=replacement.internal_register_token,
                pid=os.getpid(),
                started_at=int(time.time()),
                runtime_identity=current_approval_center_runtime_identity(),
            ),
        )
        held_servers.append(replacement)
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.client.spawn_managed_approval_center_process",
        fake_spawn,
    )

    fallback_calls = 0

    def fallback_factory() -> ApprovalServer:
        nonlocal fallback_calls
        fallback_calls += 1
        server = ApprovalServer(
            port=0,
            evidence_store=store,
            internal_register_token="fixture-internal-token-not-real",
        )
        server.start()
        held_servers.append(server)
        return server

    without_reconcile = resolve_approval_server(
        proxy_dir,
        evidence_store=store,
        fallback_factory=fallback_factory,
    )
    assert fallback_calls == 1
    assert isinstance(without_reconcile, ApprovalServer)
    assert not isinstance(without_reconcile, RemoteApprovalServer)
    without_reconcile.stop()

    fallback_calls = 0
    reconcile_managed_approval_center_for_runtime(
        home=home,
        proxy_command=sys.executable,
    )
    resolved = resolve_approval_server(
        proxy_dir,
        evidence_store=store,
        fallback_factory=fallback_factory,
    )
    assert fallback_calls == 0
    assert isinstance(resolved, RemoteApprovalServer)
    assert manifest_runtime_matches_current(load_manifest(proxy_dir))
    resolved.stop()
    for server in held_servers:
        if server is not resolved:
            server.stop()
    store.close()


def test_fail_soft_response_excludes_sensitive_fields(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return False

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    other_url = server.approval_url("other-request-id")
    secret_internal = server.internal_register_token
    assert secret_internal
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        # Internal outcome may retain the operator URL for browser/TTY delivery.
        assert server.session_token in outcome.approval_url
        from agentveil_mcp_proxy.passthrough import _approval_required_error

        mcp_response = _approval_required_error(
            "call-1",
            reason="local_approval_required",
            approval_outcome=outcome,
        )
        serialized = json.dumps(mcp_response)
        assert "approval_url" not in mcp_response["error"]["data"]
        assert mcp_response["error"]["data"]["delivery_status"] == "not_delivered"
        assert "recovery_command" in mcp_response["error"]["data"]
        assert "approval-center open --record-id" in mcp_response["error"]["data"]["recovery_command"]
        assert server.session_token not in serialized
        assert f"/approval/{server.session_token}" not in serialized
        assert "csrf_token" not in serialized
        assert secret_internal not in serialized
        assert other_url not in serialized
        assert "internal_register_token" not in serialized
        assert opened
        assert server.session_token in opened[0]
        assert outcome.request_id in opened[0]
    finally:
        server.stop()
        store.close()


def test_unowned_pid_not_terminated_on_prepare(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    foreign_pid = os.getpid()
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=foreign_pid,
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("e" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_owns_pid",
        lambda _home, _pid: False,
    )

    def forbid_terminate(*_args, **_kwargs):
        raise AssertionError("must not terminate unowned pid")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.terminate_managed_approval_center_pid",
        forbid_terminate,
    )
    prepared = prepare_stale_managed_approval_center(home)
    assert prepared["prepared"] is True
    assert prepared["stopped"] is False
    assert load_manifest(proxy_dir) is None
    assert os.getpid() == foreign_pid
