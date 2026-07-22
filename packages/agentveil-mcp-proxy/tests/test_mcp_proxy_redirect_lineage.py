"""Verified redirect lineage: red/green contract for durable follow-up binding.

Proves that redirect_context is accepted only when durable server-side evidence
shows a permitted follow-up to the referenced original — not merely that a
matching playbook record exists.
"""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream, run_proxy
from agentveil_mcp_proxy.client_guidance import (
    build_hook_runtime_binding,
    parse_redirect_context_from_cursor_hook_output,
    resolve_live_hook_runtime_binding,
    write_hook_runtime_binding,
)
from agentveil_mcp_proxy.cursor_setup import build_hook_command
from agentveil_mcp_proxy.quickstart_filesystem import quickstart_sandbox_root_from_downstream_args
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.store import (
    ApprovalEvidenceDuplicateError,
    ApprovalEvidenceTransitionError,
)
from agentveil_mcp_proxy.role_doctor import (
    INVALID_REDIRECT_CONTEXT,
    REDIRECT_LINEAGE_MAX_AGE_SECONDS,
    canonical_project_workspace_root_hash,
    parse_redirect_context,
    project_scope_fingerprint,
    verify_redirect_lineage_facts,
)
from mcp_fake_downstream import tool_entry, write_downstream


SECRET = "SECRET_DOWNSTREAM_TOKEN"
DOWNSTREAM_SERVER = "filesystem"
_FIXED_SESSION_ID = "lineage-session-fixed-001"
_FIXED_CLIENT_ID = "lineage-client-fixed-001"


def _stabilize_manager_identity(monkeypatch) -> None:
    """Keep client/session identity stable across separate run_proxy invocations."""

    original_init = ApprovalManager.__init__

    def _init(self, *args, **kwargs):
        kwargs["session_id"] = _FIXED_SESSION_ID
        original_init(self, *args, **kwargs)
        self.client_id = _FIXED_CLIENT_ID
        self.session_id = _FIXED_SESSION_ID

    monkeypatch.setattr(proxy_cli, "ApprovalManager", ApprovalManager)
    monkeypatch.setattr(ApprovalManager, "__init__", _init)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _tool_call_args(tool: str, arguments: dict, *, call_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _set_quickstart_downstream(
    config_path: Path,
    *,
    sandbox_root: Path,
    extra_args: list[str] | None = None,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    downstream = dict(quickstart_filesystem_downstream(sandbox_root))
    if extra_args:
        downstream["args"] = list(downstream["args"]) + extra_args
    config["downstream"] = downstream
    _write_json(config_path, config)


def _seed_workspace_file(sandbox_root: Path, relative_path: str = "workspace/note.txt") -> None:
    target = sandbox_root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("seed\n", encoding="utf-8")


def _set_fake_downstream_without_provable_root(
    config_path: Path,
    tmp_path: Path,
    *,
    extra_dir: Path | None = None,
) -> None:
    script = write_downstream(
        tmp_path,
        filename="lineage_fake_ds.py",
        tools=[tool_entry("read_file"), tool_entry("write_file")],
    )
    args = ["-u", str(script)]
    if extra_dir is not None:
        args.append(str(extra_dir.resolve()))
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": args,
    }
    _write_json(config_path, config)


def _allow_policy(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-lineage",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(config_path, config)


def _approval_policy(config_path: Path, *, tool: str = "write_file") -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-lineage-approval",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": "write-approval",
            "source": "user",
            "decision": "approval",
            "risk_class": "write",
            "match": {"server": DOWNSTREAM_SERVER, "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _prepare_implementer_approval_home(
    tmp_path: Path,
    monkeypatch,
    *,
    fixture_id: str,
    target_path: str,
) -> tuple[Path, Path, Path, str]:
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    _patch_no_agent(monkeypatch)
    _stabilize_manager_identity(monkeypatch)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    target = sandbox / target_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("seed\n", encoding="utf-8")
    _set_quickstart_downstream(init.config_path, sandbox_root=sandbox)
    _allow_policy(init.config_path)
    return home, sandbox, target_path


def _create_pending_instruction_original(
    home: Path,
    *,
    call_id: str,
    target_path: str,
) -> str:
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": target_path, "content": "original"},
            call_id=call_id,
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(out.getvalue())[0]
    data = response["error"]["data"]
    assert data["status"] == "approval_required"
    original_request_id = data.get("record_id")
    assert isinstance(original_request_id, str) and original_request_id
    meta = _metadata_for(home, original_request_id)
    assert meta is not None
    assert meta.get("redirect_playbook_id") == "request_approval"
    return original_request_id


def _follow_up_write_with_redirect(
    home: Path,
    *,
    call_id: str,
    original_request_id: str,
    target_path: str,
    content: str = "follow-up",
) -> dict:
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {
                "path": target_path,
                "content": content,
                "redirect_context": {
                    "original_request_id": original_request_id,
                    "redirect_playbook_id": "request_approval",
                },
            },
            call_id=call_id,
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    return _responses(out.getvalue())[0]


def _evidence_path(home: Path) -> Path:
    return home / "mcp-proxy" / "evidence.sqlite"


def _evidence_rows(home: Path) -> list[dict]:
    path = _evidence_path(home)
    if not path.exists():
        return []
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM pending_approvals ORDER BY created_at, request_id"
        ).fetchall()
    return [dict(row) for row in rows]


def _metadata_for(home: Path, request_id: str) -> dict | None:
    for row in _evidence_rows(home):
        if row["request_id"] != request_id:
            continue
        raw = row.get("action_gate_metadata_jcs")
        if not isinstance(raw, str) or not raw:
            return None
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    return None


def _patch_no_agent(monkeypatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect lineage path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def _prepare_reviewer_home(
    tmp_path: Path,
    monkeypatch,
    *,
    fixture_id: str,
    stabilize_identity: bool = False,
    sandbox_root: Path | None = None,
) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    _patch_no_agent(monkeypatch)
    if stabilize_identity:
        _stabilize_manager_identity(monkeypatch)
    if sandbox_root is None:
        sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir(parents=True, exist_ok=True)
    _seed_workspace_file(sandbox_root)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    _set_quickstart_downstream(init.config_path, sandbox_root=sandbox_root)
    _allow_policy(init.config_path)
    return home, log_path, outcome_path


def _deny_original_write(
    home: Path,
    *,
    call_id: str = "orig-write",
    path: str = "workspace/note.txt",
) -> dict:
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": path, "content": "probe"},
            call_id=call_id,
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(out.getvalue())[0]
    assert "error" in response
    return response


def _follow_up_read(
    home: Path,
    *,
    call_id: str,
    original_request_id: str,
    path: str = "workspace/note.txt",
    playbook: str = "create_implementer_task",
    extra_context: dict | None = None,
) -> dict:
    context = {
        "original_request_id": original_request_id,
        "redirect_playbook_id": playbook,
    }
    if extra_context:
        context.update(extra_context)
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {"path": path, "redirect_context": context},
            call_id=call_id,
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    return _responses(out.getvalue())[0]


def _assert_redirect_rejected(response: dict) -> None:
    assert "error" in response
    data = response["error"]["data"]
    assert data["reason"] in {INVALID_REDIRECT_CONTEXT, "unsupported_redirect_playbook"}
    assert data["status"] in {"invalid_redirect_context", "blocked"}
    assert SECRET not in json.dumps(response)


def test_redirect_lineage_rejects_cross_client_reuse(tmp_path, monkeypatch):
    """Gap: original from client A must not authorize follow-up as client B."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-cross-client"
    )
    _deny_original_write(home)
    row = next(r for r in _evidence_rows(home) if r["request_id"] == "orig-write")
    assert row["client_id"]
    with sqlite3.connect(_evidence_path(home)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET client_id = ? WHERE request_id = ?",
            ("forged-other-client", "orig-write"),
        )
        conn.commit()
    response = _follow_up_read(home, call_id="follow-cross-client", original_request_id="orig-write")
    _assert_redirect_rejected(response)
    assert _pending_approval_prompts(home) == 0


def test_redirect_lineage_rejects_cross_session_reuse(tmp_path, monkeypatch):
    """Gap: separate proxy sessions must not share an original_request_id."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-cross-session"
    )
    _deny_original_write(home)
    # Second run_proxy creates a new ApprovalManager session_id.
    response = _follow_up_read(home, call_id="follow-cross-session", original_request_id="orig-write")
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_cross_project_scope_reuse(tmp_path, monkeypatch):
    """Different workspace roots with the same basename must not share scope."""

    sandbox_a = tmp_path / "parent-a" / "workspace"
    sandbox_b = tmp_path / "parent-b" / "workspace"
    sandbox_a.mkdir(parents=True)
    sandbox_b.mkdir(parents=True)

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path,
        monkeypatch,
        fixture_id="lineage-cross-scope",
        stabilize_identity=True,
        sandbox_root=sandbox_a,
    )
    _deny_original_write(home)
    meta = _metadata_for(home, "orig-write")
    assert meta is not None
    scope_a = meta.get("project_scope_fingerprint")
    assert scope_a
    facts = meta.get("session_bound_facts")
    assert isinstance(facts, dict)
    startup = facts.get("downstream_startup_fingerprint")
    assert isinstance(startup, str) and startup
    scope_b = project_scope_fingerprint(
        downstream_server=DOWNSTREAM_SERVER,
        downstream_startup_fingerprint=startup,
        project_workspace_root_hash=canonical_project_workspace_root_hash(sandbox_b),
    )
    assert scope_b is not None
    assert scope_a != scope_b

    config_path = home / "mcp-proxy" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    args = list(config["downstream"]["args"])
    config["downstream"]["args"] = args[:-1] + [str(sandbox_b.resolve())]
    _write_json(config_path, config)

    response = _follow_up_read(home, call_id="follow-cross-scope", original_request_id="orig-write")
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_wrong_target_intent(tmp_path, monkeypatch):
    """Gap: same playbook with a different resource identity must fail."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-wrong-target"
    )
    _deny_original_write(home, path="workspace/note.txt")
    response = _follow_up_read(
        home,
        call_id="follow-wrong-target",
        original_request_id="orig-write",
        path="workspace/other.txt",
    )
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_stale_original(tmp_path, monkeypatch):
    """Gap: expired originals must not authorize follow-ups."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-stale"
    )
    _deny_original_write(home)
    stale_ts = int(time.time()) - 10_000
    with sqlite3.connect(_evidence_path(home)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET created_at = ?, expires_at = ? WHERE request_id = ?",
            (stale_ts, stale_ts + 60, "orig-write"),
        )
        conn.commit()
    response = _follow_up_read(home, call_id="follow-stale", original_request_id="orig-write")
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_executed_or_target_reached_original(tmp_path, monkeypatch):
    """Gap: executed / target_reached originals cannot authorize follow-ups."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-reached"
    )
    _deny_original_write(home)
    meta = _metadata_for(home, "orig-write")
    assert meta is not None
    meta["target_reached"] = True
    meta["execution_status"] = "completed"
    with sqlite3.connect(_evidence_path(home)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET status = ?, action_gate_metadata_jcs = ? "
            "WHERE request_id = ?",
            ("executed", json.dumps(meta, separators=(",", ":")), "orig-write"),
        )
        conn.commit()
    response = _follow_up_read(home, call_id="follow-reached", original_request_id="orig-write")
    _assert_redirect_rejected(response)


def test_redirect_lineage_concurrent_claims_have_one_winner(tmp_path):
    """Two concurrent store claims must resolve to exactly one winner."""

    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    db = Path(init.config_path).parent / "evidence.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    scope_fp = "sha256:" + "d" * 64
    resource_hash = "sha256:" + "a" * 64
    with ApprovalEvidenceStore(db) as store:
        meta_jcs = json.dumps(
            {
                "redirect_role": "original",
                "redirect_playbook_id": "create_implementer_task",
                "target_reached": False,
                "original_request_id": "orig-concurrent",
                "project_scope_fingerprint": scope_fp,
            },
            separators=(",", ":"),
        )
        store.record_terminal_deny(
            request_id="orig-concurrent",
            session_id="session-concurrent",
            client_id="client-a",
            downstream_server="fake-downstream",
            tool_name="write_file",
            risk_class="write",
            resource_hash=resource_hash,
            payload_hash="sha256:" + "b" * 64,
            policy_id="redirect-lineage",
            policy_rule_id=None,
            policy_context_hash="c" * 64,
            created_at=int(time.time()),
            reason="role_authority_denied",
            action_gate_metadata_jcs=meta_jcs,
        )
        barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def _claim(follow_up_id: str) -> None:
            barrier.wait()
            try:
                store.claim_redirect_lineage(
                    "orig-concurrent",
                    follow_up_request_id=follow_up_id,
                    claimed_at=int(time.time()),
                    redirect_playbook_id="create_implementer_task",
                    project_scope_fingerprint=scope_fp,
                    expected_session_id="session-concurrent",
                    expected_client_id="client-a",
                    expected_downstream_server="fake-downstream",
                    expected_resource_hash=resource_hash,
                    playbook_target_bound=True,
                )
                with lock:
                    results.append(f"won:{follow_up_id}")
            except ApprovalEvidenceDuplicateError:
                with lock:
                    results.append(f"lost:{follow_up_id}")

        threads = [
            threading.Thread(target=_claim, args=("follow-a",)),
            threading.Thread(target=_claim, args=("follow-b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        winners = [item for item in results if item.startswith("won:")]
        losers = [item for item in results if item.startswith("lost:")]
        assert len(winners) == 1
        assert len(losers) == 1
        claim = store.get_redirect_lineage_claim("orig-concurrent")
        assert claim is not None
        assert claim["follow_up_request_id"] in {"follow-a", "follow-b"}


def test_redirect_lineage_claim_rejects_status_change_under_lock(tmp_path):
    """CAS rejects an original status flip before the claim."""

    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    db = Path(init.config_path).parent / "evidence.sqlite"
    scope_fp = "sha256:" + "e" * 64
    resource_hash = "sha256:" + "a" * 64
    with ApprovalEvidenceStore(db) as store:
        store.record_terminal_deny(
            request_id="orig-cas",
            session_id="session-cas",
            client_id="client-a",
            downstream_server="fake-downstream",
            tool_name="write_file",
            risk_class="write",
            resource_hash=resource_hash,
            payload_hash="sha256:" + "b" * 64,
            policy_id="redirect-lineage",
            policy_rule_id=None,
            policy_context_hash="c" * 64,
            created_at=int(time.time()),
            reason="role_authority_denied",
            action_gate_metadata_jcs=json.dumps(
                {
                    "redirect_role": "original",
                    "redirect_playbook_id": "create_implementer_task",
                    "target_reached": False,
                    "project_scope_fingerprint": scope_fp,
                },
                separators=(",", ":"),
            ),
        )
        with sqlite3.connect(db) as conn:
            conn.execute(
                "UPDATE pending_approvals SET status = ? WHERE request_id = ?",
                ("cancelled", "orig-cas"),
            )
            conn.commit()
        with pytest.raises(ApprovalEvidenceTransitionError):
            store.claim_redirect_lineage(
                "orig-cas",
                follow_up_request_id="follow-cas",
                claimed_at=int(time.time()),
                redirect_playbook_id="create_implementer_task",
                project_scope_fingerprint=scope_fp,
                expected_session_id="session-cas",
                expected_client_id="client-a",
                expected_downstream_server="fake-downstream",
                expected_resource_hash=resource_hash,
                playbook_target_bound=True,
            )
        assert store.get_redirect_lineage_claim("orig-cas") is None


@pytest.mark.parametrize(
    "status",
    ["cancelled", "error", "invalidated", "pending", "approved"],
)
def test_redirect_lineage_rejects_ineligible_original_status(tmp_path, monkeypatch, status):
    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id=f"lineage-status-{status}", stabilize_identity=True
    )
    _deny_original_write(home)
    with sqlite3.connect(_evidence_path(home)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET status = ? WHERE request_id = ?",
            (status, "orig-write"),
        )
        conn.commit()
    response = _follow_up_read(
        home,
        call_id=f"follow-status-{status}",
        original_request_id="orig-write",
    )
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_target_bound_missing_resource_hashes():
    error = verify_redirect_lineage_facts(
        original_redirect_role="original",
        original_playbook_id="create_implementer_task",
        claimed_playbook_id="create_implementer_task",
        target_reached=False,
        original_status="blocked",  # claim-check: allow denied-status negative fixture.
        original_client_id="client-a",
        follow_up_client_id="client-a",
        original_session_id="session-a",
        follow_up_session_id="session-a",
        original_downstream_server="fake-downstream",
        follow_up_downstream_server="fake-downstream",
        original_project_scope="sha256:" + "a" * 64,
        follow_up_project_scope="sha256:" + "a" * 64,
        original_resource_hash=None,
        follow_up_resource_hash=None,
        playbook_target_bound=True,
        created_at=int(time.time()),
        expires_at=None,
        now_timestamp=int(time.time()),
        already_claimed=False,
    )
    assert error == INVALID_REDIRECT_CONTEXT


def test_invalid_schema_follow_up_does_not_consume_lineage(tmp_path, monkeypatch):
    home, _log_path, _outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-schema", stabilize_identity=True
    )
    _deny_original_write(home)
    bad_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "extra": "forbidden",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-bad-schema",
        ))),
        out=bad_out,
        approval_ui_mode="none",
    ) == 0
    bad_response = _responses(bad_out.getvalue())[0]
    assert bad_response["error"]["data"]["status"] == "invalid_tool_arguments"
    with ApprovalEvidenceStore(_evidence_path(home)) as store:
        assert store.get_redirect_lineage_claim("orig-write") is None
    good = _follow_up_read(home, call_id="follow-after-schema", original_request_id="orig-write")
    assert "result" in good


def test_policy_block_follow_up_does_not_consume_lineage(tmp_path, monkeypatch):
    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-policy", stabilize_identity=True
    )
    config_path = home / "mcp-proxy" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-lineage-block-read",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": "block-read",
            "source": "user",
            "decision": "block",
            "risk_class": "read",
            "match": {"server": DOWNSTREAM_SERVER, "tool": "read_file"},
        }],
    }
    _write_json(config_path, config)
    _deny_original_write(home)
    # claim-check: allow policy-block negative regression assertion.
    blocked = _follow_up_read(home, call_id="follow-policy-block", original_request_id="orig-write")
    assert blocked["error"]["data"]["reason"] == "local_policy_block"  # claim-check: allow negative assertion.
    with ApprovalEvidenceStore(_evidence_path(home)) as store:
        assert store.get_redirect_lineage_claim("orig-write") is None
    config["policy"] = {
        "id": "redirect-lineage-allow",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(config_path, config)
    good = _follow_up_read(home, call_id="follow-after-policy", original_request_id="orig-write")
    assert "result" in good


def test_redirect_lineage_concurrent_handle_client_one_winner(tmp_path, monkeypatch):
    """Full run_proxy follow-ups racing one original produce a single winner."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-race", stabilize_identity=True
    )
    _deny_original_write(home)
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def _race(call_id: str) -> None:
        barrier.wait()
        response = _follow_up_read(
            home,
            call_id=call_id,
            original_request_id="orig-write",
        )
        with lock:
            results.append(response)

    threads = [
        threading.Thread(target=_race, args=("follow-race-a",)),
        threading.Thread(target=_race, args=("follow-race-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    winners = [item for item in results if "result" in item]
    losers = [item for item in results if "error" in item]
    assert len(winners) == 1
    assert len(losers) == 1
    assert losers[0]["error"]["data"]["reason"] == INVALID_REDIRECT_CONTEXT
    with ApprovalEvidenceStore(_evidence_path(home)) as store:
        claim = store.get_redirect_lineage_claim("orig-write")
        assert claim is not None
        assert claim["follow_up_request_id"] in {"follow-race-a", "follow-race-b"}
    assert winners[0]["result"]["content"]


@pytest.mark.parametrize("target_path", ["AGENTS.md", ".bashrc"])
def test_redirect_lineage_concurrent_early_approval_paths_one_pending(
    tmp_path,
    monkeypatch,
    target_path,
):
    """Instruction/persistence approvals claim lineage before registering cards."""

    home, _sandbox, path = _prepare_implementer_approval_home(
        tmp_path,
        monkeypatch,
        fixture_id=f"lineage-early-approval-{target_path.replace('.', '_')}",
        target_path=target_path,
    )
    original_id = _create_pending_instruction_original(
        home,
        call_id=f"orig-{target_path.replace('.', '_')}",
        target_path=path,
    )
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def _race(call_id: str) -> None:
        barrier.wait()
        response = _follow_up_write_with_redirect(
            home,
            call_id=call_id,
            original_request_id=original_id,
            target_path=path,
        )
        with lock:
            results.append(response)

    threads = [
        threading.Thread(target=_race, args=("follow-early-a",)),
        threading.Thread(target=_race, args=("follow-early-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    approval_required = [
        item for item in results
        if item.get("error", {}).get("data", {}).get("status") == "approval_required"
    ]
    rejected = [
        item for item in results
        if item.get("error", {}).get("data", {}).get("reason") == INVALID_REDIRECT_CONTEXT
    ]
    assert len(approval_required) == 1
    assert len(rejected) == 1
    assert _pending_approval_prompts(home) == 2
    with ApprovalEvidenceStore(_evidence_path(home)) as store:
        claim = store.get_redirect_lineage_claim(original_id)
        assert claim is not None
        assert claim["follow_up_request_id"] in {"follow-early-a", "follow-early-b"}


def test_project_scope_fingerprint_differs_for_same_basename_workspace(tmp_path):
    """Privacy-bounded startup preview alone must not define project identity."""

    root_a = tmp_path / "parent-a" / "workspace"
    root_b = tmp_path / "parent-b" / "workspace"
    root_a.mkdir(parents=True)
    root_b.mkdir(parents=True)
    hash_a = canonical_project_workspace_root_hash(root_a)
    hash_b = canonical_project_workspace_root_hash(root_b)
    assert hash_a is not None and hash_b is not None
    assert hash_a != hash_b
    startup = "sha256:" + "c" * 64
    fp_a = project_scope_fingerprint(
        downstream_server=DOWNSTREAM_SERVER,
        downstream_startup_fingerprint=startup,
        project_workspace_root_hash=hash_a,
    )
    fp_b = project_scope_fingerprint(
        downstream_server=DOWNSTREAM_SERVER,
        downstream_startup_fingerprint=startup,
        project_workspace_root_hash=hash_b,
    )
    assert fp_a is not None and fp_b is not None
    assert fp_a != fp_b


def test_unrelated_directory_arg_does_not_define_project_workspace(tmp_path):
    """Extra downstream args must not become project workspace identity."""

    from agentveil_mcp_proxy.cli import quickstart_filesystem_downstream
    from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough

    sandbox = tmp_path / "sandbox"
    cache_dir = tmp_path / "cache-output"
    sandbox.mkdir()
    cache_dir.mkdir()
    downstream = quickstart_filesystem_downstream(sandbox)
    args = tuple(downstream["args"]) + (str(cache_dir.resolve()),)

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=downstream["command"],
            args=args,
            name=downstream["name"],
        ),
    )
    assert passthrough._trusted_project_workspace_root() == sandbox.resolve()
    assert passthrough._project_workspace_root_hash() is not None

    fake_script = write_downstream(
        tmp_path,
        filename="lineage_cache_only_ds.py",
        tools=[tool_entry("read_file")],
    )
    cache_only = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(fake_script), str(cache_dir.resolve())),
            name="fake-downstream",
        ),
    )
    assert cache_only._trusted_project_workspace_root() is None
    assert cache_only._project_workspace_root_hash() is None
    assert quickstart_sandbox_root_from_downstream_args(list(args)) == sandbox.resolve()


def test_redirect_lineage_fails_closed_without_provable_workspace_root(
    tmp_path,
    monkeypatch,
):
    """Fake downstream without quickstart or explicit root must reject redirect follow-ups."""

    home, _log, _outcome = _prepare_reviewer_home(
        tmp_path,
        monkeypatch,
        fixture_id="lineage-no-root",
        stabilize_identity=True,
    )
    _deny_original_write(home)
    cache_dir = tmp_path / "cache-output"
    cache_dir.mkdir()
    _set_fake_downstream_without_provable_root(
        home / "mcp-proxy" / "config.json",
        tmp_path,
        extra_dir=cache_dir,
    )
    response = _follow_up_read(
        home,
        call_id="follow-no-root",
        original_request_id="orig-write",
    )
    _assert_redirect_rejected(response)


def test_redirect_lineage_rejects_forged_client_lineage_fields():
    """Gap: client-supplied lineage authorization fields must be rejected."""

    context, error = parse_redirect_context(
        {
            "redirect_context": {
                "original_request_id": "orig-write",
                "redirect_playbook_id": "create_implementer_task",
                "lineage_status": "verified",
                "redirect_parent_request_id": "forged-parent",
            }
        }
    )
    assert context is None
    assert error == INVALID_REDIRECT_CONTEXT


def test_redirect_lineage_rejects_unsupported_tool_transition(tmp_path, monkeypatch):
    """Gap: playbook-disallowed tool transitions must fail closed."""

    home, _log, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-bad-tool"
    )
    _deny_original_write(home)
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {
                "path": "workspace/note.txt",
                "content": "x",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-bad-tool",
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(out.getvalue())[0]
    _assert_redirect_rejected(response)


def test_direct_mcp_call_without_redirect_context_unchanged(tmp_path, monkeypatch):
    """Direct tools/call without redirect_context keeps existing allow behavior."""

    home, log_path, outcome_path = _prepare_reviewer_home(
        tmp_path, monkeypatch, fixture_id="lineage-direct"
    )
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {"path": "workspace/note.txt"},
            call_id="direct-read",
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(out.getvalue())[0]
    assert "result" in response
    assert "redirect_context" not in json.dumps(response)
    meta = _metadata_for(home, "direct-read")
    assert meta is None or meta.get("redirect_role") != "follow_up"


def test_valid_same_scope_redirect_records_verified_lineage(tmp_path, monkeypatch):
    """Post-fix: same client/session/scope follow-up is verified and stripped."""

    home, log_path, outcome_path = _prepare_reviewer_home(
        tmp_path,
        monkeypatch,
        fixture_id="lineage-valid",
        stabilize_identity=True,
    )
    _deny_original_write(home)
    response = _follow_up_read(home, call_id="follow-read", original_request_id="orig-write")
    assert "result" in response
    follow_meta = _metadata_for(home, "follow-read")
    assert follow_meta is not None
    assert follow_meta.get("redirect_role") == "follow_up"
    assert follow_meta.get("lineage_status") == "verified"
    assert follow_meta.get("original_request_id") == "orig-write"
    assert follow_meta.get("redirect_parent_request_id") == "orig-write"
    assert SECRET not in json.dumps(response)
    assert "/Users/" not in json.dumps(follow_meta)
    assert _pending_approval_prompts(home) == 0


def _pending_approval_prompts(home: Path) -> int:
    path = _evidence_path(home)
    if not path.exists():
        return 0
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()
    return int(row[0])


def _redirect_lineage_claim_count(home: Path) -> int:
    path = _evidence_path(home)
    if not path.exists():
        return 0
    with sqlite3.connect(path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM redirect_lineage_claims").fetchone()
    return int(row[0])


def _init_product_route_home(
    tmp_path: Path,
    monkeypatch,
    *,
    stabilize_identity: bool = True,
) -> tuple[Path, Path]:
    import os

    from agentveil_mcp_proxy.product_route import (
        PRODUCT_ROUTE_SETUP_PROFILE,
        PRODUCT_ROUTE_TOOL_CATALOG,
        build_product_route_downstream_config,
        initialize_product_route_profile,
    )

    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    initialize_product_route_profile(profile_root)
    downstream = build_product_route_downstream_config(profile_root)
    proxy_root = Path(__file__).resolve().parents[1]
    repo_root = proxy_root.parents[1]
    pythonpath = os.pathsep.join((str(repo_root), str(proxy_root)))
    env = dict(downstream.get("env", {}))
    if env.get("PYTHONPATH"):
        pythonpath = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
    env["PYTHONPATH"] = pythonpath
    downstream["env"] = env
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        role_preset="implementer",
        policy_pack="product_route",
        setup_profile=PRODUCT_ROUTE_SETUP_PROFILE,
        downstream_config=downstream,
    )
    _patch_no_agent(monkeypatch)
    if stabilize_identity:
        _stabilize_manager_identity(monkeypatch)
    assert len(PRODUCT_ROUTE_TOOL_CATALOG) == 71
    return home, profile_root


def _set_wait_for_decision(home: Path) -> None:
    config_path = home / "mcp-proxy" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    approval = config.get("approval")
    if not isinstance(approval, dict):
        approval = {}
        config["approval"] = approval
    approval["wait_for_decision"] = True
    _write_json(config_path, config)


class _QueuedStdin(io.TextIOBase):
    """Serve an initial bootstrap line, then block until more lines are queued."""

    def __init__(self, bootstrap_line: str) -> None:
        self._lines = [bootstrap_line]
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()
        self._closed = False

    def queue_line(self, message: dict) -> None:
        self._lines.append(_json_line(message))
        self._gate.set()

    def close_writer(self) -> None:
        self._closed = True
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size == 0:
            return ""
        while True:
            if self._line_index >= len(self._lines):
                if self._closed:
                    return ""
                self._gate.clear()
                if not self._gate.wait(timeout=30):
                    return ""
                continue
            if self._char_index == 0:
                self._gate.wait(timeout=30)
            if self._line_index >= len(self._lines):
                continue
            line = self._lines[self._line_index]
            if size < 0:
                chunk = line[self._char_index :]
                self._line_index += 1
                self._char_index = 0
                return chunk
            chunk = line[self._char_index : self._char_index + size]
            self._char_index += len(chunk)
            if self._char_index >= len(line):
                self._line_index += 1
                self._char_index = 0
            return chunk


class _StagedStdin(io.TextIOBase):
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size == 0:
            return ""
        if self._line_index >= len(self._lines):
            return ""
        if self._char_index == 0:
            self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        if size < 0:
            chunk = line[self._char_index :]
            self._line_index += 1
            self._char_index = 0
            if self._line_index < len(self._lines):
                self._gate.clear()
            return chunk
        chunk = line[self._char_index : self._char_index + size]
        self._char_index += len(chunk)
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            if self._line_index < len(self._lines):
                self._gate.clear()
        return chunk

    def release_next(self) -> None:
        self._gate.set()


def _install_operator_browser_capture(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    opened: list[str] = []

    def capture_open(url: str) -> bool:
        opened.append(url)
        return False

    monkeypatch.setattr("webbrowser.open", capture_open)
    return opened


def _wait_operator_pending_url(opened: list[str], request_id: str, *, deadline: float) -> str:
    while time.monotonic() < deadline:
        for url in opened:
            if request_id in url and "/pending/" in url:
                return url
        time.sleep(0.02)
    raise AssertionError(f"pending URL for {request_id} not opened; saw={opened!r}")


def _get_csrf(client: httpx.Client, url: str) -> str:
    page = client.get(url)
    page.raise_for_status()
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None, page.text
    return match.group(1)


def _post_decision(client: httpx.Client, url: str, *, decision: str, csrf: str) -> httpx.Response:
    return client.post(
        url,
        data={"decision": decision, "approval_scope": "exact", "csrf_token": csrf},
    )


def _run_installed_cursor_hook(
    *,
    home: Path,
    workspace: Path,
    evidence_path: Path,
    target_path: str = "lineage-probe.txt",
    content: str = "probe-body",
) -> dict[str, str]:
    payload = {
        "hook_event": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"path": target_path, "contents": content},
    }
    command = build_hook_command(
        python=sys.executable,
        workspace=workspace,
        home=home,
        evidence_path=evidence_path,
        hook_event="preToolUse",
    )
    proc = subprocess.run(
        command,
        shell=True,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    hook_output = json.loads(proc.stdout)
    redirect_context = parse_redirect_context_from_cursor_hook_output(hook_output)
    assert redirect_context is not None
    assert redirect_context["redirect_playbook_id"] == "request_approval"
    return redirect_context


def _start_live_product_route_proxy(
    home: Path,
    client_in: io.TextIOBase,
    *,
    approval_ui_mode: str = "none",
) -> tuple[threading.Thread, io.StringIO]:
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode=approval_ui_mode,
        ),
        daemon=True,
    )
    worker.start()
    return worker, client_out


def _wait_for_response_count(client_out: io.StringIO, count: int, *, deadline: float) -> list[dict]:
    while time.monotonic() < deadline:
        responses = _responses(client_out.getvalue())
        if len(responses) >= count:
            return responses
        time.sleep(0.02)
    raise AssertionError(
        f"expected {count} responses, got {len(_responses(client_out.getvalue()))}: "
        f"{client_out.getvalue()!r}"
    )


def _live_binding_exists(home: Path) -> bool:
    bindings_dir = home / "mcp-proxy" / "hook_runtime_bindings"
    if not bindings_dir.is_dir():
        return False
    return len(list(bindings_dir.glob("*.json"))) == 1


def _product_route_write_target(profile_root: Path, relative_path: str) -> Path:
    return profile_root / "workspace" / relative_path


_PRODUCT_ROUTE_PROBE_PATH = "lineage-probe.txt"
_PRODUCT_ROUTE_PROBE_CONTENT = "probe-body"


def test_product_route_native_hook_registers_durable_origin_and_verified_follow_up(
    tmp_path,
    monkeypatch,
) -> None:
    """Live proxy + installed hook shape: deny → agent surface → verified follow-up."""

    home, profile_root = _init_product_route_home(tmp_path, monkeypatch)
    workspace = profile_root / "workspace"
    evidence_path = workspace / "hook-evidence.jsonl"
    deferred_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(home, deferred_in)
    deadline = time.monotonic() + 15.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        assert _live_binding_exists(home)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PRODUCT_ROUTE_PROBE_PATH,
            content=_PRODUCT_ROUTE_PROBE_CONTENT,
        )
        original_id = redirect_context["original_request_id"]
        original_meta = _metadata_for(home, original_id)
        assert original_meta is not None
        assert original_meta.get("redirect_role") == "original"
        assert original_meta.get("redirect_playbook_id") == "request_approval"
        deferred_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        follow_response = _wait_for_response_count(client_out, 2, deadline=deadline)[1]
        follow_data = follow_response["error"]["data"]
        assert follow_data["status"] == "approval_required"
        follow_request_id = follow_data.get("record_id")
        assert isinstance(follow_request_id, str) and follow_request_id
        follow_meta = _metadata_for(home, follow_request_id)
        assert follow_meta is not None
        assert follow_meta.get("redirect_role") == "follow_up"
        assert follow_meta.get("lineage_status") == "verified"
        assert follow_meta.get("original_request_id") == original_id
        assert _redirect_lineage_claim_count(home) == 1
        assert _pending_approval_prompts(home) == 1
    finally:
        worker.join(timeout=2)


def test_product_route_hook_follow_up_replay_does_not_create_new_card(
    tmp_path,
    monkeypatch,
) -> None:
    home, profile_root = _init_product_route_home(tmp_path, monkeypatch)
    workspace = profile_root / "workspace"
    evidence_path = workspace / "hook-evidence.jsonl"
    deferred_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(home, deferred_in)
    deadline = time.monotonic() + 15.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PRODUCT_ROUTE_PROBE_PATH,
            content=_PRODUCT_ROUTE_PROBE_CONTENT,
        )
        deferred_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        _wait_for_response_count(client_out, 2, deadline=deadline)
        assert _pending_approval_prompts(home) == 1
        deferred_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-replay",
        ))
        replay_response = _wait_for_response_count(client_out, 3, deadline=deadline)[2]
        _assert_redirect_rejected(replay_response)
        assert _pending_approval_prompts(home) == 1
        assert not _product_route_write_target(profile_root, _PRODUCT_ROUTE_PROBE_PATH).exists()
        target = _product_route_write_target(profile_root, _PRODUCT_ROUTE_PROBE_PATH)
        assert not target.exists()
    finally:
        worker.join(timeout=2)


def test_product_route_stopped_proxy_binding_is_not_actionable(
    tmp_path,
    monkeypatch,
) -> None:
    home, profile_root = _init_product_route_home(tmp_path, monkeypatch)
    workspace = profile_root / "workspace"
    queued_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(home, queued_in)
    deadline = time.monotonic() + 10.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        assert _live_binding_exists(home)
    finally:
        queued_in.close_writer()
        worker.join(timeout=10)
    assert not _live_binding_exists(home)
    hook_out = io.StringIO()
    from agentveil_mcp_proxy import cursor_hooks

    cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "tool_input": {"path": "lineage-probe.txt", "contents": "probe-body"},
        },
        workspace=workspace,
        home=home,
        out=hook_out,
    )
    payload = json.loads(hook_out.getvalue())
    assert parse_redirect_context_from_cursor_hook_output(payload) is None


def test_product_route_follow_up_approve_executes_once(
    tmp_path,
    monkeypatch,
) -> None:
    home, profile_root = _init_product_route_home(
        tmp_path,
        monkeypatch,
        stabilize_identity=False,
    )
    workspace = profile_root / "workspace"
    evidence_path = workspace / "hook-evidence.jsonl"
    target = _product_route_write_target(profile_root, _PRODUCT_ROUTE_PROBE_PATH)
    _set_wait_for_decision(home)
    opened = _install_operator_browser_capture(monkeypatch)
    queued_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(
        home,
        queued_in,
        approval_ui_mode="browser",
    )
    deadline = time.monotonic() + 20.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PRODUCT_ROUTE_PROBE_PATH,
            content=_PRODUCT_ROUTE_PROBE_CONTENT,
        )
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        follow_response = _wait_for_response_count(client_out, 2, deadline=deadline)[1]
        pending_id = follow_response["error"]["data"]["record_id"]
        approval_url = _wait_operator_pending_url(opened, pending_id, deadline=deadline)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            _post_decision(client, approval_url, decision="approve", csrf=csrf).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.APPROVED.value
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {"path": _PRODUCT_ROUTE_PROBE_PATH, "content": _PRODUCT_ROUTE_PROBE_CONTENT},
            call_id="retry-write",
        ))
        retry_response = _wait_for_response_count(client_out, 3, deadline=deadline)[2]
        assert "result" in retry_response
        assert _pending_approval_prompts(home) == 0
        assert target.is_file()
        assert target.read_text(encoding="utf-8") == _PRODUCT_ROUTE_PROBE_CONTENT
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-replay-after-approve",
        ))
        replay_response = _wait_for_response_count(client_out, 4, deadline=deadline)[3]
        _assert_redirect_rejected(replay_response)
        assert target.read_text(encoding="utf-8") == _PRODUCT_ROUTE_PROBE_CONTENT
        assert _pending_approval_prompts(home) == 0
    finally:
        queued_in.close_writer()
        worker.join(timeout=15)


def test_product_route_follow_up_deny_does_not_execute(
    tmp_path,
    monkeypatch,
) -> None:
    home, profile_root = _init_product_route_home(
        tmp_path,
        monkeypatch,
        stabilize_identity=False,
    )
    workspace = profile_root / "workspace"
    evidence_path = workspace / "hook-evidence.jsonl"
    target = _product_route_write_target(profile_root, _PRODUCT_ROUTE_PROBE_PATH)
    _set_wait_for_decision(home)
    opened = _install_operator_browser_capture(monkeypatch)
    queued_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(
        home,
        queued_in,
        approval_ui_mode="browser",
    )
    deadline = time.monotonic() + 20.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PRODUCT_ROUTE_PROBE_PATH,
            content=_PRODUCT_ROUTE_PROBE_CONTENT,
        )
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        follow_response = _wait_for_response_count(client_out, 2, deadline=deadline)[1]
        pending_id = follow_response["error"]["data"]["record_id"]
        approval_url = _wait_operator_pending_url(opened, pending_id, deadline=deadline)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            _post_decision(client, approval_url, decision="deny", csrf=csrf).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.DENIED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.DENIED.value
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {"path": _PRODUCT_ROUTE_PROBE_PATH, "content": _PRODUCT_ROUTE_PROBE_CONTENT},
            call_id="retry-write",
        ))
        retry_response = _wait_for_response_count(client_out, 3, deadline=deadline)[2]
        assert retry_response["error"]["data"]["reason"] == "user_denied"
        assert _pending_approval_prompts(home) == 0
        assert not target.exists()
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PRODUCT_ROUTE_PROBE_PATH,
                "content": _PRODUCT_ROUTE_PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-replay-after-deny",
        ))
        replay_response = _wait_for_response_count(client_out, 4, deadline=deadline)[3]
        _assert_redirect_rejected(replay_response)
        assert not target.exists()
        assert _pending_approval_prompts(home) == 0
    finally:
        queued_in.close_writer()
        worker.join(timeout=15)


def test_product_route_direct_write_without_redirect_context_has_no_verified_lineage(
    tmp_path,
    monkeypatch,
) -> None:
    """Direct MCP write_file without redirect_context keeps ordinary approval behavior."""

    home, _profile_root = _init_product_route_home(tmp_path, monkeypatch)
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "direct.txt", "content": "body"},
            call_id="direct-write",
        ))),
        out=out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    meta = _metadata_for(home, "direct-write")
    assert meta is None or meta.get("lineage_status") != "verified"
    assert _redirect_lineage_claim_count(home) == 0


def test_live_binding_survives_past_max_age_while_owner_lease_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redirect_hook_contract_fixtures import init_redirect_contract_home, publish_live_hook_binding
    from agentveil_mcp_proxy import cursor_hooks

    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    binding_path = home / "mcp-proxy" / "hook_runtime_bindings" / (
        f"{fixture.owner_pid}-{fixture.instance_token}.json"
    )
    payload = json.loads(binding_path.read_text(encoding="utf-8"))
    payload["written_at"] = int(time.time()) - REDIRECT_LINEAGE_MAX_AGE_SECONDS - 60
    binding_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    try:
        assert resolve_live_hook_runtime_binding(home) is not None
        out = io.StringIO()
        cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "note.txt", "contents": "hello"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        hook_output = json.loads(out.getvalue())
        assert parse_redirect_context_from_cursor_hook_output(hook_output) is not None
    finally:
        fixture.lease.close()


def test_stale_unheld_binding_is_not_actionable(tmp_path: Path) -> None:
    from redirect_hook_contract_fixtures import init_redirect_contract_home, publish_live_hook_binding

    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    fixture.lease.close()
    assert resolve_live_hook_runtime_binding(home) is None


def test_two_simultaneous_live_bindings_are_ambiguous(tmp_path: Path) -> None:
    from redirect_hook_contract_fixtures import CONTRACT_SESSION_ID, init_redirect_contract_home
    from agentveil_mcp_proxy import cursor_hooks
    from agentveil_mcp_proxy.approval.server import build_owner_client_id, publish_owner_claim

    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    claim_dir = home / "mcp-proxy" / "owner_claims"
    pid = os.getpid()
    lease_a = publish_owner_claim(
        claim_dir,
        pid=pid,
        instance_token="binding-a",
        session_id=f"{CONTRACT_SESSION_ID}-a",
    )
    lease_b = publish_owner_claim(
        claim_dir,
        pid=pid,
        instance_token="binding-b",
        session_id=f"{CONTRACT_SESSION_ID}-b",
    )
    for token, session_id in (("binding-a", f"{CONTRACT_SESSION_ID}-a"), ("binding-b", f"{CONTRACT_SESSION_ID}-b")):
        binding = build_hook_runtime_binding(
            owner_pid=pid,
            instance_token=token,
            session_id=session_id,
            client_id=build_owner_client_id("filesystem", pid=pid, instance_token=token),
            downstream=downstream,
        )
        assert binding is not None
        write_hook_runtime_binding(home, binding)
    try:
        assert resolve_live_hook_runtime_binding(home) is None
        out = io.StringIO()
        cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "note.txt", "contents": "hello"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        assert parse_redirect_context_from_cursor_hook_output(json.loads(out.getvalue())) is None
    finally:
        lease_a.close()
        lease_b.close()
