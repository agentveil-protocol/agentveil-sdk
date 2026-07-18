"""Product-route CI / repo trust path proofs through the MCP proxy."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from conftest import operator_approval_url
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.passthrough import CI_REPO_UNTRUSTED_TEXT_RISK_MESSAGE

from mcp_fake_downstream import (
    ADVERSARIAL_CI_REPO_TEXT,
    ADVERSARIAL_CI_WORKFLOW_YAML,
    ADVERSARIAL_GITHUB_ISSUE_BODY,
    FAKE_CI_ENV_SECRET_VALUE,
    FAKE_GITHUB_SECRET_VALUE,
    ci_repo_target_snapshot,
    github_pack_tool_entries,
    github_target_reached,
    seed_ci_repo_target,
    write_github_downstream,
)


LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")
CSRF_RE = __import__("re").compile(r'name="csrf_token" value="([^"]+)"')
OWNER = "acme"
REPO = "demo-repo"


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _repo_args(content_root: Path, *, extra: dict | None = None) -> dict:
    payload = {"owner": OWNER, "repo": REPO, "repo_root": str(content_root)}
    if extra:
        payload.update(extra)
    return payload


def _tool_call(
    tool: str,
    content_root: Path,
    *,
    arguments: dict | None = None,
    call_id: str = "call-1",
) -> str:
    payload = _repo_args(content_root, extra=arguments)
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": payload},
    })


def _init_ci_repo_target(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    home = tmp_path / "home"
    content_root = tmp_path / "content"
    state_dir = tmp_path / "state"
    outcome_log = tmp_path / "ci-outcome.jsonl"
    downstream_log = tmp_path / "downstream.log"
    config_path = home / "mcp-proxy" / "config.json"
    downstream = write_github_downstream(
        tmp_path,
        state_dir,
        content_root,
        ci_repo=True,
    )
    init_proxy(
        home=home,
        plaintext=True,
        policy_pack="github",
        downstream_config={
            "name": "github",
            "command": sys.executable,
            "args": ["-u", str(downstream), str(state_dir), str(content_root)],
            "env": {
                "GITHUB_OUTCOME_LOG": str(outcome_log),
                "DOWNSTREAM_LOG": str(downstream_log),
            },
        },
    )
    return home, content_root, state_dir, outcome_log, downstream, config_path


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def _metadata_for_tool(home: Path, tool: str) -> dict:
    with _evidence_store(home) as store:
        matches = [
            parse_controlled_path_metadata(record)
            for record in store.list_records()
            if parse_controlled_path_metadata(record) is not None
            and parse_controlled_path_metadata(record).get("tool") == tool
        ]
    assert matches, f"expected metadata row for {tool!r}"
    return matches[-1]


def _executed_metadata_for_tool(home: Path, tool: str) -> dict:
    with _evidence_store(home) as store:
        for record in reversed(store.list_records()):
            if record.status != ApprovalStatus.EXECUTED.value:
                continue
            metadata = parse_controlled_path_metadata(record)
            if metadata is not None and metadata.get("tool") == tool:
                return metadata
    raise AssertionError(f"expected executed metadata row for {tool!r}")


def _set_role_authority(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["role_authority"] = {
        "mode": "enforce",
        "role": "implementer",
        "authority": "implement",
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)


class _StagedStdin(io.TextIOBase):
    def __init__(self, lines: list[str]) -> None:
        self._lines = [line if line.endswith("\n") else f"{line}\n" for line in lines]
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size not in (-1, 1):
            raise io.UnsupportedOperation("only single-character reads are supported")
        if self._line_index >= len(self._lines):
            return ""
        self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        char = line[self._char_index]
        self._char_index += 1
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            self._gate.clear()
        return char

    def release_next(self) -> None:
        self._gate.set()


def _approve_first_pending(home: Path, response: dict) -> str:
    pending_id = response["error"]["data"]["record_id"]
    approval_url = operator_approval_url(pending_id)
    with httpx.Client() as client:
        page = client.get(approval_url)
        page.raise_for_status()
        match = CSRF_RE.search(page.text)
        assert match is not None
        client.post(approval_url, data={
            "decision": "approve",
            "approval_scope": "exact",
            "csrf_token": match.group(1),
        }).raise_for_status()
    deadline = time.monotonic() + 5
    with _evidence_store(home) as store:
        record = store.get_pending(pending_id)
        while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
            time.sleep(0.02)
            record = store.get_pending(pending_id)
        assert record.status == ApprovalStatus.APPROVED.value
    return pending_id


def _block_avp_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("ci/repo trust path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def _assert_no_leaks(*parts: str) -> None:
    blob = "\n".join(parts)
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in blob, f"unexpected local path marker {marker!r}"
    for forbidden in (
        ADVERSARIAL_GITHUB_ISSUE_BODY,
        ADVERSARIAL_CI_REPO_TEXT,
        ADVERSARIAL_CI_WORKFLOW_YAML,
        FAKE_GITHUB_SECRET_VALUE,
        FAKE_CI_ENV_SECRET_VALUE,
    ):
        assert forbidden not in blob


@pytest.mark.parametrize("tool,extra_args", [
    ("list_workflows", {}),
    ("get_workflow", {}),
    ("list_ci_jobs", {}),
    ("get_ci_job", {}),
    ("get_package_metadata", {}),
    ("list_workflow_runs", {}),
    ("ci_repo_target_snapshot", {}),
])
def test_ci_repo_read_tools_reach_target_without_mutation(
    tmp_path,
    monkeypatch,
    tool: str,
    extra_args: dict,
):
    home, content_root, state_dir, outcome_log, _downstream, _config = _init_ci_repo_target(tmp_path)
    before = ci_repo_target_snapshot(state_dir)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(tool, content_root, arguments=extra_args, call_id=f"{tool}-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    assert ci_repo_target_snapshot(state_dir) == before
    response = _responses(out.getvalue())[0]
    assert "result" in response
    payload = json.loads(response["result"]["content"][0]["text"])
    assert "body" not in payload
    assert "secret_value" not in payload
    assert "yaml" not in json.dumps(payload).lower()
    assert github_target_reached(outcome_log, tool=tool)
    metadata = _metadata_for_tool(home, tool)
    assert metadata["policy_rule"] == "github-read"
    assert metadata["target_reached"] is True
    _assert_no_leaks(out.getvalue(), json.dumps(payload), json.dumps(metadata))


@pytest.mark.parametrize("tool,extra_args", [
    ("dispatch_workflow", {"workflow_run_id": 1}),
    ("publish_package", {}),
    ("deploy_release", {}),
    ("run_remote_command", {}),
    ("merge_pull_request", {"pull_number": 1}),
    ("create_release", {"tag_name": "v9.9.9"}),
    ("rerun_workflow", {"workflow_run_id": 1}),
    ("cancel_workflow", {"workflow_run_id": 1}),
])
def test_privileged_ci_repo_actions_gated_before_mutation(
    tmp_path,
    monkeypatch,
    tool: str,
    extra_args: dict,
):
    home, content_root, state_dir, outcome_log, _downstream, _config = _init_ci_repo_target(tmp_path)
    before = ci_repo_target_snapshot(state_dir)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(tool, content_root, arguments=extra_args, call_id=f"{tool}-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    assert ci_repo_target_snapshot(state_dir) == before
    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    assert (
        response["error"]["data"]["ci_repo_untrusted_text_risk_message"]
        == CI_REPO_UNTRUSTED_TEXT_RISK_MESSAGE
    )
    assert response["error"]["data"]["ci_repo_trust_surface_present"] is True
    assert not github_target_reached(outcome_log, tool=tool)
    metadata = _metadata_for_tool(home, tool)
    assert metadata["target_reached"] is False
    _assert_no_leaks(out.getvalue(), json.dumps(metadata))


def test_get_env_secret_blocked_before_target(tmp_path, monkeypatch):
    home, content_root, state_dir, outcome_log, _downstream, _config = _init_ci_repo_target(tmp_path)
    before = ci_repo_target_snapshot(state_dir)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "get_env_secret",
            content_root,
            arguments={"secret_name": "DEPLOY_TOKEN"},
            call_id="env-secret-1",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    assert ci_repo_target_snapshot(state_dir) == before
    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "blocked"  # claim-check: allow tested policy status; target_reached=false.
    assert not github_target_reached(outcome_log, tool="get_env_secret")
    metadata = _metadata_for_tool(home, "get_env_secret")
    assert metadata["policy_rule"] == "github-secrets-block"
    assert metadata["target_reached"] is False
    _assert_no_leaks(out.getvalue(), json.dumps(metadata))


def test_untrusted_ci_context_status_is_bounded(tmp_path, monkeypatch):
    home, content_root, _state_dir, _outcome_log, _downstream, _config = _init_ci_repo_target(tmp_path)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("untrusted_context_status", content_root, call_id="ctx-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["untrusted_text_surface_present"] is True
    assert payload["ci_repo_trust_surface_present"] is True
    assert payload["instruction_surface_risk_message"] == CI_REPO_UNTRUSTED_TEXT_RISK_MESSAGE
    _assert_no_leaks(out.getvalue(), json.dumps(payload))


def test_deploy_stays_gated_despite_adversarial_workflow_text(tmp_path, monkeypatch):
    home, content_root, state_dir, outcome_log, _downstream, _config = _init_ci_repo_target(tmp_path)
    before = ci_repo_target_snapshot(state_dir)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("deploy_release", content_root, call_id="deploy-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    assert ci_repo_target_snapshot(state_dir) == before
    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["untrusted_text_surface_present"] is True
    assert not github_target_reached(outcome_log, tool="deploy_release")
    _assert_no_leaks(out.getvalue())


def test_approved_dispatch_workflow_mutates_only_after_approval(tmp_path, monkeypatch):
    home, content_root, state_dir, outcome_log, _downstream, config_path = _init_ci_repo_target(tmp_path)
    _set_role_authority(config_path)
    before = ci_repo_target_snapshot(state_dir)
    run_count_before = before["workflow_run_count"]
    _block_avp_agent(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call("dispatch_workflow", content_root, arguments={"workflow_run_id": 1}, call_id="dispatch-pending"),
        _tool_call("dispatch_workflow", content_root, arguments={"workflow_run_id": 1}, call_id="dispatch-retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        assert first["error"]["data"]["status"] == "approval_required"
        assert ci_repo_target_snapshot(state_dir) == before
        pending_id = _approve_first_pending(home, first)
        staged_in.release_next()
        worker.join(timeout=10)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        assert "result" in responses[1]
        after = ci_repo_target_snapshot(state_dir)
        assert after["workflow_run_count"] == run_count_before + 1
        assert github_target_reached(outcome_log, tool="dispatch_workflow")
        metadata = _executed_metadata_for_tool(home, "dispatch_workflow")
        assert metadata["target_reached"] is True
        assert metadata["execution_status"] == ApprovalStatus.EXECUTED.value
        with _evidence_store(home) as store:
            retry_records = [
                record for record in store.list_records()
                if record.granted_by_request_id == pending_id
            ]
            assert len(retry_records) == 1
        _assert_no_leaks(client_out.getvalue(), json.dumps(metadata))
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_ci_repo_target_seeded_with_adversarial_fixtures(tmp_path):
    content_root = tmp_path / "content"
    state_dir = tmp_path / "state"
    seed_ci_repo_target(content_root, state_dir)
    assert (content_root / ".github" / "workflows" / "deploy.yml").is_file()
    assert (content_root / ".ci_repo_trust_manifest.json").is_file()
    snapshot = ci_repo_target_snapshot(state_dir)
    assert snapshot["workflow_count"] >= 1
    assert snapshot["ci_job_count"] >= 1
    assert snapshot["deploy_active"] is False


def test_ci_repo_pack_tools_advertised_by_downstream(tmp_path):
    content_root = tmp_path / "content"
    state_dir = tmp_path / "state"
    downstream = write_github_downstream(tmp_path, state_dir, content_root, ci_repo=True)
    proc = subprocess.run(
        [sys.executable, "-u", str(downstream), str(state_dir), str(content_root)],
        input=_json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout.strip())
    names = {item["name"] for item in payload["result"]["tools"]}
    assert names == {entry["name"] for entry in github_pack_tool_entries()}
