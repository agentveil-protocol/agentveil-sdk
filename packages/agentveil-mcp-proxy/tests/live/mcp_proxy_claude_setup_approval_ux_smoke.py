#!/usr/bin/env python3
"""Installed-path smoke for Claude Code setup read/approval UX (P0.1)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from installed_wheel_env import bootstrap_reexec, build_installed_runtime, clean_env

WRITE_PROBE = "approval-ui-smoke.txt"
READ_PROBE = "installed-read-probe.txt"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _tool_call(tool: str, arguments: dict, *, call_id: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str], input_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def _proxy_run(
    cli: Path,
    *,
    home: Path,
    env: dict[str, str],
    tool: str,
    arguments: dict,
    call_id: str,
) -> dict:
    completed = _run(
        [
            str(cli),
            "run",
            "--home",
            str(home),
            "--approval-ui-mode",
            "none",
        ],
        cwd=home.parent,
        env=env,
        input_text=_tool_call(tool, arguments, call_id=call_id),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"run failed for {tool}: rc={completed.returncode}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    lines = completed.stdout.splitlines()
    if not lines:
        raise RuntimeError(f"run returned no stdout for {tool}")
    return _responses(completed.stdout)[0]


def _assert_read_tool_allowed(response: dict, *, tool: str) -> None:
    if "error" in response:
        data = response["error"].get("data", {})
        raise AssertionError(
            f"{tool} should not require approval; got {response['error']!r}; data={data!r}"
        )
    assert "result" in response, response


def _assert_main_view_human_friendly(html: str) -> None:
    main_view, _, _ = html.partition('<details class="approval-proof-details">')
    assert WRITE_PROBE in main_view
    assert "write_file" in main_view
    assert "Write action" in main_view
    assert "Unknown risk" not in main_view
    assert "Approve</button>" in main_view
    assert "Deny</button>" in main_view
    assert "sha256:" not in main_view


def _assert_installed_events_show(cli: Path, *, home: Path, env: dict[str, str]) -> None:
    human = _run(
        [str(cli), "events", "show", "--home", str(home), "--last"],
        cwd=home.parent,
        env=env,
    )
    if human.returncode != 0:
        raise RuntimeError(
            f"events show --last failed: rc={human.returncode}\n"
            f"stdout={human.stdout}\nstderr={human.stderr}"
        )
    text = human.stdout
    assert "decision=approval_required" in text, text
    assert "tool=write_file" in text, text
    assert "events show --last --verify" in text, text
    assert "/proof" not in text, text
    assert "sha256:" not in text, text
    assert not text.lstrip().startswith("{"), text

    json_completed = _run(
        [str(cli), "events", "show", "--home", str(home), "--last", "--json"],
        cwd=home.parent,
        env=env,
    )
    if json_completed.returncode != 0:
        raise RuntimeError(
            f"events show --last --json failed: rc={json_completed.returncode}\n"
            f"stdout={json_completed.stdout}\nstderr={json_completed.stderr}"
        )
    payload = json.loads(json_completed.stdout)
    assert payload.get("event_count", 0) >= 1, payload
    write_events = [
        event for event in payload.get("events", [])
        if isinstance(event, dict) and event.get("tool") == "write_file"
    ]
    assert write_events, payload
    event = write_events[-1]
    assert event.get("decision") == "approval_required", event
    assert event.get("record_id"), event
    assert event.get("payload_hash", "").startswith("sha256:"), event

    verify_completed = _run(
        [str(cli), "events", "show", "--home", str(home), "--last", "--json", "--verify"],
        cwd=home.parent,
        env=env,
    )
    if verify_completed.returncode != 0:
        raise RuntimeError(
            f"events show --last --verify failed: rc={verify_completed.returncode}\n"
            f"stdout={verify_completed.stdout}\nstderr={verify_completed.stderr}"
        )
    verify_payload = json.loads(verify_completed.stdout)
    verify = verify_payload.get("verify")
    if not isinstance(verify, dict):
        raise AssertionError(f"events show --verify missing verify block: {verify_payload!r}")
    status = verify.get("status")
    if status not in {"not_available", "intact", "failed"}:
        raise AssertionError(f"unexpected verify status: {status!r}")


def _assert_proof_details_compact(html: str) -> None:
    proof_view, _, raw_tail = html.partition('<details class="approval-raw-evidence">')
    assert "Proof details" in proof_view
    assert "Decision" in proof_view
    assert "Why approval is required" in proof_view
    assert "Policy rule" in proof_view
    assert "Execution status" in proof_view
    assert "Target reached" in proof_view
    assert "Request id" in proof_view
    assert "Payload hash" in proof_view
    assert "Secret access: unknown" not in proof_view
    for unknown_row in (
        "Shell execution: unknown",
        "Package install: unknown",
        "Deploy/release: unknown",
        "Credential posture: unknown",
        "External network/send: unknown",
    ):
        assert unknown_row not in proof_view
    assert "Not applicable to this filesystem operation." in proof_view
    assert "Raw evidence" in raw_tail
    assert "Blast radius: Secret access" in raw_tail


def main() -> int:
    reexec_code = bootstrap_reexec(Path(__file__))
    if reexec_code is not None:
        return reexec_code

    env = clean_env()
    with tempfile.TemporaryDirectory(prefix="avp-claude-setup-approval-ux-") as tmp:
        install_root = Path(tmp) / "install"
        cli, _python = build_installed_runtime(install_root)
        project = Path(tmp) / "project"
        project.mkdir()
        (project / READ_PROBE).write_text("read-me\n", encoding="utf-8")

        setup_cmd = [
            str(cli),
            "setup",
            "claude-code",
            "--project-dir",
            str(project),
            "--yes",
            "--json",
        ]
        setup = _run(setup_cmd, cwd=project, env=env)
        if setup.returncode != 0:
            print(setup.stdout)
            print(setup.stderr, file=sys.stderr)
            return setup.returncode

        home = project / ".avp"
        if not (home / "mcp-proxy" / "config.json").is_file():
            raise RuntimeError("setup did not create proxy config")

        config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
        if config.get("policy", {}).get("id") != "filesystem":
            raise RuntimeError(f"expected filesystem policy, got {config.get('policy', {}).get('id')!r}")
        if config.get("fallback", {}).get("read") != "allow":
            raise RuntimeError(f"expected fallback.read=allow, got {config.get('fallback')!r}")

        for tool, args, call_id in (
            ("list_workspace", {}, "read-list"),
            ("read_file", {"path": READ_PROBE}, "read-file"),
            ("get_file_info", {"path": READ_PROBE}, "read-info"),
            ("instruction_surface_status", {}, "read-surface"),
            ("local_proof", {"last": 5, "verify": True}, "read-proof"),
        ):
            response = _proxy_run(cli, home=home, env=env, tool=tool, arguments=args, call_id=call_id)
            _assert_read_tool_allowed(response, tool=tool)

        write_response = _proxy_run(
            cli,
            home=home,
            env=env,
            tool="write_file",
            arguments={"path": WRITE_PROBE, "content": "probe\n"},
            call_id="write-pending",
        )
        if "error" not in write_response:
            raise AssertionError(f"write_file should require approval: {write_response!r}")
        data = write_response["error"].get("data", {})
        if data.get("status") != "approval_required":
            raise AssertionError(f"write_file expected approval_required, got {data!r}")
        approval_url = data.get("approval_url")
        if not isinstance(approval_url, str) or not approval_url:
            raise AssertionError(f"write_file missing approval_url in {data!r}")

        import httpx

        with httpx.Client() as client:
            html = client.get(approval_url, timeout=5.0).text
        _assert_main_view_human_friendly(html)
        _assert_proof_details_compact(html)
        assert "The agent wants to run write_file" in html
        assert "This decision will be recorded locally" in html
        assert "Local proof" not in html
        assert "approval-local-proof-command" not in html
        assert "Copy command" not in html
        assert "agentveil-mcp-proxy events show --last --verify" not in html
        assert "/proof" not in html
        proof_hint = data.get("proof_inspection_hint")
        if not isinstance(proof_hint, str) or "local_proof" not in proof_hint:
            raise AssertionError(f"write_file missing local_proof proof_inspection_hint in {data!r}")

        _assert_installed_events_show(cli, home=home, env=env)

        proof_response = _proxy_run(
            cli,
            home=home,
            env=env,
            tool="local_proof",
            arguments={"last": 5, "verify": True},
            call_id="local-proof",
        )
        proof_payload = json.loads(proof_response["result"]["content"][0]["text"])
        if proof_payload.get("status") != "ok":
            raise AssertionError(f"local_proof expected status ok: {proof_payload!r}")
        if not proof_payload.get("proof", {}).get("events"):
            raise AssertionError(f"local_proof missing proof events: {proof_payload!r}")
        events = proof_payload["proof"]["events"]
        write_proof = [
            event
            for event in events
            if event.get("tool") == "write_file" and event.get("decision") == "approval_required"
        ]
        if not write_proof:
            raise AssertionError(f"local_proof missing write_file approval_required event: {proof_payload!r}")

        print("P0.4B_CLAUDE_SETUP_APPROVAL_UX_AND_EVENTS_SHOW_SMOKE: ok")
        print(f"setup_cmd={' '.join(setup_cmd)}")
        print(f"read_tools=list_workspace,read_file,get_file_info,instruction_surface_status,local_proof")
        print(f"write_file_status={data.get('status')}")
        print(f"write_file_reason={data.get('reason')}")
        print(f"approval_url={approval_url}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
