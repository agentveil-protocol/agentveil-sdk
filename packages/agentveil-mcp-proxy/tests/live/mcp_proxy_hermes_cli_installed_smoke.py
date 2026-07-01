#!/usr/bin/env python3
"""P0.13b operator-assisted Hermes live gate.

This is not product acceptance by itself. Exit 0 only when a real Hermes CLI
run completes the bounded live scenario with evidence on disk.

Required operator setup:
- Real Hermes executable (AGENTVEIL_HERMES_BIN or hermes on PATH)
- Ephemeral LLM provider key in the operator shell (DEEPSEEK_API_KEY or OPENAI_API_KEY)
- AGENTVEIL_HERMES_LIVE_PROOF=1

During the run the operator must approve the risky write in Approval Center when
Hermes attempts the file creation through AgentVeil MCP.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentveil_mcp_proxy.agent_launcher import (  # noqa: E402
    launch_manifest_path,
    project_avp_home,
    runtime_route_path,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore  # noqa: E402
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata  # noqa: E402

LIVE_PROMPT = (
    "Create hermes-agentveil-proof.txt with content HERMES_AGENTVEIL_PROOF."
)
PROOF_FILENAME = "hermes-agentveil-proof.txt"
PROOF_CONTENT = "HERMES_AGENTVEIL_PROOF"
SENTINEL = "P0_13B_HERMES_CLI_LIVE_GATE"
SECRET_MARKERS = ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "sk-", "/Users/")


def _has_provider_key() -> bool:
    for key in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        value = os.environ.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _resolve_hermes_bin() -> str | None:
    configured = os.environ.get("AGENTVEIL_HERMES_BIN", "").strip()
    if configured and Path(configured).is_file():
        return configured
    found = shutil.which("hermes")
    return found if found else None


def _assert_bounded(text: str) -> None:
    for marker in SECRET_MARKERS:
        if marker.startswith("sk-"):
            continue
        assert marker not in text, f"bounded output leak: {marker!r}"
    for key in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        value = os.environ.get(key, "")
        if value:
            assert value not in text, f"provider key leaked into {key!r} output"


def main() -> int:
    if os.environ.get("AGENTVEIL_HERMES_LIVE_PROOF") != "1":
        print(
            "SKIP installed Hermes live proof: set AGENTVEIL_HERMES_LIVE_PROOF=1 for "
            "operator-assisted live gate",
            file=sys.stderr,
        )
        return 0

    hermes_bin = _resolve_hermes_bin()
    if hermes_bin is None:
        print(
            "HOLD: real Hermes executable not found; set AGENTVEIL_HERMES_BIN or install hermes",
            file=sys.stderr,
        )
        return 2

    if not _has_provider_key():
        print(
            "HOLD: set DEEPSEEK_API_KEY or OPENAI_API_KEY in the operator shell before live gate",
            file=sys.stderr,
        )
        return 2

    cli = shutil.which("agentveil-mcp-proxy")
    launch_cmd = [cli or sys.executable]
    if cli is None:
        launch_cmd.extend(["-m", "agentveil_mcp_proxy.cli"])

    with tempfile.TemporaryDirectory(prefix="avp-hermes-live-gate-") as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        completed = subprocess.run(
            [
                *launch_cmd,
                "launch",
                "--profile",
                "hermes-cli",
                "--project-dir",
                str(project),
                "--json",
                "--",
                hermes_bin,
                "chat",
                "-q",
                LIVE_PROMPT,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.stdout.strip():
            try:
                launch_payload = json.loads(completed.stdout.strip().splitlines()[-1])
            except json.JSONDecodeError:
                launch_payload = {}
        else:
            launch_payload = {}

        home = project_avp_home(project)
        manifest_text = ""
        route_text = ""
        if launch_manifest_path(home).is_file():
            manifest_text = launch_manifest_path(home).read_text(encoding="utf-8")
        if runtime_route_path(home).is_file():
            route_text = runtime_route_path(home).read_text(encoding="utf-8")
        bounded = "\n".join((completed.stdout, completed.stderr, manifest_text, route_text))
        _assert_bounded(bounded)

        proof_path = project / PROOF_FILENAME
        target_reached = False
        evidence_path = home / "mcp-proxy" / "evidence.sqlite"
        if evidence_path.is_file():
            with ApprovalEvidenceStore(evidence_path) as store:
                for record in store.list_records():
                    meta = parse_controlled_path_metadata(record)
                    if (
                        meta is not None
                        and meta.get("tool") == "write_file"
                        and meta.get("target_reached") is True
                    ):
                        target_reached = True
                        break

        ok = (
            completed.returncode == 0
            and proof_path.is_file()
            and proof_path.read_text(encoding="utf-8") == PROOF_CONTENT
            and target_reached
            and launch_payload.get("child_foreground") is True
        )
        summary = {
            "ok": ok,
            "launch_exit_code": completed.returncode,
            "child_foreground": launch_payload.get("child_foreground"),
            "child_exit_code": launch_payload.get("child_exit_code"),
            "proof_file_exists": proof_path.is_file(),
            "proof_content_match": proof_path.read_text(encoding="utf-8") == PROOF_CONTENT
            if proof_path.is_file()
            else False,
            "target_reached": target_reached,
            "hermes_bin_set": True,
            "provider_key_set": True,
            "prompt": LIVE_PROMPT,
        }
        rendered = json.dumps(summary, sort_keys=True)
        _assert_bounded(rendered)
        if not ok:
            print(completed.stdout, file=sys.stderr)
            print(completed.stderr, file=sys.stderr)
            print(f"{SENTINEL}_HOLD: {rendered}", file=sys.stderr)
            return 2
        print(f"{SENTINEL}_OK: {rendered}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
