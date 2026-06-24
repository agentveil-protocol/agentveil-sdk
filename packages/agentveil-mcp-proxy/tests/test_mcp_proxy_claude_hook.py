"""Tests for agentveil_mcp_proxy.claude_hook (P10D.14 S1).

Covers the seven spec cases (Write/Edit deny, Bash deny, read allow,
MCP write deny, MCP read allow, evidence bounded, unknown maps to deny)
plus three implementer clarifications (sentinel-based privacy, explicit
ASK_BACKEND deny-fallback semantics, JSONL append correctness).
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from agentveil_mcp_proxy import claude_hook
from agentveil_mcp_proxy.claude_hook import (
    CLAUDE_SERVER_LABEL,
    HookDecision,
    _bounded_input_ref,
    build_evidence_record,
    build_tool_call_context,
    classify_claude_tool,
    decide,
    default_hook_policy,
    default_proxy_config_for_hook,
    format_hook_output,
    main,
    process_hook,
)
from agentveil_mcp_proxy.policy import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    ProxyConfig,
    RiskClass,
)


# ----- helpers ---------------------------------------------------------------


def _payload(tool_name: str, tool_input: dict | None = None, **extra) -> dict:
    return {
        "session_id": extra.get("session_id", "test-session"),
        "cwd": extra.get("cwd", "/tmp/probe"),
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
    }


# ----- classifier basics -----------------------------------------------------


@pytest.mark.parametrize(
    "tool_name,expected_risk",
    [
        ("Write", RiskClass.WRITE),
        ("Edit", RiskClass.WRITE),
        ("MultiEdit", RiskClass.WRITE),
        ("NotebookEdit", RiskClass.WRITE),
        ("Read", RiskClass.READ),
        ("LS", RiskClass.READ),
        ("Glob", RiskClass.READ),
        ("Grep", RiskClass.READ),
        ("WebSearch", RiskClass.READ),
        ("WebFetch", RiskClass.READ),
    ],
)
def test_classify_claude_builtin_tools(tool_name: str, expected_risk: RiskClass) -> None:
    assert classify_claude_tool(tool_name, {}) is expected_risk


@pytest.mark.parametrize(
    "command,expected_risk",
    [
        # Allowlist read-only commands -> READ
        ("ls -la", RiskClass.READ),
        ("cat /tmp/x.txt", RiskClass.READ),
        ("pwd", RiskClass.READ),
        ("grep foo /tmp/x", RiskClass.READ),
        ("find . -name '*.py'", RiskClass.READ),
        # Mutation operators on otherwise-read-looking commands -> WRITE
        ("echo hello > /tmp/out.txt", RiskClass.WRITE),
        ("touch /tmp/x", RiskClass.WRITE),
        ("mv /tmp/a /tmp/b", RiskClass.WRITE),
        # Destructive -> DESTRUCTIVE
        ("rm /tmp/x", RiskClass.DESTRUCTIVE),
        ("rm -rf /tmp/probe", RiskClass.DESTRUCTIVE),
        ("rmdir /tmp/probe", RiskClass.DESTRUCTIVE),
    ],
)
def test_classify_bash_by_command(command: str, expected_risk: RiskClass) -> None:
    assert classify_claude_tool("Bash", {"command": command}) is expected_risk


# ----- corrective: Bash deny fallback for arbitrary interpreters / mutations --


@pytest.mark.parametrize(
    "command",
    [
        # Arbitrary interpreters can write to filesystem without matching
        # any mutation token. They MUST NOT classify as READ.
        "python3 -c \"open('owned.txt','w').write('x')\"",
        "python -c 'import os; os.remove(\"x\")'",
        "node -e 'require(\"fs\").writeFileSync(\"x\",\"y\")'",
        "ruby -e 'File.write(\"x\",\"y\")'",
        # sed -i / perl -pi in-place edits — caught by mutation tokens
        "sed -i 's/foo/bar/' file",
        "perl -pi -e 's/foo/bar/' file",
        # git mutation subcommands — caught by git allowlist
        "git checkout main",
        "git reset --hard HEAD~1",
        "git clean -fd",
        "git push origin main",
        "git commit -m 'x'",
        "git add .",
        # awk, xargs, eval, source — not on allowlist, must not auto-allow
        "awk '{print}' /etc/passwd",
        "xargs -I {} echo {}",
        "eval 'rm x'",
        "source ~/.bashrc",
        # interactive shells — not on allowlist
        "bash -c 'echo x > y'",
        "zsh -c 'rm x'",
    ],
)
def test_classify_bash_fail_closed_for_non_allowlisted(command: str) -> None:
    """Anything not unambiguously read-only must be non-READ."""
    risk = classify_claude_tool("Bash", {"command": command})
    assert risk is not RiskClass.READ, (
        f"Bash command {command!r} should NOT classify as READ; got {risk}"
    )


@pytest.mark.parametrize("command", ["git status", "git status -s", "git diff", "git diff --stat"])
def test_classify_bash_git_readonly_subcommands_allowed(command: str) -> None:
    assert classify_claude_tool("Bash", {"command": command}) is RiskClass.READ


def test_classify_bash_empty_command_is_unknown() -> None:
    assert classify_claude_tool("Bash", {"command": ""}) is RiskClass.UNKNOWN
    assert classify_claude_tool("Bash", {"command": "   "}) is RiskClass.UNKNOWN
    assert classify_claude_tool("Bash", {}) is RiskClass.UNKNOWN


# ----- corrective-2: shell composition uses deny fallback -------------------

# The four exact repro commands the reviewer found that bypassed the
# first-token allowlist (read-looking first token + hidden mutation).
_COMPOSITION_REPRO = [
    "echo $(python3 -c \"open('owned.txt','w').write('x')\")",
    "ls | python3 -c \"open('owned.txt','w').write('x')\"",
    "cat `python3 -c \"open('owned.txt','w').write('x')\"`",
    "echo hi; python3 -c \"open('owned.txt','w').write('x')\"",
]


@pytest.mark.parametrize("command", _COMPOSITION_REPRO)
def test_corrective2_composition_repro_not_read(command: str) -> None:
    """Reviewer repro: these read-looking commands hid a mutation. Must NOT
    classify as READ."""
    risk = classify_claude_tool("Bash", {"command": command})
    assert risk is not RiskClass.READ, f"{command!r} classified READ ({risk})"


@pytest.mark.parametrize("command", _COMPOSITION_REPRO)
def test_corrective2_composition_repro_denied_end_to_end(command: str) -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": command}), engine)
    assert decision.hook_action == "deny", (
        f"{command!r} must deny; got {decision.hook_action} "
        f"(risk={decision.evaluation.risk_class.value})"
    )


@pytest.mark.parametrize(
    "command",
    [
        "echo $(whoami)",            # command substitution
        "echo `whoami`",            # backtick substitution
        "ls | grep foo",            # pipe
        "echo a; echo b",           # semicolon chain
        "true && echo ok",          # && chain
        "false || echo fallback",   # || chain
        "cat <(echo x)",            # process substitution (read side)
        "diff <(ls a) <(ls b)",     # process substitution
        "echo x > file",            # redirect (also caught by mutation token)
        "echo x>file",              # redirect no spaces (was a gap)
        "echo x >> file",           # append redirect
        "cat foo &",                # background
        "ls\nrm x",                 # embedded newline
    ],
)
def test_corrective2_each_composition_metachar_denied(command: str) -> None:
    """Each individual composition metacharacter maps to deny."""
    risk = classify_claude_tool("Bash", {"command": command})
    assert risk is not RiskClass.READ, f"{command!r} classified READ ({risk})"
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": command}), engine)
    assert decision.hook_action == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "cat file",
        "cat /tmp/some/file.txt",
        "grep foo file",
        "grep -rn pattern src",
        "find . -name '*.py'",
        "git status",
        "git status -s",
        "git diff",
        "git diff --stat HEAD~1",
        "pwd",
        "head -n 20 file",
        "tail -f file",
        "wc -l file",
    ],
)
def test_corrective2_simple_reads_still_allowed(command: str) -> None:
    """Composition guard must not regress simple single read-only commands."""
    risk = classify_claude_tool("Bash", {"command": command})
    assert risk is RiskClass.READ, f"{command!r} should be READ; got {risk}"
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": command}), engine)
    assert decision.hook_action == "allow", f"{command!r} should allow"


def test_classify_mcp_tool_via_classification_primitives() -> None:
    # mcp__server__list_items -> infer matches the "list" prefix -> READ
    assert classify_claude_tool("mcp__probe__list_items", {}) is RiskClass.READ
    # mcp__server__write_note -> "write" prefix -> WRITE
    assert classify_claude_tool("mcp__probe__write_note", {"content": "x"}) is RiskClass.WRITE
    # mcp__server__delete_thing -> "delete" prefix -> DESTRUCTIVE
    assert classify_claude_tool("mcp__probe__delete_thing", {}) is RiskClass.DESTRUCTIVE


def test_classify_unknown_returns_unknown_risk() -> None:
    # No prefix match, not in built-in table, not Bash, not mcp__
    assert classify_claude_tool("ZorblatXyz", {}) is RiskClass.UNKNOWN


def test_classify_mcp_with_unrecognized_suffix_returns_unknown() -> None:
    # mcp__server__zorblat -> not matching any prefix in classification.py
    assert classify_claude_tool("mcp__probe__zorblat", {}) is RiskClass.UNKNOWN


# ----- context building ------------------------------------------------------


def test_context_for_claude_builtin() -> None:
    ctx = build_tool_call_context(_payload("Write", {"file_path": "/tmp/x", "content": "y"}))
    assert ctx.server == CLAUDE_SERVER_LABEL
    assert ctx.tool == "Write"
    assert ctx.action == f"{CLAUDE_SERVER_LABEL}.Write"
    assert ctx.risk_class is RiskClass.WRITE


def test_context_for_mcp_tool_splits_server_and_tool() -> None:
    ctx = build_tool_call_context(_payload("mcp__probe__write_note", {"content": "x"}))
    assert ctx.server == "probe"
    assert ctx.tool == "write_note"
    assert ctx.action == "probe.write_note"
    assert ctx.risk_class is RiskClass.WRITE


# ----- spec test 1: Write/Edit/MultiEdit/NotebookEdit deny ------------------


@pytest.mark.parametrize("tool_name", ["Write", "Edit", "MultiEdit", "NotebookEdit"])
def test_spec1_write_family_denied_under_default_policy(tool_name: str) -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload(tool_name, {"file_path": "/tmp/x", "content": "y"}), engine)
    assert decision.hook_action == "deny"
    assert decision.reason_code == "risky_blocked"
    assert decision.evaluation.risk_class is RiskClass.WRITE
    # write -> approval rule fires; with no approval surface in S1, treated as deny.
    assert decision.evaluation.decision is PolicyDecision.APPROVAL


# ----- spec test 2: Bash mutation deny --------------------------------------


def test_spec2_bash_mutation_denied() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": "echo y > /tmp/out"}), engine)
    assert decision.hook_action == "deny"
    assert decision.evaluation.risk_class is RiskClass.WRITE


def test_spec2_bash_destructive_blocked_by_rule() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": "rm -rf /tmp/foo"}), engine)
    assert decision.hook_action == "deny"
    assert decision.evaluation.risk_class is RiskClass.DESTRUCTIVE
    assert decision.evaluation.decision is PolicyDecision.BLOCK


# ----- corrective: end-to-end deny for arbitrary interpreters / git mutations


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"open('owned.txt','w').write('x')\"",
        "sed -i 's/foo/bar/' file",
        "perl -pi -e 's/foo/bar/' file",
        "git checkout main",
        "git reset --hard",
        "git clean -fd",
        "node -e 'require(\"fs\").writeFileSync(\"x\",\"y\")'",
    ],
)
def test_corrective_bash_fail_closed_denies_at_decide(command: str) -> None:
    """Reviewer-found blocker: these commands previously classified as READ
    and were allowed. After fix they must be denied end-to-end."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": command}), engine)
    assert decision.hook_action == "deny", (
        f"Bash {command!r} must be denied but got {decision.hook_action} "
        f"(risk={decision.evaluation.risk_class.value}, "
        f"policy_decision={decision.evaluation.decision.value})"
    )


@pytest.mark.parametrize("command", ["git status", "git diff", "git status -s"])
def test_corrective_bash_git_readonly_still_allowed_at_decide(command: str) -> None:
    """Allowlist preserved end-to-end."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": command}), engine)
    assert decision.hook_action == "allow"


# ----- spec test 3: read/list allows ----------------------------------------


@pytest.mark.parametrize("tool_name", ["Read", "LS", "Glob", "Grep"])
def test_spec3_safe_reads_allowed(tool_name: str) -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload(tool_name, {"path": "/tmp/probe"}), engine)
    assert decision.hook_action == "allow"
    assert decision.evaluation.risk_class is RiskClass.READ
    assert decision.evaluation.decision is PolicyDecision.ALLOW


def test_spec3_bash_readonly_command_allowed() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Bash", {"command": "ls -la"}), engine)
    assert decision.hook_action == "allow"


# ----- spec test 4: MCP write-like denied through Claude MCP naming --------


def test_spec4_mcp_write_note_denied() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(
        _payload("mcp__probe__write_note", {"content": "x"}), engine
    )
    assert decision.hook_action == "deny"
    assert decision.evaluation.risk_class is RiskClass.WRITE
    assert decision.context.server == "probe"
    assert decision.context.tool == "write_note"


def test_spec4_mcp_destructive_blocked() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("mcp__probe__delete_record", {}), engine)
    assert decision.hook_action == "deny"
    assert decision.evaluation.risk_class is RiskClass.DESTRUCTIVE
    assert decision.evaluation.decision is PolicyDecision.BLOCK


# ----- spec test 5: MCP read/list allowed -----------------------------------


def test_spec5_mcp_safe_list_allowed() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("mcp__probe__safe_list", {}), engine)
    assert decision.hook_action == "allow"
    assert decision.evaluation.risk_class is RiskClass.READ


# ----- spec test 6: evidence rows are bounded (sentinel privacy proof) -----


SENTINEL_CONTENT = "SENTINEL_RAW_VALUE_xyz_should_never_appear_in_evidence"
SENTINEL_PATH = "SENTINEL_RAW_FILE_PATH_abc_should_never_appear_in_evidence"
SENTINEL_COMMAND = "SENTINEL_RAW_SHELL_COMMAND_def_should_never_appear_in_evidence"


def _evidence_to_json_str(record: dict) -> str:
    """Serialize record exactly as write_evidence does for grep checks."""
    return json.dumps(record, separators=(",", ":"), default=str)


def test_spec6_write_evidence_does_not_contain_raw_content_or_path() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload(
        "Write",
        {"file_path": SENTINEL_PATH, "content": SENTINEL_CONTENT},
    )
    decision = decide(payload, engine)
    record = build_evidence_record(payload, decision)
    serialized = _evidence_to_json_str(record)
    assert SENTINEL_CONTENT not in serialized, "raw write content leaked"
    assert SENTINEL_PATH not in serialized, "raw file path leaked"


def test_spec6_bash_evidence_does_not_contain_raw_command() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload("Bash", {"command": f"echo {SENTINEL_COMMAND} > /tmp/x"})
    decision = decide(payload, engine)
    record = build_evidence_record(payload, decision)
    serialized = _evidence_to_json_str(record)
    assert SENTINEL_COMMAND not in serialized, "raw shell command leaked"


def test_spec6_mcp_evidence_does_not_contain_raw_input_values() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload(
        "mcp__probe__write_note",
        {"content": SENTINEL_CONTENT, "filename": SENTINEL_PATH},
    )
    decision = decide(payload, engine)
    record = build_evidence_record(payload, decision)
    serialized = _evidence_to_json_str(record)
    assert SENTINEL_CONTENT not in serialized
    assert SENTINEL_PATH not in serialized


def test_spec6_input_ref_contains_only_hash_and_keys() -> None:
    ref = _bounded_input_ref({"content": "hello", "file_path": "/tmp/x"})
    assert set(ref.keys()) == {"input_hash", "input_keys"}
    assert ref["input_hash"].startswith("sha256:")
    assert ref["input_keys"] == ["content", "file_path"]
    # No raw values
    serialized = json.dumps(ref)
    assert "hello" not in serialized
    assert "/tmp/x" not in serialized


# ----- corrective: cwd must not appear raw in evidence ---------------------


SENTINEL_CWD = "/Users/olegboiko/SENTINEL_SECRET_WORKSPACE_zlj9k"


def test_corrective_evidence_does_not_contain_raw_cwd() -> None:
    """Reviewer-found blocker: build_evidence_record was writing raw cwd.
    After fix, the workspace path must not appear in serialized evidence."""
    payload = _payload(
        "Write",
        {"file_path": "/tmp/x", "content": "y"},
        cwd=SENTINEL_CWD,
    )
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(payload, engine)
    record = build_evidence_record(payload, decision)
    serialized = _evidence_to_json_str(record)
    assert SENTINEL_CWD not in serialized, "raw cwd leaked in evidence"
    assert "SENTINEL_SECRET_WORKSPACE" not in serialized, "raw cwd path fragment leaked"
    # The bounded digest field MUST be present in its place.
    assert "cwd_digest" in record
    assert record["cwd_digest"].startswith("sha256:")
    assert "cwd" not in record, "raw cwd field must not be present"


def test_corrective_cwd_digest_is_deterministic_for_same_path() -> None:
    """Audit need: same workspace -> same digest, so sessions can be grouped
    without leaking the path."""
    payload_a = _payload("Read", {"file_path": "/tmp/x"}, cwd="/Users/x/proj")
    payload_b = _payload("Read", {"file_path": "/tmp/y"}, cwd="/Users/x/proj")
    payload_c = _payload("Read", {"file_path": "/tmp/z"}, cwd="/Users/x/other")
    engine = PolicyEngine(default_proxy_config_for_hook())
    rec_a = build_evidence_record(payload_a, decide(payload_a, engine))
    rec_b = build_evidence_record(payload_b, decide(payload_b, engine))
    rec_c = build_evidence_record(payload_c, decide(payload_c, engine))
    assert rec_a["cwd_digest"] == rec_b["cwd_digest"]
    assert rec_a["cwd_digest"] != rec_c["cwd_digest"]


def test_corrective_empty_cwd_yields_marker_digest() -> None:
    payload = _payload("Read", {"file_path": "/tmp/x"}, cwd="")
    engine = PolicyEngine(default_proxy_config_for_hook())
    record = build_evidence_record(payload, decide(payload, engine))
    assert record["cwd_digest"] == "sha256:empty"


# ----- spec test 7: unknown mutation-shaped fails closed -------------------


def test_spec7_unknown_tool_fails_closed() -> None:
    """Conservative fallback: UNKNOWN risk -> default_decision=ASK_BACKEND
    -> hook treats as deny (no backend in S1)."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("ZorblatUnknownTool", {"any": "value"}), engine)
    assert decision.evaluation.risk_class is RiskClass.UNKNOWN
    assert decision.evaluation.decision is PolicyDecision.ASK_BACKEND
    assert decision.hook_action == "deny"
    assert decision.reason_code == "risky_blocked"


def test_spec7_unknown_mcp_tool_fails_closed() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("mcp__weird__zorblat", {}), engine)
    assert decision.evaluation.risk_class is RiskClass.UNKNOWN
    assert decision.hook_action == "deny"


# ----- output formatting + evidence writer ---------------------------------


def test_format_hook_output_allow_returns_none() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Read", {"file_path": "/tmp/x"}), engine)
    assert format_hook_output(decision) is None


def test_format_hook_output_deny_returns_claude_compatible_json() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("Write", {"file_path": "/tmp/x", "content": "y"}), engine)
    raw = format_hook_output(decision)
    assert raw is not None
    out = json.loads(raw)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "target_reached=false" in reason
    assert "risk_class=write" in reason


# ----- S2 corrective: native deny carries an agent-facing redirect ----------


from agentveil_mcp_proxy.claude_hook import NATIVE_REDIRECT_INSTRUCTION


@pytest.mark.parametrize(
    "tool_name,tool_input",
    [
        ("Write", {"file_path": "/tmp/x", "content": "y"}),
        ("Edit", {"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}),
        ("MultiEdit", {"file_path": "/tmp/x", "edits": []}),
        ("Bash", {"command": "echo y > /tmp/out"}),
    ],
)
def test_native_mutation_deny_includes_redirect_instruction(tool_name, tool_input) -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload(tool_name, tool_input), engine)
    assert decision.hook_action == "deny"
    raw = format_hook_output(decision)
    reason = json.loads(raw)["hookSpecificOutput"]["permissionDecisionReason"]
    # Each required instruction element is present.
    assert "Direct native tool use was blocked before mutation" in reason  # claim-check: allow literal hook-deny text asserted by this test.
    assert "controlled MCP tool" in reason
    assert "same path, content, and intent" in reason
    assert "ask the user to approve" in reason and "retry the controlled tool call" in reason
    assert NATIVE_REDIRECT_INSTRUCTION in reason


def test_native_deny_redirect_does_not_leak_raw_input() -> None:
    """Redirect text must not reintroduce a raw-value leak."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload(
        "Write",
        {"file_path": SENTINEL_PATH, "content": SENTINEL_CONTENT},
    )
    decision = decide(payload, engine)
    raw = format_hook_output(decision)
    assert SENTINEL_CONTENT not in raw
    assert SENTINEL_PATH not in raw


def test_native_bash_deny_redirect_does_not_leak_command() -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload("Bash", {"command": f"echo {SENTINEL_COMMAND} > /tmp/x"})
    decision = decide(payload, engine)
    raw = format_hook_output(decision)
    assert SENTINEL_COMMAND not in raw


# ----- S3 corrective: controlled AgentVeil MCP route must pass through -------


from agentveil_mcp_proxy.claude_hook import AGENTVEIL_CONTROLLED_MCP_SERVER


@pytest.mark.parametrize(
    "tool_name,tool_input",
    [
        (f"mcp__{AGENTVEIL_CONTROLLED_MCP_SERVER}__write_file", {"path": "/x", "content": "y"}),
        (f"mcp__{AGENTVEIL_CONTROLLED_MCP_SERVER}__delete_file", {"path": "/x"}),
        (f"mcp__{AGENTVEIL_CONTROLLED_MCP_SERVER}__move_file", {"src": "/a", "dst": "/b"}),
        (f"mcp__{AGENTVEIL_CONTROLLED_MCP_SERVER}__list_workspace", {}),
    ],
)
def test_controlled_mcp_route_passes_through(tool_name, tool_input) -> None:
    """S3 blocker fix: the hook must NOT deny the AgentVeil controlled MCP
    tools, or the redirect dead-ends. They self-govern at the proxy."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload(tool_name, tool_input), engine)
    assert decision.hook_action == "allow", (
        f"controlled route {tool_name} must pass through; got {decision.hook_action}"
    )
    assert decision.reason_code == "controlled_route_passthrough"
    # No deny JSON emitted -> the call reaches the proxy.
    assert format_hook_output(decision) is None


def test_controlled_passthrough_does_not_weaken_other_mcp_servers() -> None:
    """A non-AgentVeil MCP write tool is still denied (no blanket allow)."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("mcp__other_server__write_note", {"content": "x"}), engine)
    assert decision.hook_action == "deny"


def test_controlled_passthrough_does_not_weaken_native_writes() -> None:
    """Native Write/Bash mutations are still denied after the passthrough fix."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    assert decide(_payload("Write", {"file_path": "/x", "content": "y"}), engine).hook_action == "deny"
    assert decide(_payload("Bash", {"command": "echo y > /x"}), engine).hook_action == "deny"


def test_mcp_deny_does_not_carry_native_redirect() -> None:
    """The native redirect is scoped to native tools, not MCP tool denies."""
    engine = PolicyEngine(default_proxy_config_for_hook())
    decision = decide(_payload("mcp__probe__write_note", {"content": "x"}), engine)
    assert decision.hook_action == "deny"
    reason = json.loads(format_hook_output(decision))["hookSpecificOutput"]["permissionDecisionReason"]
    assert NATIVE_REDIRECT_INSTRUCTION not in reason
    assert "target_reached=false" in reason  # base bounded reason still present


def test_write_evidence_appends_jsonl_line(tmp_path: Path) -> None:
    engine = PolicyEngine(default_proxy_config_for_hook())
    payload = _payload("Write", {"file_path": "/tmp/x", "content": "y"})
    decision = decide(payload, engine)
    record = build_evidence_record(payload, decision)
    evidence_path = tmp_path / "decisions.jsonl"
    claude_hook.write_evidence(record, evidence_path)
    claude_hook.write_evidence(record, evidence_path)
    lines = evidence_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        decoded = json.loads(line)
        assert decoded["tool_name"] == "Write"
        assert decoded["hook_action"] == "deny"


# ----- process_hook end-to-end + main() CLI --------------------------------


def test_process_hook_writes_evidence_and_deny_output(tmp_path: Path) -> None:
    payload = _payload("Write", {"file_path": "/tmp/x", "content": "y"})
    out = io.StringIO()
    evidence = tmp_path / "decisions.jsonl"
    decision = process_hook(payload, evidence_path=evidence, out=out)
    assert decision.hook_action == "deny"
    assert "permissionDecision" in out.getvalue()
    assert evidence.read_text(encoding="utf-8").strip() != ""


def test_process_hook_allow_writes_evidence_but_no_output(tmp_path: Path) -> None:
    payload = _payload("Read", {"file_path": "/tmp/x"})
    out = io.StringIO()
    evidence = tmp_path / "decisions.jsonl"
    decision = process_hook(payload, evidence_path=evidence, out=out)
    assert decision.hook_action == "allow"
    assert out.getvalue() == ""  # silent allow
    assert evidence.read_text(encoding="utf-8").strip() != ""  # but evidence written


def test_main_reads_stdin_and_writes_stdout(tmp_path: Path, monkeypatch) -> None:
    payload = _payload("Write", {"file_path": "/tmp/x", "content": "y"})
    evidence = tmp_path / "decisions.jsonl"
    monkeypatch.setenv("AGENTVEIL_HOOK_EVIDENCE_PATH", str(evidence))
    in_stream = io.StringIO(json.dumps(payload))
    out_stream = io.StringIO()
    rc = main(stdin=in_stream, stdout=out_stream)
    assert rc == 0
    assert "permissionDecision" in out_stream.getvalue()
    assert evidence.read_text(encoding="utf-8").strip() != ""


def test_main_rejects_non_object_payload() -> None:
    in_stream = io.StringIO('"not an object"')
    out_stream = io.StringIO()
    rc = main(stdin=in_stream, stdout=out_stream)
    assert rc == 1
    assert out_stream.getvalue() == ""


def test_main_evidence_path_arg_writes_evidence(tmp_path: Path) -> None:
    """S2 wiring: the installed hook command passes --evidence-path."""
    payload = _payload("Write", {"file_path": "/tmp/x", "content": "y"})
    evidence = tmp_path / "agentveil" / "evidence.jsonl"
    in_stream = io.StringIO(json.dumps(payload))
    out_stream = io.StringIO()
    rc = main(["--evidence-path", str(evidence)], stdin=in_stream, stdout=out_stream)
    assert rc == 0
    assert "permissionDecision" in out_stream.getvalue()
    assert evidence.read_text(encoding="utf-8").strip() != ""


def test_main_evidence_path_arg_overrides_env(tmp_path: Path, monkeypatch) -> None:
    arg_path = tmp_path / "arg.jsonl"
    env_path = tmp_path / "env.jsonl"
    monkeypatch.setenv("AGENTVEIL_HOOK_EVIDENCE_PATH", str(env_path))
    payload = _payload("Read", {"file_path": "/tmp/x"})
    rc = main(
        ["--evidence-path", str(arg_path)],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=io.StringIO(),
    )
    assert rc == 0
    assert arg_path.exists()
    assert not env_path.exists()  # arg wins over env


# ----- ASK_BACKEND deny fallback semantics (spec clarification #2) ----------


def test_ask_backend_is_fail_closed_in_s1() -> None:
    """Direct construction of an ASK_BACKEND decision proves deny mapping."""
    # Use a context with risk that won't match any rule -> default_decision fires.
    config = default_proxy_config_for_hook()
    engine = PolicyEngine(config)
    # default_decision is ASK_BACKEND; UNKNOWN risk doesn't match any rule.
    payload = _payload("ZorblatUnknownTool", {})
    decision = decide(payload, engine)
    assert decision.evaluation.decision is PolicyDecision.ASK_BACKEND
    assert decision.hook_action == "deny"
