"""Tests for agentveil_mcp_proxy.claude_hook_setup (P10D.14 S2).

Covers install / status / uninstall with merge preservation, idempotency,
invalid-JSON no-rewrite handling, bounded status, and project-local evidence
path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy import claude_hook_setup
from agentveil_mcp_proxy.claude_hook_setup import (
    AGENTVEIL_HOOK_MARKER,
    HOOK_MATCHER,
    HookSetupError,
    build_hook_command,
    build_managed_hook_entry,
    install_hook,
    load_settings,
    project_evidence_path,
    project_settings_path,
    status_hook,
    uninstall_hook,
)


# ----- helpers ---------------------------------------------------------------


def _read_settings(project: Path) -> dict:
    return json.loads(project_settings_path(project).read_text(encoding="utf-8"))


def _managed_entries(settings: dict) -> list:
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    return [e for e in pre if AGENTVEIL_HOOK_MARKER in json.dumps(e)]


# ----- build helpers ---------------------------------------------------------


def test_build_hook_command_invokes_module_with_evidence_path() -> None:
    cmd = build_hook_command(python="/usr/bin/python3", evidence_path=Path("/proj/.claude/agentveil/evidence.jsonl"))
    assert "-m agentveil_mcp_proxy.claude_hook" in cmd
    assert "--evidence-path" in cmd
    assert ".claude" in cmd
    assert "agentveil" in cmd
    assert "evidence.jsonl" in cmd


def test_managed_entry_uses_combined_matcher() -> None:
    entry = build_managed_hook_entry(python="/usr/bin/python3", evidence_path=Path("/x/e.jsonl"))
    assert entry["matcher"] == HOOK_MATCHER
    assert "Bash" in entry["matcher"]
    assert "mcp__" in entry["matcher"]
    assert entry["hooks"][0]["type"] == "command"


def test_evidence_path_is_project_local_under_dot_claude(tmp_path: Path) -> None:
    ev = project_evidence_path(tmp_path)
    assert ev.is_relative_to(tmp_path / ".claude")


# ----- install ---------------------------------------------------------------


def test_install_creates_settings_with_managed_entry(tmp_path: Path) -> None:
    result = install_hook(tmp_path)
    assert result.created_settings is True
    assert result.reload_required is True
    settings = _read_settings(tmp_path)
    managed = _managed_entries(settings)
    assert len(managed) == 1
    command = managed[0]["hooks"][0]["command"]
    assert "-m agentveil_mcp_proxy.claude_hook" in command
    assert "--evidence-path" in command


def test_install_is_idempotent(tmp_path: Path) -> None:
    install_hook(tmp_path)
    install_hook(tmp_path)
    install_hook(tmp_path)
    settings = _read_settings(tmp_path)
    assert len(_managed_entries(settings)) == 1, "install must not duplicate managed entries"


def test_install_replaces_stale_managed_entry_without_duplicate(tmp_path: Path) -> None:
    # Pre-seed an older managed entry (marker present, old command form).
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "python /old/agentveil_mcp_proxy.claude_hook.py"}],
                }
            ]
        }
    }), encoding="utf-8")
    result = install_hook(tmp_path)
    assert result.replaced_existing_managed is True
    settings = _read_settings(tmp_path)
    assert len(_managed_entries(settings)) == 1


def test_install_preserves_unrelated_top_level_settings(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "model": "claude-opus-4-8",
        "env": {"FOO": "bar"},
        "permissions": {"allow": ["Read"]},
    }), encoding="utf-8")
    install_hook(tmp_path)
    settings = _read_settings(tmp_path)
    assert settings["model"] == "claude-opus-4-8"
    assert settings["env"] == {"FOO": "bar"}
    assert settings["permissions"] == {"allow": ["Read"]}
    assert len(_managed_entries(settings)) == 1


def test_install_preserves_unrelated_hooks(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "hooks": {
            "PostToolUse": [
                {"matcher": "Write", "hooks": [{"type": "command", "command": "echo post"}]}
            ],
            "PreToolUse": [
                {"matcher": "Read", "hooks": [{"type": "command", "command": "echo user-pre"}]}
            ],
        }
    }), encoding="utf-8")
    install_hook(tmp_path)
    settings = _read_settings(tmp_path)
    # Unrelated PostToolUse preserved
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "echo post"
    # Unrelated PreToolUse preserved
    pre = settings["hooks"]["PreToolUse"]
    user_pre = [e for e in pre if e.get("matcher") == "Read"]
    assert len(user_pre) == 1
    assert user_pre[0]["hooks"][0]["command"] == "echo user-pre"
    # AgentVeil entry added alongside
    assert len(_managed_entries(settings)) == 1


def test_install_fails_closed_on_invalid_json_without_rewrite(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    garbage = "{ this is not valid json ]"
    settings_path.write_text(garbage, encoding="utf-8")
    with pytest.raises(HookSetupError):
        install_hook(tmp_path)
    # File must be untouched.
    assert settings_path.read_text(encoding="utf-8") == garbage


# ----- uninstall -------------------------------------------------------------


def test_uninstall_removes_only_managed_entry(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "model": "x",
        "hooks": {
            "PreToolUse": [
                {"matcher": "Read", "hooks": [{"type": "command", "command": "echo user-pre"}]}
            ],
        },
    }), encoding="utf-8")
    install_hook(tmp_path)
    assert len(_managed_entries(_read_settings(tmp_path))) == 1

    result = uninstall_hook(tmp_path)
    assert result.removed_entries == 1
    settings = _read_settings(tmp_path)
    assert len(_managed_entries(settings)) == 0
    # unrelated preserved
    assert settings["model"] == "x"
    pre = settings["hooks"]["PreToolUse"]
    assert any(e.get("matcher") == "Read" for e in pre)


def test_uninstall_idempotent_no_file(tmp_path: Path) -> None:
    result = uninstall_hook(tmp_path)
    assert result.removed_entries == 0
    assert result.settings_existed is False


def test_uninstall_idempotent_no_managed_entry(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({"model": "x"}), encoding="utf-8")
    result = uninstall_hook(tmp_path)
    assert result.removed_entries == 0
    # file preserved
    assert _read_settings(tmp_path)["model"] == "x"


def test_uninstall_cleans_empty_generated_containers(tmp_path: Path) -> None:
    # install into an otherwise-empty project, then uninstall.
    install_hook(tmp_path)
    uninstall_hook(tmp_path)
    settings = _read_settings(tmp_path)
    # The generated empty PreToolUse list and hooks dict should be cleaned.
    assert "hooks" not in settings or settings.get("hooks") not in ({}, {"PreToolUse": []})


def test_uninstall_fails_closed_on_invalid_json(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    garbage = "{bad json"
    settings_path.write_text(garbage, encoding="utf-8")
    with pytest.raises(HookSetupError):
        uninstall_hook(tmp_path)
    assert settings_path.read_text(encoding="utf-8") == garbage


def test_uninstall_preserves_user_hook_in_mixed_group(tmp_path: Path) -> None:
    """Corrective: a group containing BOTH a user hook and an AgentVeil hook
    must keep the user hook on uninstall (remove only the AgentVeil hook)."""
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "echo user-hook"},
                        {"type": "command", "command": "python -m agentveil_mcp_proxy.claude_hook --evidence-path /x"},
                    ],
                }
            ]
        }
    }), encoding="utf-8")
    result = uninstall_hook(tmp_path)
    assert result.removed_entries == 1
    settings = _read_settings(tmp_path)
    pre = settings["hooks"]["PreToolUse"]
    # The group survives with the user hook intact.
    assert len(pre) == 1
    commands = [h["command"] for h in pre[0]["hooks"]]
    assert "echo user-hook" in commands
    assert all(AGENTVEIL_HOOK_MARKER not in c for c in commands)  # claim-check: allow Python all() assertion.


def test_install_preserves_user_hook_in_mixed_group(tmp_path: Path) -> None:
    """Install upsert must not drop a user hook sharing a group with an old
    AgentVeil hook."""
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "echo user-hook"},
                        {"type": "command", "command": "python -m agentveil_mcp_proxy.claude_hook --evidence-path /old"},
                    ],
                }
            ]
        }
    }), encoding="utf-8")
    install_hook(tmp_path)
    settings = _read_settings(tmp_path)
    all_commands = [
        h["command"]
        for g in settings["hooks"]["PreToolUse"]
        for h in g["hooks"]
    ]
    assert "echo user-hook" in all_commands, "user hook in mixed group was dropped"
    # Exactly one current managed entry (the fresh one; old stale one removed).
    assert len(_managed_entries(settings)) == 1


def test_install_command_shell_quotes_paths_with_spaces(tmp_path: Path) -> None:
    """Corrective: project/python paths with spaces must be shell-quoted so the
    generated command is parseable."""
    import shlex

    spaced = tmp_path / "dir with spaces"
    spaced.mkdir()
    result = install_hook(spaced, python="/opt/py thon/bin/python3")
    settings = json.loads(project_settings_path(spaced).read_text(encoding="utf-8"))
    command = _managed_entries(settings)[0]["hooks"][0]["command"]
    # The command must split cleanly via shlex (no broken quoting).
    tokens = shlex.split(command)
    assert "/opt/py thon/bin/python3" in tokens
    assert "-m" in tokens
    assert "agentveil_mcp_proxy.claude_hook" in tokens
    # The evidence path (with spaces) round-trips as a single token.
    ev_index = tokens.index("--evidence-path") + 1
    assert "dir with spaces" in tokens[ev_index]


def test_install_uninstall_roundtrip_preserves_unrelated(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    original = {"model": "x", "hooks": {"PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "echo post"}]}]}}
    settings_path.write_text(json.dumps(original), encoding="utf-8")
    install_hook(tmp_path)
    uninstall_hook(tmp_path)
    settings = _read_settings(tmp_path)
    assert settings["model"] == "x"
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "echo post"
    assert len(_managed_entries(settings)) == 0


# ----- status ----------------------------------------------------------------


def test_status_missing_is_unsafe(tmp_path: Path) -> None:
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "unsafe"
    assert status["state"] == "missing"
    assert status["settings_present"] is False


def test_status_installed_without_evidence_is_advisory_not_protected(tmp_path: Path) -> None:
    """Corrective: a freshly installed hook is advisory (reload pending), NOT
    protected. Protected would overclaim before the hook has run."""
    install_hook(tmp_path)
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "advisory"
    assert status["state"] == "installed"
    assert status["managed_hook_present"] is True
    assert status["hook_command_points_to_module"] is True
    assert status["evidence_path_configured"] is True
    assert status["reload_required"] is True


def _set_mtime(path: Path, mtime: float) -> None:
    import os
    os.utime(path, (mtime, mtime))


def test_status_protected_only_after_firing_evidence(tmp_path: Path) -> None:
    """Protected requires firing evidence whose mtime post-dates settings.json."""
    install_hook(tmp_path)
    ev = project_evidence_path(tmp_path)
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_text('{"decision":"deny"}\n', encoding="utf-8")
    # Force evidence newer than settings.json so the check is deterministic
    # regardless of filesystem mtime granularity.
    settings_mtime = project_settings_path(tmp_path).stat().st_mtime
    _set_mtime(ev, settings_mtime + 5)
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "protected"
    assert status["state"] == "installed"
    assert status["reload_required"] is False


def test_status_old_evidence_before_install_is_advisory(tmp_path: Path) -> None:
    """Corrective: stale evidence from a previous install must NOT yield
    protected after a reinstall."""
    # 1. An old evidence file predates the (re)install.
    ev = project_evidence_path(tmp_path)
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_text('{"old":"evidence"}\n', encoding="utf-8")
    _set_mtime(ev, 1_000_000.0)  # far in the past

    # 2. Install now (settings.json mtime is "now", newer than old evidence).
    install_hook(tmp_path)
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "advisory", "stale evidence must not claim protected"
    assert status["state"] == "installed"
    assert status["reload_required"] is True

    # 3. A fresh firing (evidence mtime newer than settings.json) -> protected.
    settings_mtime = project_settings_path(tmp_path).stat().st_mtime
    ev.write_text('{"new":"evidence"}\n', encoding="utf-8")
    _set_mtime(ev, settings_mtime + 5)
    status2 = status_hook(tmp_path).to_bounded_dict()
    assert status2["status"] == "protected"
    assert status2["reload_required"] is False


def test_status_empty_evidence_file_is_still_advisory(tmp_path: Path) -> None:
    install_hook(tmp_path)
    ev = project_evidence_path(tmp_path)
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_text("", encoding="utf-8")  # exists but empty => not fired
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "advisory"
    assert status["reload_required"] is True


def test_status_invalid_json_is_unsafe(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text("{not json", encoding="utf-8")
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "unsafe"
    assert status["state"] == "invalid-json"


def test_status_stale_when_command_does_not_point_to_module(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    # Managed (marker present) but old invocation form (no `-m module`).
    settings_path.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "python /old/agentveil_mcp_proxy.claude_hook.py --evidence-path /x"}]}
            ]
        }
    }), encoding="utf-8")
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["state"] == "stale"
    assert status["status"] == "advisory"
    assert status["managed_hook_present"] is True
    assert status["hook_command_points_to_module"] is False


def test_status_no_managed_entry_is_unsafe(tmp_path: Path) -> None:
    settings_path = project_settings_path(tmp_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "echo x"}]}]}
    }), encoding="utf-8")
    status = status_hook(tmp_path).to_bounded_dict()
    assert status["status"] == "unsafe"
    assert status["state"] == "missing"
    assert status["managed_hook_present"] is False


def test_status_bounded_has_no_absolute_paths_or_raw_data(tmp_path: Path) -> None:
    install_hook(tmp_path)
    bounded = status_hook(tmp_path).to_bounded_dict()
    serialized = json.dumps(bounded)
    # No absolute project path, no python interpreter path, no evidence path.
    assert str(tmp_path) not in serialized
    assert ".claude/settings.json" not in serialized  # no settings path string
    assert "/usr" not in serialized and "python" not in serialized
    # Only bounded keys present.
    assert set(bounded.keys()) == {
        "scope", "status", "state", "settings_present", "managed_hook_present",
        "hook_command_points_to_module", "evidence_path_configured",
        "reload_required", "matched_tool_classes", "notes",
    }


# ----- load_settings edge cases ---------------------------------------------


def test_load_settings_absent_returns_empty(tmp_path: Path) -> None:
    assert load_settings(project_settings_path(tmp_path)) == {}


def test_load_settings_empty_file_returns_empty(tmp_path: Path) -> None:
    p = project_settings_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("   \n", encoding="utf-8")
    assert load_settings(p) == {}


def test_load_settings_non_object_raises(tmp_path: Path) -> None:
    p = project_settings_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("[1,2,3]", encoding="utf-8")
    with pytest.raises(HookSetupError):
        load_settings(p)


# ----- P10D.14 S5: one-command connector (.mcp.json route + status) ----------

from agentveil_mcp_proxy.claude_hook_setup import (
    AGENTVEIL_MCP_SERVER_NAME,
    connector_status,
    mcp_route_present,
    project_mcp_config_path,
    remove_mcp_route,
)


def _write_mcp(project: Path, data: dict) -> None:
    p = project_mcp_config_path(project)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")


def _seed_agentveil_mcp(project: Path, *, with_other: bool = False) -> None:
    servers = {AGENTVEIL_MCP_SERVER_NAME: {"command": "agentveil-mcp-proxy", "args": ["run"]}}
    if with_other:
        servers["other-server"] = {"command": "other", "args": []}
    _write_mcp(project, {"mcpServers": servers})


def test_mcp_route_present_detects_agentveil_entry(tmp_path: Path) -> None:
    assert mcp_route_present(tmp_path) is False
    _seed_agentveil_mcp(tmp_path)
    assert mcp_route_present(tmp_path) is True


def test_remove_mcp_route_removes_only_agentveil(tmp_path: Path) -> None:
    _seed_agentveil_mcp(tmp_path, with_other=True)
    result = remove_mcp_route(tmp_path)
    assert result.removed is True
    data = json.loads(project_mcp_config_path(tmp_path).read_text(encoding="utf-8"))
    assert AGENTVEIL_MCP_SERVER_NAME not in data["mcpServers"]
    assert "other-server" in data["mcpServers"], "unrelated MCP server must survive"


def test_remove_mcp_route_idempotent_and_cleans_empty(tmp_path: Path) -> None:
    # no file
    assert remove_mcp_route(tmp_path).removed is False
    # only agentveil -> removed + mcpServers key cleaned
    _seed_agentveil_mcp(tmp_path)
    assert remove_mcp_route(tmp_path).removed is True
    data = json.loads(project_mcp_config_path(tmp_path).read_text(encoding="utf-8"))
    assert "mcpServers" not in data or data.get("mcpServers") == {}
    # second remove is a no-op
    assert remove_mcp_route(tmp_path).removed is False


def test_remove_mcp_route_fail_closed_invalid_json(tmp_path: Path) -> None:
    p = project_mcp_config_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    garbage = "{bad json"
    p.write_text(garbage, encoding="utf-8")
    with pytest.raises(HookSetupError):
        remove_mcp_route(tmp_path)
    assert p.read_text(encoding="utf-8") == garbage  # not rewritten


def test_remove_mcp_route_preserves_unrelated_top_level(tmp_path: Path) -> None:
    _write_mcp(tmp_path, {
        "mcpServers": {AGENTVEIL_MCP_SERVER_NAME: {"command": "x"}},
        "otherKey": {"keep": True},
    })
    remove_mcp_route(tmp_path)
    data = json.loads(project_mcp_config_path(tmp_path).read_text(encoding="utf-8"))
    assert data["otherKey"] == {"keep": True}


def test_connector_status_missing_is_unsafe(tmp_path: Path) -> None:
    st = connector_status(tmp_path, proxy_route_present=False)
    assert st["status"] == "unsafe"
    assert st["hook"] == "missing"
    assert st["mcp_route"] == "missing"
    assert st["proxy_route"] == "missing"
    assert st["next_step"].startswith("run ")


def test_connector_status_complete_is_advisory(tmp_path: Path) -> None:
    install_hook(tmp_path)
    _seed_agentveil_mcp(tmp_path)
    st = connector_status(tmp_path, proxy_route_present=True)
    assert st["status"] == "advisory"
    assert st["hook"] == "installed"
    assert st["mcp_route"] == "configured"
    assert st["proxy_route"] == "configured"
    assert st["restart_required"] is True


def test_connector_status_bounded_no_absolute_paths(tmp_path: Path) -> None:
    install_hook(tmp_path)
    _seed_agentveil_mcp(tmp_path)
    st = connector_status(tmp_path, proxy_route_present=True)
    serialized = json.dumps(st)
    assert str(tmp_path) not in serialized
    assert "/Users/" not in serialized and "/private/" not in serialized
    assert set(st.keys()) == {
        "scope", "status", "hook", "mcp_route", "proxy_route",
        "restart_required", "matched_tool_classes", "next_step",
    }
