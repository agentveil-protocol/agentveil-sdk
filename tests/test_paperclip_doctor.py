"""Tests for the agentveil-paperclip doctor command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agentveil_paperclip.cli import agentveil_main, main
from agentveil_paperclip.doctor import (
    collect_doctor_report,
    render_doctor_report,
)


def _empty_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_doctor_runs_with_no_clis_present(tmp_path):
    """With nothing on PATH the doctor reports missing without raising."""
    home = _empty_home(tmp_path)
    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda _name: None,
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)

    assert report.proxy.status == "missing"
    assert report.claude_cli.status == "missing"
    assert report.codex_cli.status == "missing"
    # When the CLI is missing, the doctor does not attempt the MCP-config check.
    assert report.claude_mcp_config.status == "not_checked"
    assert report.codex_mcp_config.status == "not_checked"


def test_doctor_runs_with_clis_present_but_configs_absent(tmp_path):
    """With CLIs present but no config files, MCP-config is reported missing."""
    home = _empty_home(tmp_path)

    def fake_which(name: str) -> str:
        return f"/usr/local/bin/{name}"

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=fake_which,
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)

    assert report.proxy.status == "found"
    assert report.claude_cli.status == "found"
    assert report.codex_cli.status == "found"
    assert report.claude_mcp_config.status == "missing"
    assert report.codex_mcp_config.status == "missing"


def test_doctor_finds_claude_settings_json(tmp_path):
    """~/.claude/settings.json should register as a Claude MCP config."""
    home = _empty_home(tmp_path)
    claude_dir = home / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("{}")

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)

    assert report.claude_mcp_config.status == "found"
    assert report.claude_mcp_config.detail == str(claude_dir / "settings.json")


def test_doctor_finds_project_mcp_json(tmp_path):
    """A project-level .mcp.json at cwd should register as a Claude MCP config."""
    home = _empty_home(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text("{}")

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=project)

    assert report.claude_mcp_config.status == "found"
    assert report.claude_mcp_config.detail == str(project / ".mcp.json")


def test_doctor_finds_codex_config_toml(tmp_path):
    """~/.codex/config.toml should register as a Codex MCP config."""
    home = _empty_home(tmp_path)
    codex_dir = home / ".codex"
    codex_dir.mkdir()
    (codex_dir / "config.toml").write_text("# placeholder\n")

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)

    assert report.codex_mcp_config.status == "found"
    assert report.codex_mcp_config.detail == str(codex_dir / "config.toml")


def test_doctor_output_contains_integration_boundary_lines(tmp_path):
    """Rendered output names the integration boundary explicitly."""
    home = _empty_home(tmp_path)
    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda _name: None,
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)
    text = render_doctor_report(report)

    assert "MCP-routed tool calls only" in text
    assert "Built-in agent-runtime tools" in text
    assert "not verified by this doctor" in text
    assert "Optional advisory companion" in text
    assert "Not the runtime control layer" in text


def test_doctor_does_not_call_config_presence_ready(tmp_path):
    """A config file alone is not enough to prove the proxy path is ready."""
    home = _empty_home(tmp_path)
    (home / ".claude.json").write_text("{}")
    codex_dir = home / ".codex"
    codex_dir.mkdir()
    (codex_dir / "config.toml").write_text("# placeholder\n")

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)
    text = render_doctor_report(report)

    assert "ready" not in text.lower()
    assert "proxy entry not verified" in text


def test_doctor_never_prints_config_or_auth_file_contents(tmp_path):
    """The doctor must report path presence only, never file contents."""
    home = _empty_home(tmp_path)

    claude_dir = home / ".claude"
    claude_dir.mkdir()
    settings = claude_dir / "settings.json"
    claude_secret = "PROXY_SECRET_DO_NOT_LEAK_98765"
    settings.write_text(claude_secret)

    codex_dir = home / ".codex"
    codex_dir.mkdir()
    config_toml = codex_dir / "config.toml"
    codex_secret_value = "CODEX_RUNTIME_SECRET_DO_NOT_LEAK_98765"
    config_toml.write_text(f"SECRET_FIELD = '{codex_secret_value}'\n")
    auth_json = codex_dir / "auth.json"
    auth_secret = "RUNTIME_AUTH_SECRET_DO_NOT_LEAK_98765"
    auth_json.write_text(f'{{"AUTH_SECRET":"{auth_secret}"}}')

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)
    text = render_doctor_report(report)

    assert claude_secret not in text
    assert codex_secret_value not in text
    assert auth_secret not in text


def test_main_entry_returns_zero_and_writes_to_stdout(capsys):
    """`agentveil-paperclip doctor` returns 0 and writes the report header to stdout."""
    return_code = main(["doctor"])
    assert return_code == 0

    captured = capsys.readouterr()
    assert "AgentVeil Paperclip Doctor" in captured.out
    assert "MCP-routed tool calls only" in captured.out
    assert "Optional advisory companion" in captured.out


def test_agentveil_paperclip_entry_returns_zero(capsys):
    """`agentveil paperclip doctor` returns 0 and writes the doctor report."""
    return_code = agentveil_main(["paperclip", "doctor"])
    assert return_code == 0

    captured = capsys.readouterr()
    assert "AgentVeil Paperclip Doctor" in captured.out
    assert "MCP-routed tool calls only" in captured.out


def test_main_entry_requires_subcommand(capsys):
    """Calling the entry point with no subcommand should fail with a usage error."""
    import pytest

    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code != 0
    captured = capsys.readouterr()
    # argparse prints usage to stderr when a required subcommand is missing.
    assert "agentveil-paperclip" in captured.err or "usage" in captured.err.lower()


# ---------------------------------------------------------------------------
# `init --dry-run` (Stage 5B) tests
# ---------------------------------------------------------------------------


def test_init_dry_run_via_agentveil_entry_returns_zero(capsys):
    """`agentveil paperclip init --dry-run` returns 0 and prints the plan."""
    return_code = agentveil_main(["paperclip", "init", "--dry-run"])
    assert return_code == 0

    captured = capsys.readouterr()
    assert "AgentVeil Paperclip Init Plan (dry-run)" in captured.out
    # The plan must use the "would" / "manual review" wording, not claim a
    # ready state from file presence alone.
    assert "Would:" in captured.out
    assert "Manual review required" in captured.out
    assert "ready" not in captured.out.lower()


def test_init_dry_run_via_paperclip_helper_entry_returns_zero(capsys):
    """`agentveil-paperclip init --dry-run` also runs and exits 0."""
    return_code = main(["init", "--dry-run"])
    assert return_code == 0

    captured = capsys.readouterr()
    assert "AgentVeil Paperclip Init Plan (dry-run)" in captured.out
    assert "MCP-routed tool calls only" in captured.out


def test_init_dry_run_describes_each_integration_surface(capsys):
    """Dry-run output must describe every integration surface, not just one."""
    return_code = agentveil_main(["paperclip", "init", "--dry-run"])
    assert return_code == 0

    text = capsys.readouterr().out
    assert "AgentVeil MCP proxy:" in text
    assert "Local Claude:" in text
    assert "Local Codex:" in text
    assert "Sandbox / remote:" in text
    assert "Paperclip plugin:" in text
    # Sandbox boundary must remain present and qualified.
    assert "not verified by this dry-run" in text


def test_init_without_dry_run_fails_with_clear_message(capsys):
    """`init` without --dry-run must exit non-zero and explain --dry-run."""
    return_code = agentveil_main(["paperclip", "init"])
    assert return_code != 0

    captured = capsys.readouterr()
    assert "--dry-run" in captured.err
    # The error must say nothing has been written.
    assert "No mutating init implementation" in captured.err


def test_init_dry_run_does_not_write_any_file(monkeypatch):
    """The dry-run must never call an io-write API."""
    write_targets: list[tuple[str, str]] = []
    real_open = open

    def tracking_open(file, mode="r", *args, **kwargs):  # type: ignore[no-untyped-def]
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            write_targets.append((str(file), mode))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", tracking_open)
    return_code = agentveil_main(["paperclip", "init", "--dry-run"])
    assert return_code == 0
    assert write_targets == []


def test_init_dry_run_never_prints_planted_secret_contents(tmp_path, monkeypatch, capsys):
    """Mock-planted secret contents in real-shaped configs must not leak into output."""
    home = _empty_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))

    claude_dir = home / ".claude"
    claude_dir.mkdir()
    claude_secret = "INIT_PLAN_CLAUDE_SECRET_DO_NOT_LEAK_42424"
    (claude_dir / "settings.json").write_text(claude_secret)

    codex_dir = home / ".codex"
    codex_dir.mkdir()
    codex_secret = "INIT_PLAN_RUNTIME_SECRET_DO_NOT_LEAK_42424"
    (codex_dir / "config.toml").write_text(
        f"SECRET_FIELD = '{codex_secret}'\n"
    )
    auth_secret = "INIT_PLAN_AUTH_SECRET_DO_NOT_LEAK_42424"
    (codex_dir / "auth.json").write_text(
        f'{{"AUTH_SECRET":"{auth_secret}"}}'
    )

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        return_code = agentveil_main(["paperclip", "init", "--dry-run"])
    assert return_code == 0

    captured = capsys.readouterr()
    assert claude_secret not in captured.out
    assert claude_secret not in captured.err
    assert codex_secret not in captured.out
    assert codex_secret not in captured.err
    assert auth_secret not in captured.out
    assert auth_secret not in captured.err
