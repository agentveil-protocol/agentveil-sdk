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
    codex_passphrase = "AVP_PROXY_PASSPHRASE_DO_NOT_LEAK_98765"
    config_toml.write_text(f"AVP_PROXY_PASSPHRASE = '{codex_passphrase}'\n")
    auth_json = codex_dir / "auth.json"
    auth_secret = "OPENAI_API_KEY_DO_NOT_LEAK_98765"
    auth_json.write_text(f'{{"OPENAI_API_KEY":"{auth_secret}"}}')

    with patch(
        "agentveil_paperclip.doctor.shutil.which",
        side_effect=lambda name: f"/usr/local/bin/{name}",
    ):
        report = collect_doctor_report(home=home, cwd=tmp_path)
    text = render_doctor_report(report)

    assert claude_secret not in text
    assert codex_passphrase not in text
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
