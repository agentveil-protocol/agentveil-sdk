"""Read-only Paperclip integration diagnostics.

The doctor reports whether the operator's local environment can run the
external AgentVeil MCP proxy alongside Paperclip-managed Claude or Codex
agents. It only inspects PATH and the existence of well-known
configuration files; it never reads file contents and never calls the
AgentVeil backend or any agent runtime.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CheckResult:
    """Result of a single read-only diagnostic check."""

    label: str
    status: str  # "found" | "missing" | "not_checked"
    detail: str | None = None


@dataclass
class DoctorReport:
    """Aggregate result of the Paperclip-integration diagnostic run."""

    proxy: CheckResult
    claude_cli: CheckResult
    claude_mcp_config: CheckResult
    codex_cli: CheckResult
    codex_mcp_config: CheckResult


def _which(command: str) -> Path | None:
    """Resolve `command` on PATH without executing it."""

    resolved = shutil.which(command)
    return Path(resolved) if resolved else None


def _claude_mcp_config_present(home: Path, cwd: Path) -> tuple[bool, str | None]:
    """Report whether any plausible Claude MCP config exists.

    Checked locations, in order:

    * Project-level ``.mcp.json`` next to ``cwd``.
    * User-level ``~/.claude.json``.
    * User-level ``~/.claude/settings.json``.

    The function never reads file contents; it only reports the first
    matching path so the operator knows where the doctor looked.
    """

    candidates = [
        cwd / ".mcp.json",
        home / ".claude.json",
        home / ".claude" / "settings.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return True, str(candidate)
    return False, None


def _codex_mcp_config_present(home: Path) -> tuple[bool, str | None]:
    """Report whether the Codex MCP config exists at the documented path."""

    candidate = home / ".codex" / "config.toml"
    if candidate.exists():
        return True, str(candidate)
    return False, None


def collect_doctor_report(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
) -> DoctorReport:
    """Run the read-only diagnostic checks and return a structured report."""

    home = home or Path.home()
    cwd = cwd or Path.cwd()

    proxy_path = _which("agentveil-mcp-proxy")
    claude_path = _which("claude")
    codex_path = _which("codex")

    if claude_path is not None:
        present, detail = _claude_mcp_config_present(home, cwd)
        claude_mcp_config = CheckResult(
            label="Claude MCP config",
            status="found" if present else "missing",
            detail=detail,
        )
    else:
        claude_mcp_config = CheckResult(
            label="Claude MCP config",
            status="not_checked",
            detail=None,
        )

    if codex_path is not None:
        present, detail = _codex_mcp_config_present(home)
        codex_mcp_config = CheckResult(
            label="Codex MCP config",
            status="found" if present else "missing",
            detail=detail,
        )
    else:
        codex_mcp_config = CheckResult(
            label="Codex MCP config",
            status="not_checked",
            detail=None,
        )

    return DoctorReport(
        proxy=CheckResult(
            label="AgentVeil MCP proxy",
            status="found" if proxy_path else "missing",
            detail=str(proxy_path) if proxy_path else None,
        ),
        claude_cli=CheckResult(
            label="Claude CLI",
            status="found" if claude_path else "missing",
            detail=str(claude_path) if claude_path else None,
        ),
        claude_mcp_config=claude_mcp_config,
        codex_cli=CheckResult(
            label="Codex CLI",
            status="found" if codex_path else "missing",
            detail=str(codex_path) if codex_path else None,
        ),
        codex_mcp_config=codex_mcp_config,
    )


def _summarise(cli_check: CheckResult, config_check: CheckResult) -> str:
    """Combine a (CLI, MCP-config) pair into a short human-readable status."""

    if cli_check.status != "found":
        return "needs setup (CLI missing)"
    if config_check.status == "found":
        return "needs review (MCP config file present; proxy entry not verified)"
    if config_check.status == "missing":
        return "needs setup (CLI present, MCP config missing)"
    return "not checked"


def _line_with_detail(label: str, check: CheckResult, *, show_paths: bool = False) -> str:
    if check.detail is None or not show_paths:
        return f"  {label}: {check.status}"
    return f"  {label}: {check.status} ({check.detail})"


def render_doctor_report(report: DoctorReport, *, show_paths: bool = False) -> str:
    """Render a `DoctorReport` as a human-readable text block.

    Privacy-by-default: absolute local filesystem paths are omitted
    unless ``show_paths=True`` is passed. The structured
    :class:`CheckResult` data on ``report`` always retains the
    underlying paths internally; this flag only controls what the
    operator-visible text reveals.
    """

    lines: list[str] = [
        "AgentVeil Paperclip Doctor",
        "",
        "Runtime control surface:",
        "  MCP-routed tool calls only.",
        "  Built-in agent-runtime tools (file edits, shell, search, and",
        "  similar in-runtime tools) do not pass through MCP and are out",
        "  of scope for this proxy.",
        "",
        "AgentVeil MCP proxy:",
        _line_with_detail("CLI", report.proxy, show_paths=show_paths),
        "",
        "Local Claude:",
        _line_with_detail("CLI", report.claude_cli, show_paths=show_paths),
        _line_with_detail("MCP config file", report.claude_mcp_config, show_paths=show_paths),
        f"  Status: {_summarise(report.claude_cli, report.claude_mcp_config)}",
        "",
        "Local Codex:",
        _line_with_detail("CLI", report.codex_cli, show_paths=show_paths),
        _line_with_detail("MCP config file", report.codex_mcp_config, show_paths=show_paths),
        f"  Status: {_summarise(report.codex_cli, report.codex_mcp_config)}",
        "",
        "Sandbox / remote:",
        "  Status: not verified by this doctor.",
        "  Requirement: the AgentVeil MCP proxy must be installed in the",
        "  sandbox or remote runtime environment for MCP-routed coverage",
        "  to apply there.",
        "",
        "Paperclip plugin:",
        "  Optional advisory companion. Not the runtime control layer.",
    ]
    if not show_paths:
        lines.extend([
            "",
            "(Local filesystem paths are omitted by default. Re-run with",
            "`--show-paths` to include them.)",
        ])
    return "\n".join(lines) + "\n"
