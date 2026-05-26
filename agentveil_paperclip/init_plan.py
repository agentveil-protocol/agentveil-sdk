"""Read-only init plan ("dry-run") for the Paperclip integration.

The plan describes what an `init` flow would do if it were implemented.
It mutates nothing: no config is written, no proxy identity is created,
no backend is called. The plan derives entirely from the same
read-only probes used by :mod:`agentveil_paperclip.doctor`.

The plan deliberately avoids printing exact config snippets, secrets,
file contents, or proxy policy internals. It uses "would" wording and
explicitly marks each step as requiring manual review.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .doctor import DoctorReport, collect_doctor_report


@dataclass
class InitProposal:
    """A single proposed step in the init plan."""

    label: str
    current: str
    would: str


@dataclass
class InitPlan:
    """Aggregate of init proposals for each integration surface."""

    proxy: InitProposal
    claude: InitProposal
    codex: InitProposal
    sandbox: InitProposal
    plugin: InitProposal


def _proxy_proposal(report: DoctorReport, *, show_paths: bool = False) -> InitProposal:
    current = f"CLI {report.proxy.status}"
    if show_paths and report.proxy.detail:
        current += f" ({report.proxy.detail})"
    if report.proxy.status == "found":
        would = (
            "confirm the resolved path before use. Manual review required."
        )
    else:
        would = (
            "install the AgentVeil package into the Python environment "
            "that will run the proxy, so that `agentveil-mcp-proxy` "
            "becomes resolvable on PATH. Manual review required."
        )
    return InitProposal(
        label="AgentVeil MCP proxy",
        current=current,
        would=would,
    )


def _claude_proposal(report: DoctorReport, *, show_paths: bool = False) -> InitProposal:
    cli_part = f"CLI {report.claude_cli.status}"
    if show_paths and report.claude_cli.detail:
        cli_part += f" ({report.claude_cli.detail})"
    cfg_part = f"MCP config file {report.claude_mcp_config.status}"
    if show_paths and report.claude_mcp_config.detail:
        cfg_part += f" ({report.claude_mcp_config.detail})"
    current = f"{cli_part}, {cfg_part}"
    if report.claude_cli.status != "found":
        would = (
            "install the Claude CLI before configuring the integration. "
            "Manual review required."
        )
    elif report.claude_mcp_config.status == "found":
        would = (
            "review the existing Claude MCP configuration and, if needed, "
            "add or update the runtime MCP server entry that points at the "
            "AgentVeil MCP proxy. Do not modify automatically. Manual "
            "review required to choose secret storage and the downstream "
            "MCP server."
        )
    else:
        would = (
            "propose creating a project-level Claude MCP configuration "
            "at the workspace root with an entry that points at the "
            "AgentVeil MCP proxy. Manual review required."
        )
    return InitProposal(
        label="Local Claude",
        current=current,
        would=would,
    )


def _codex_proposal(report: DoctorReport, *, show_paths: bool = False) -> InitProposal:
    cli_part = f"CLI {report.codex_cli.status}"
    if show_paths and report.codex_cli.detail:
        cli_part += f" ({report.codex_cli.detail})"
    cfg_part = f"MCP config file {report.codex_mcp_config.status}"
    if show_paths and report.codex_mcp_config.detail:
        cfg_part += f" ({report.codex_mcp_config.detail})"
    current = f"{cli_part}, {cfg_part}"
    if report.codex_cli.status != "found":
        would = (
            "install the Codex CLI before configuring the integration. "
            "Manual review required."
        )
    elif report.codex_mcp_config.status == "found":
        would = (
            "review the existing Codex configuration and, if needed, "
            "add or update the runtime MCP server entry that launches the "
            "AgentVeil MCP proxy. Do not modify automatically. Manual "
            "review required."
        )
    else:
        would = (
            "propose creating a Codex configuration file with an "
            "MCP server entry that launches the AgentVeil "
            "MCP proxy. Manual review required."
        )
    return InitProposal(
        label="Local Codex",
        current=current,
        would=would,
    )


def _sandbox_proposal() -> InitProposal:
    return InitProposal(
        label="Sandbox / remote",
        current="not verified by this dry-run",
        would=(
            "ensure the AgentVeil MCP proxy is installed inside the "
            "sandbox or remote runtime image or environment so that "
            "MCP-routed coverage applies there. Manual review required."
        ),
    )


def _plugin_proposal() -> InitProposal:
    return InitProposal(
        label="Paperclip plugin",
        current="optional advisory companion; not the runtime control layer",
        would=(
            "make no plugin changes. Runtime control lives in the "
            "external AgentVeil MCP proxy."
        ),
    )


def collect_init_plan(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
    show_paths: bool = False,
) -> InitPlan:
    """Build a read-only init plan from the same probes the doctor uses.

    Privacy-by-default: when ``show_paths`` is ``False`` (the default)
    the proposals' ``current`` strings omit absolute local filesystem
    paths. The underlying :class:`DoctorReport` always retains the
    paths internally; this flag controls only what the operator-visible
    plan reveals.
    """

    report = collect_doctor_report(home=home, cwd=cwd)
    return InitPlan(
        proxy=_proxy_proposal(report, show_paths=show_paths),
        claude=_claude_proposal(report, show_paths=show_paths),
        codex=_codex_proposal(report, show_paths=show_paths),
        sandbox=_sandbox_proposal(),
        plugin=_plugin_proposal(),
    )


def render_init_plan(plan: InitPlan, *, show_paths: bool = False) -> str:
    """Render an :class:`InitPlan` as a human-readable dry-run preview.

    Privacy-by-default: when ``show_paths`` is ``False`` the rendered
    output appends a footer note explaining that paths are omitted.
    The proposals' ``current`` strings must have been built with the
    same flag value (see :func:`collect_init_plan`).
    """

    lines: list[str] = [
        "AgentVeil Paperclip Init Plan (dry-run)",
        "",
        "This is a dry-run preview. No files have been written and no",
        "proxy state has been created. Apply any of the proposed steps",
        "manually after review.",
        "",
        "Runtime control surface:",
        "  MCP-routed tool calls only. Built-in agent-runtime tools",
        "  are out of scope for this proxy.",
        "",
    ]
    for proposal in (plan.proxy, plan.claude, plan.codex, plan.sandbox, plan.plugin):
        lines.append(f"{proposal.label}:")
        lines.append(f"  Current: {proposal.current}")
        # The "would" wording is intentionally wrapped at a reasonable
        # width to keep the preview legible without using textwrap so
        # the test suite can match exact substrings.
        for index, chunk in enumerate(_wrap_indent(proposal.would, indent="  ", first="  Would: ")):
            lines.append(chunk)
        lines.append("")

    lines.append(
        "To apply any of the proposed steps, perform them manually after review."
    )
    if not show_paths:
        lines.extend([
            "",
            "(Local filesystem paths are omitted by default. Re-run with",
            "`--show-paths` to include them.)",
        ])
    return "\n".join(lines) + "\n"


def _wrap_indent(text: str, *, indent: str, first: str, width: int = 78) -> list[str]:
    """Render ``text`` with the first line prefixed by ``first`` and continuations by ``indent``.

    This is a tiny wrapper around line-by-line layout so the preview stays
    readable without depending on the system's terminal width and without
    breaking long unbroken tokens.
    """

    words = text.split()
    if not words:
        return [first.rstrip()]
    lines: list[str] = []
    current = first
    # Track whether the current line is still at its blank prefix so we never
    # break before the very first token on a line.
    at_prefix_start = True
    for word in words:
        addition = word if current.endswith(" ") else f" {word}"
        candidate = f"{current}{addition}"
        if at_prefix_start or len(candidate) <= width:
            current = candidate
            at_prefix_start = False
        else:
            lines.append(current.rstrip())
            current = f"{indent}{word}"
            at_prefix_start = False
    lines.append(current.rstrip())
    return lines
