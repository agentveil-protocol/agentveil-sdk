"""Paperclip-side helpers for AgentVeil.

This package hosts read-only diagnostics that help an operator understand
whether their local environment is ready to run the external AgentVeil MCP
proxy alongside Paperclip-managed Claude or Codex agents.

The runtime control surface lives in `agentveil-mcp-proxy`. This package
does not start the proxy, mutate configuration, or call the AgentVeil
backend.
"""

from .doctor import (
    CheckResult,
    DoctorReport,
    collect_doctor_report,
    render_doctor_report,
)

__all__ = [
    "CheckResult",
    "DoctorReport",
    "collect_doctor_report",
    "render_doctor_report",
]
