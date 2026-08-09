# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded hook-deny guidance copy in client_guidance."""

from __future__ import annotations

import pytest

from agentveil_mcp_proxy.client_guidance import (
    NATIVE_FILE_WRITE_REDIRECT_INSTRUCTION,
    NATIVE_FILE_WRITE_ROUTE_UNAVAILABLE_INSTRUCTION,
    NATIVE_SHELL_HARD_BLOCK_INSTRUCTION,
    NATIVE_SHELL_NO_MCP_ROUTE_INSTRUCTION,
    native_hook_deny_instruction,
    native_write_redirect_supported,
)


@pytest.mark.parametrize(
    "native_tool",
    [
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "StrReplace",
        "ApplyPatch",
        "apply_patch",
        "write_file",
        "replace",
    ],
)
def test_native_file_write_tools_get_controlled_write_redirect(native_tool: str) -> None:
    assert native_write_redirect_supported(native_tool=native_tool)
    message = native_hook_deny_instruction(native_tool=native_tool, risk_class="write")
    assert message == NATIVE_FILE_WRITE_REDIRECT_INSTRUCTION
    assert "write_file" in message
    assert "controlled MCP tool" in message
    assert "same path, content, and intent" in message


def test_native_file_write_without_ready_route_has_honest_stop_guidance() -> None:
    message = native_hook_deny_instruction(
        native_tool="Write",
        risk_class="write",
        redirect_route_ready=False,
    )
    assert message == NATIVE_FILE_WRITE_ROUTE_UNAVAILABLE_INSTRUCTION
    assert "not currently available" in message
    assert "write_file" not in message
    assert "controlled MCP tool" not in message


@pytest.mark.parametrize(
    "native_tool,risk_class",
    [
        ("Bash", "write"),
        ("Shell", "write"),
        ("run_shell_command", "write"),
        ("Bash", "unknown"),
    ],
)
def test_shell_no_route_blocks_do_not_suggest_write_file(
    native_tool: str,
    risk_class: str,
) -> None:
    message = native_hook_deny_instruction(native_tool=native_tool, risk_class=risk_class)
    assert message == NATIVE_SHELL_NO_MCP_ROUTE_INSTRUCTION
    assert "write_file" not in message
    assert "No controlled MCP route exists for this shell action" in message
    assert "Stop and tell the user" in message
    assert "Do not retry through native shell" in message


# claim-check: allow "production" is a risk_class fixture value under negative-test coverage.
@pytest.mark.parametrize("risk_class", ["destructive", "production", "financial"])
def test_high_risk_shell_blocks_use_hard_block_copy(risk_class: str) -> None:
    message = native_hook_deny_instruction(native_tool="Bash", risk_class=risk_class)
    assert message == NATIVE_SHELL_HARD_BLOCK_INSTRUCTION
    assert "bounded security reason" in message
    assert "Stop and tell the user" in message
    assert "Do not retry through native shell" in message
    assert "write_file" not in message
    assert "controlled MCP tool" not in message
    assert "request another approval" not in message


def test_hard_block_copy_does_not_invite_retry_or_bypass() -> None:
    message = native_hook_deny_instruction(native_tool="run_shell_command", risk_class="destructive")
    lowered = message.lower()
    assert "retry through native shell" in lowered
    assert "bypass through native tools" in lowered
    assert "use an agentveil controlled mcp tool" not in lowered


def test_native_hook_deny_instruction_does_not_echo_raw_inputs() -> None:
    secret_path = "/private/customer/secret.txt"
    secret_token = "device-code-secret-token"
    message = native_hook_deny_instruction(native_tool="Write", risk_class="write")
    assert secret_path not in message
    assert secret_token not in message
