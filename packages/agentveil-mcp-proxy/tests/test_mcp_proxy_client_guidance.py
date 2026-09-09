# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded hook-deny guidance copy in client_guidance."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from agentveil_mcp_proxy.client_guidance import (
    NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
    NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
    NATIVE_FILE_WRITE_REDIRECT_INSTRUCTION,
    NATIVE_FILE_WRITE_ROUTE_UNAVAILABLE_INSTRUCTION,
    NATIVE_SHELL_HARD_BLOCK_INSTRUCTION,
    NATIVE_SHELL_NO_MCP_ROUTE_INSTRUCTION,
    NATIVE_STATIC_CONTROLLED_ROUTE_INSTRUCTION,
    ControlledAlternativeSuggestion,
    NativeActionIntent,
    NativeControlledGuidanceEnvelope,
    add_agentveil_owned_git_excludes,
    build_client_guidance_payload,
    build_native_controlled_guidance_envelope,
    format_native_controlled_guidance_text,
    is_agentveil_owned_controlled_mcp_tool,
    native_action_intent_from_mapping,
    native_controlled_guidance_envelope_from_mapping,
    native_hook_deny_instruction,
    native_write_redirect_supported,
    normalize_native_action,
    remove_agentveil_owned_git_exclude_if_target_missing,
    remove_agentveil_owned_git_excludes,
    select_controlled_alternative_suggestion,
    trusted_static_controlled_route_ready,
)
from redirect_hook_contract_fixtures import init_redirect_contract_home


def test_client_guidance_routes_explicit_git_intents_to_agentveil_tool() -> None:
    payload = build_client_guidance_payload(client_id="codex")
    guidance = "\n".join(payload["routing_guidance"])
    assert "agentveil_git_operation" in guidance
    assert "operation=commit" in guidance
    assert "operation=push" in guidance
    assert "bounded denial is the controlled completion signal" in guidance
    assert "commit is authorized" not in guidance
    assert "push is authorized" not in guidance


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
    if native_tool in {"ApplyPatch", "apply_patch"}:
        assert "controlled MCP tool apply_patch" in message
        assert "single-file patch" in message
    else:
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


_EXACT_DELETE_PATH = "notes.txt"
_EXACT_DELETE_PATCH = "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"
_CANARY_ABS = "/private/customer/secret.txt"
_AUTHORITY_WORDS = ("ALLOW", "BLOCK", "APPROVAL", "authority", "capability", "receipt", "lineage")


def _assert_exact_delete_intent(intent: NativeActionIntent, *, native_tool: str) -> None:
    assert intent.native_tool == native_tool
    assert intent.operation == "delete"
    assert intent.relative_path == _EXACT_DELETE_PATH
    assert intent.confidence == "exact"
    assert intent.action_family == "filesystem"
    assert intent.reason == "exact_single_target_delete"
    assert _CANARY_ABS not in repr(intent)
    assert "rm " not in repr(intent)
    assert "***" not in repr(intent)


def _assert_available_envelope(envelope: NativeControlledGuidanceEnvelope) -> None:
    mapping = envelope.public_mapping()
    assert mapping["schema_version"] == 1
    assert mapping["suggestion_status"] == "available"
    assert mapping["reason"] == "exact_single_target_delete"
    assert mapping["alternative"]["id"] == NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE
    assert mapping["alternative"]["tool_contract"] == NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT
    assert mapping["alternative"]["input"] == {"path": _EXACT_DELETE_PATH}
    text = format_native_controlled_guidance_text(envelope)
    assert "schema_version=1" in text
    assert "suggestion_status=available" in text
    assert "reason=exact_single_target_delete" in text
    assert "alternative.tool_contract=agentveil_stage_delete" in text
    assert "alternative.input.path=notes.txt" in text
    assert "alternative.id=" not in text
    assert "non-authorizing" in text
    for word in _AUTHORITY_WORDS:
        assert word not in text


def _assert_unavailable(envelope: NativeControlledGuidanceEnvelope, *, reason: str, leaks: tuple[str, ...] = ()) -> None:
    mapping = envelope.public_mapping()
    assert mapping["schema_version"] == 1
    assert mapping["suggestion_status"] == "unavailable"
    assert mapping["reason"] == reason
    assert mapping["alternative"] is None
    text = format_native_controlled_guidance_text(envelope)
    assert "suggestion_status=unavailable" in text
    assert "alternative=null" in text
    assert "filesystem.stage_delete.v1" not in text
    assert "controlled MCP tool" not in text
    for leak in leaks:
        assert leak not in text
        assert leak not in repr(envelope)


def test_exact_codex_delete_file_patch_selects_stage_delete() -> None:
    intent = normalize_native_action(
        native_tool="apply_patch",
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    _assert_exact_delete_intent(intent, native_tool="apply_patch")
    envelope = select_controlled_alternative_suggestion(intent, redirect_route_ready=True)
    _assert_available_envelope(envelope)
    unavailable = select_controlled_alternative_suggestion(intent, redirect_route_ready=False)
    _assert_unavailable(unavailable, reason="route_unavailable")


def test_exact_literal_shell_delete_selects_stage_delete() -> None:
    intent = normalize_native_action(
        native_tool="Bash",
        tool_input={"command": "rm notes.txt"},
    )
    _assert_exact_delete_intent(intent, native_tool="Bash")
    _assert_available_envelope(
        select_controlled_alternative_suggestion(intent, redirect_route_ready=True)
    )


@pytest.mark.parametrize(
    ("native_tool", "tool_input"),
    [
        ("Delete", {"path": "secrets.env"}),
        ("Bash", {"command": "rm .env"}),
        ("Bash", {"command": "rm .env.local"}),
        ("Delete", {"path": "credentials.json"}),
        ("apply_patch", {"patch": "*** Begin Patch\n*** Delete File: secrets.env\n*** End Patch"}),
    ],
)
def test_unsafe_secret_delete_does_not_select_stage_delete(
    native_tool: str,
    tool_input: dict[str, str],
) -> None:
    intent = normalize_native_action(native_tool=native_tool, tool_input=tool_input)
    envelope = select_controlled_alternative_suggestion(intent, redirect_route_ready=True)
    _assert_unavailable(
        envelope,
        reason="insufficient_target",
        leaks=("secrets.env", ".env", ".env.local", "credentials.json", "filesystem.stage_delete.v1"),
    )
    still_safe = select_controlled_alternative_suggestion(
        normalize_native_action(native_tool="Delete", tool_input={"path": "notes.txt"}),
        redirect_route_ready=True,
    )
    _assert_available_envelope(still_safe)


def test_exact_unlink_and_double_dash_shell_delete_are_exact() -> None:
    unlink_intent = normalize_native_action(
        native_tool="run_shell_command",
        tool_input={"command": "unlink notes.txt"},
    )
    dashed = normalize_native_action(
        native_tool="Shell",
        tool_input={"command": "rm -- notes.txt"},
    )
    _assert_exact_delete_intent(unlink_intent, native_tool="run_shell_command")
    _assert_exact_delete_intent(dashed, native_tool="Shell")


def test_semantically_equivalent_exact_payloads_share_envelope() -> None:
    fixtures = (
        ("apply_patch", {"patch": _EXACT_DELETE_PATCH}),
        ("ApplyPatch", {"patch": "*** Begin Patch\n*** Delete File: ./notes.txt\n*** End Patch"}),
        ("Bash", {"command": "rm notes.txt"}),
        ("Bash", {"command": "rm -- 'notes.txt'"}),
        ("Shell", {"command": "rm notes.txt"}),
        ("run_shell_command", {"command": "rm notes.txt"}),
        ("Delete", {"path": "notes.txt"}),
        ("Delete", {"file_path": "notes.txt"}),
    )
    envelopes = [
        build_native_controlled_guidance_envelope(
            native_tool=tool,
            tool_input=payload,
            redirect_route_ready=True,
        ).public_mapping()
        for tool, payload in fixtures
    ]
    intents = [
        normalize_native_action(native_tool=tool, tool_input=payload).public_mapping()
        for tool, payload in fixtures
    ]
    assert len({json.dumps(item, sort_keys=True) for item in envelopes}) == 1
    public_without_tool = [
        {key: value for key, value in item.items() if key != "native_tool"}
        for item in intents
    ]
    assert len({json.dumps(item, sort_keys=True) for item in public_without_tool}) == 1


def test_connector_without_exact_target_stays_insufficient() -> None:
    cases = (
        ("apply_patch", {}),
        ("Delete", {}),
        ("Bash", {}),
        ("Write", {"file_path": "notes.txt", "content": "x"}),
        ("unknown_tool", {"path": "notes.txt"}),
        ("unrelated_job_tool", {"command": "rm notes.txt"}),
    )
    for native_tool, tool_input in cases:
        intent = normalize_native_action(native_tool=native_tool, tool_input=tool_input)
        assert intent.confidence == "insufficient"
        assert intent.relative_path is None
        envelope = select_controlled_alternative_suggestion(intent)
        assert envelope.suggestion_status == "unavailable"
        assert envelope.alternative is None


@pytest.mark.parametrize(
    "native_tool,tool_input,reason",
    [
        ("apply_patch", {"patch": "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch"}, "not_delete_operation"),
        (
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: notes.txt\n@@\n-a\n+b\n*** End Patch"},
            "not_delete_operation",
        ),
        (
            "apply_patch",
            {
                "patch": (
                    "*** Begin Patch\n*** Delete File: one.txt\n*** Delete File: two.txt\n*** End Patch"
                )
            },
            "multi_target",
        ),
        (
            "apply_patch",
            {
                "patch": (
                    "*** Begin Patch\n*** Add File: one.txt\n+x\n*** Delete File: notes.txt\n*** End Patch"
                )
            },
            "mixed_operation",
        ),
        (
            "apply_patch",
            {
                "patch": (
                    "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n*** End Patch"
                )
            },
            "move_or_rename",
        ),
        ("Bash", {"command": "rm notes.txt extra.txt"}, "multi_target"),
        ("Bash", {"command": "rm notes*.txt"}, "ambiguous_shell"),
        ("Bash", {"command": "rm $var"}, "ambiguous_shell"),
        ("Bash", {"command": "rm $(echo notes.txt)"}, "ambiguous_shell"),
        ("Bash", {"command": "rm notes.txt && ls"}, "ambiguous_shell"),
        ("Bash", {"command": "rm notes.txt; echo x"}, "ambiguous_shell"),
        ("Bash", {"command": "rm notes.txt > /tmp/out"}, "ambiguous_shell"),
        ("Bash", {"command": "rm -rf notes.txt"}, "ambiguous_shell"),
        ("Bash", {"command": f"rm {_CANARY_ABS}"}, "absolute_path"),
        ("Delete", {"path": _CANARY_ABS}, "absolute_path"),
        ("Delete", {"path": "../notes.txt"}, "traversal_path"),
        ("apply_patch", {"patch": "*** Begin Patch\n*** Delete File: ../notes.txt\n*** End Patch"}, "traversal_path"),
        ("Bash", {"command": "mv notes.txt gone.txt"}, "move_or_rename"),
        ("Write", {"path": "notes.txt", "content": "x"}, "not_delete_operation"),
        ("Edit", {"file_path": "notes.txt"}, "not_delete_operation"),
        ("apply_patch", {"patch": "not-a-patch"}, "malformed_input"),
        ("Delete", {"path": "a" * 4097}, "oversized_input"),
        ("apply_patch", {"patch": "*** Begin Patch\n" + ("x" * 262_145) + "\n*** End Patch"}, "oversized_input"),
        ("Delete", {"path": " notes.txt "}, "malformed_input"),
        ("Delete", {"path": "notes.txt\nsuggestion_status=available"}, "malformed_input"),
        ("unrelated_job_tool", {"command": "rm notes.txt"}, "insufficient_target"),
    ],
)
def test_insufficient_matrix_returns_unavailable_without_target(
    native_tool: str,
    tool_input: dict,
    reason: str,
) -> None:
    intent = normalize_native_action(native_tool=native_tool, tool_input=tool_input)
    assert intent.confidence == "insufficient"
    assert intent.relative_path is None
    assert intent.reason == reason
    envelope = select_controlled_alternative_suggestion(intent)
    leaks = (_CANARY_ABS, "*** Begin Patch", "rm ", "secret-canary-token", "a" * 32)
    _assert_unavailable(envelope, reason=reason, leaks=leaks)


def test_guidance_text_with_canary_inputs_does_not_leak() -> None:
    message = native_hook_deny_instruction(
        native_tool="apply_patch",
        risk_class="write",
        redirect_route_ready=False,
        tool_input={"patch": "*** Begin Patch\n*** Delete File: /private/customer/secret.txt\nsecret-canary-token\n*** End Patch"},
    )
    assert "/private/customer/secret.txt" not in message
    assert "secret-canary-token" not in message
    assert "alternative=null" in message
    assert "filesystem.stage_delete.v1" not in message


def test_envelope_from_mapping_rejects_authority_and_invalid_available() -> None:
    with pytest.raises(ValueError):
        native_controlled_guidance_envelope_from_mapping(
            {
                "schema_version": 1,
                "suggestion_status": "available",
                "reason": "exact_single_target_delete",
                "alternative": None,
                "permission": "allow",
            }
        )
    with pytest.raises(ValueError):
        NativeControlledGuidanceEnvelope(
            schema_version=1,
            suggestion_status="available",
            reason="exact_single_target_delete",
            alternative=None,
        )
    with pytest.raises(ValueError):
        ControlledAlternativeSuggestion(
            id="filesystem.stage_delete.v1",
            tool_contract="agentveil_stage_delete",
            input={"path": _CANARY_ABS},
        )
    with pytest.raises(ValueError):
        NativeActionIntent(
            native_tool="Bash",
            operation="delete",
            relative_path=_CANARY_ABS,
            confidence="exact",
            action_family="filesystem",
            reason="exact_single_target_delete",
        )


def test_renderer_does_not_invent_missing_alternative() -> None:
    envelope = build_native_controlled_guidance_envelope(
        native_tool="Bash",
        tool_input={"command": "rm notes.txt extra.txt"},
    )
    text = format_native_controlled_guidance_text(envelope)
    assert "alternative=null" in text
    reconstructed = native_controlled_guidance_envelope_from_mapping(envelope.public_mapping())
    assert reconstructed.public_mapping() == envelope.public_mapping()
    assert format_native_controlled_guidance_text(reconstructed) == text


def test_exact_intent_mapping_round_trips_including_reason() -> None:
    intent = normalize_native_action(
        native_tool="apply_patch",
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    mapping = intent.public_mapping()
    assert mapping["reason"] == "exact_single_target_delete"
    round_trip = native_action_intent_from_mapping(mapping)
    assert round_trip.public_mapping() == mapping


def test_hard_block_exact_payload_returns_unavailable_alternative() -> None:
    envelope = build_native_controlled_guidance_envelope(
        native_tool="apply_patch",
        tool_input={"patch": _EXACT_DELETE_PATCH},
        redirect_route_ready=False,
    )
    _assert_unavailable(envelope, reason="route_unavailable")
    message = native_hook_deny_instruction(
        native_tool="apply_patch",
        risk_class="write",
        redirect_route_ready=False,
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    assert "suggestion_status=unavailable" in message
    assert "alternative=null" in message
    assert "filesystem.stage_delete.v1" not in message
    assert "managed AgentVeil write route is not currently available" in message


def test_whitespace_and_control_characters_do_not_mutate_or_inject_target() -> None:
    spaced = normalize_native_action(native_tool="Delete", tool_input={"path": " notes.txt "})
    injected = normalize_native_action(
        native_tool="Delete",
        tool_input={"path": "notes.txt\nsuggestion_status=available"},
    )
    assert spaced.confidence == "insufficient"
    assert spaced.relative_path is None
    assert spaced.reason == "malformed_input"
    assert injected.confidence == "insufficient"
    assert injected.relative_path is None
    assert injected.reason == "malformed_input"
    for envelope in (
        select_controlled_alternative_suggestion(spaced, redirect_route_ready=True),
        select_controlled_alternative_suggestion(injected, redirect_route_ready=True),
    ):
        _assert_unavailable(envelope, reason="malformed_input", leaks=(" notes.txt ", "suggestion_status=available"))


def test_unknown_tool_command_is_not_treated_as_shell_delete() -> None:
    intent = normalize_native_action(
        native_tool="unrelated_job_tool",
        tool_input={"command": "rm notes.txt"},
    )
    assert intent.confidence == "insufficient"
    assert intent.relative_path is None
    assert intent.reason == "insufficient_target"
    envelope = select_controlled_alternative_suggestion(intent, redirect_route_ready=True)
    _assert_unavailable(envelope, reason="insufficient_target", leaks=("notes.txt", "rm notes.txt"))


def _assert_bounded_type_error(exc: BaseException, *leaks: object) -> None:
    message = str(exc)
    assert _CANARY_ABS not in message
    assert "secret-canary-token" not in message
    for leak in leaks:
        text = leak if type(leak) is str else repr(leak)
        assert text not in message


def _valid_stage_delete_alternative() -> ControlledAlternativeSuggestion:
    return ControlledAlternativeSuggestion(
        id=NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
        tool_contract=NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
        input={"path": _EXACT_DELETE_PATH},
    )


def _valid_available_envelope_mapping() -> dict[str, object]:
    return {
        "schema_version": 1,
        "suggestion_status": "available",
        "reason": "exact_single_target_delete",
        "alternative": {
            "id": NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
            "tool_contract": NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
            "input": {"path": _EXACT_DELETE_PATH},
        },
    }


def _valid_exact_intent_mapping() -> dict[str, object]:
    return {
        "native_tool": "apply_patch",
        "operation": "delete",
        "relative_path": _EXACT_DELETE_PATH,
        "confidence": "exact",
        "action_family": "filesystem",
        "reason": "exact_single_target_delete",
    }


def test_mapping_and_dataclass_reject_coerced_types() -> None:
    alternative = _valid_stage_delete_alternative()
    for schema_version in (True, 1.0, "1"):
        payload = {**_valid_available_envelope_mapping(), "schema_version": schema_version}
        with pytest.raises(ValueError) as mapping_exc:
            native_controlled_guidance_envelope_from_mapping(payload)
        _assert_bounded_type_error(mapping_exc.value, True, 1.0, "True")
        with pytest.raises(ValueError) as dataclass_exc:
            NativeControlledGuidanceEnvelope(
                schema_version=schema_version,  # type: ignore[arg-type]
                suggestion_status="available",
                reason="exact_single_target_delete",
                alternative=alternative,
            )
        _assert_bounded_type_error(dataclass_exc.value, True, 1.0, "True")

    for path in (123, Path(_EXACT_DELETE_PATH), Path(_CANARY_ABS), b"notes.txt", True, False):
        payload = _valid_available_envelope_mapping()
        alternative_payload = dict(payload["alternative"])  # type: ignore[arg-type]
        alternative_payload["input"] = {"path": path}
        payload["alternative"] = alternative_payload
        with pytest.raises(ValueError) as mapping_exc:
            native_controlled_guidance_envelope_from_mapping(payload)
        _assert_bounded_type_error(mapping_exc.value, path, "123", _EXACT_DELETE_PATH, _CANARY_ABS)
        with pytest.raises(ValueError) as dataclass_exc:
            ControlledAlternativeSuggestion(
                id=NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
                tool_contract=NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
                input={"path": path},  # type: ignore[dict-item]
            )
        _assert_bounded_type_error(dataclass_exc.value, path, "123", _EXACT_DELETE_PATH, _CANARY_ABS)

    for field, value in (
        ("native_tool", 12),
        ("operation", True),
        ("relative_path", 123),
        ("confidence", 1.0),
        ("action_family", b"filesystem"),
        ("reason", Path("exact_single_target_delete")),
    ):
        payload = {**_valid_exact_intent_mapping(), field: value}
        with pytest.raises(ValueError) as mapping_exc:
            native_action_intent_from_mapping(payload)
        _assert_bounded_type_error(mapping_exc.value, value, "123", _CANARY_ABS)
        kwargs = _valid_exact_intent_mapping()
        kwargs[field] = value
        with pytest.raises(ValueError) as dataclass_exc:
            NativeActionIntent(**kwargs)  # type: ignore[arg-type]
        _assert_bounded_type_error(dataclass_exc.value, value, "123", _CANARY_ABS)

    for field, value in (
        ("id", True),
        ("tool_contract", 1.0),
        ("suggestion_status", False),
        ("reason", 2),
    ):
        if field in {"id", "tool_contract"}:
            payload = _valid_available_envelope_mapping()
            alternative_payload = dict(payload["alternative"])  # type: ignore[arg-type]
            alternative_payload[field] = value
            payload["alternative"] = alternative_payload
            with pytest.raises(ValueError) as mapping_exc:
                native_controlled_guidance_envelope_from_mapping(payload)
            _assert_bounded_type_error(mapping_exc.value, value, "True", "1.0")
            alt_kwargs: dict[str, object] = {
                "id": NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
                "tool_contract": NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
                "input": {"path": _EXACT_DELETE_PATH},
            }
            alt_kwargs[field] = value
            with pytest.raises(ValueError) as dataclass_exc:
                ControlledAlternativeSuggestion(**alt_kwargs)  # type: ignore[arg-type]
            _assert_bounded_type_error(dataclass_exc.value, value, "True", "1.0")
            continue
        payload = {**_valid_available_envelope_mapping(), field: value}
        with pytest.raises(ValueError) as mapping_exc:
            native_controlled_guidance_envelope_from_mapping(payload)
        _assert_bounded_type_error(mapping_exc.value, value, "False")
        with pytest.raises(ValueError) as dataclass_exc:
            NativeControlledGuidanceEnvelope(
                schema_version=1,
                suggestion_status=value if field == "suggestion_status" else "available",  # type: ignore[arg-type]
                reason=value if field == "reason" else "exact_single_target_delete",  # type: ignore[arg-type]
                alternative=alternative,
            )
        _assert_bounded_type_error(dataclass_exc.value, value, "False")

    round_trip_intent = native_action_intent_from_mapping(_valid_exact_intent_mapping())
    assert round_trip_intent.public_mapping() == _valid_exact_intent_mapping()
    round_trip_envelope = native_controlled_guidance_envelope_from_mapping(
        _valid_available_envelope_mapping()
    )
    assert round_trip_envelope.public_mapping() == _valid_available_envelope_mapping()
    rebuilt = NativeControlledGuidanceEnvelope(
        schema_version=1,
        suggestion_status="available",
        reason="exact_single_target_delete",
        alternative=_valid_stage_delete_alternative(),
    )
    assert rebuilt.public_mapping() == _valid_available_envelope_mapping()


def test_renderer_reconstructs_nested_alternative_and_rejects_forged_id() -> None:
    envelope = build_native_controlled_guidance_envelope(
        native_tool="apply_patch",
        tool_input={"patch": _EXACT_DELETE_PATCH},
        redirect_route_ready=True,
    )
    assert envelope.alternative is not None
    object.__setattr__(envelope.alternative, "id", "forged.authority.v1")
    with pytest.raises(ValueError):
        format_native_controlled_guidance_text(envelope)
    with pytest.raises(ValueError):
        native_action_intent_from_mapping(
            {
                "native_tool": "apply_patch",
                "operation": "delete",
                "relative_path": "notes.txt",
                "confidence": "exact",
                "action_family": "filesystem",
            }
        )


def _rewrite_downstream(home: Path, downstream: dict) -> None:
    path = home / "mcp-proxy" / "config.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["downstream"] = downstream
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def test_static_route_ready_makes_exact_suggestion_available_without_live() -> None:
    intent = normalize_native_action(
        native_tool="apply_patch",
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    envelope = select_controlled_alternative_suggestion(
        intent,
        redirect_route_ready=False,
        static_route_ready=True,
    )
    _assert_available_envelope(envelope)
    message = native_hook_deny_instruction(
        native_tool="apply_patch",
        risk_class="write",
        redirect_route_ready=False,
        static_route_ready=True,
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    assert message.startswith(NATIVE_STATIC_CONTROLLED_ROUTE_INSTRUCTION)
    assert "suggestion_status=available" in message
    assert "alternative.input.path=notes.txt" in message
    assert "not currently available" not in message
    assert "redirect_context=" not in message
    assert "verified" not in message.lower()


def test_static_route_ready_keeps_ambiguous_intent_unavailable() -> None:
    envelope = build_native_controlled_guidance_envelope(
        native_tool="Bash",
        tool_input={"command": "rm notes.txt extra.txt"},
        redirect_route_ready=False,
        static_route_ready=True,
    )
    _assert_unavailable(envelope, reason="multi_target", leaks=("notes.txt extra.txt",))
    message = native_hook_deny_instruction(
        native_tool="Bash",
        risk_class="write",
        redirect_route_ready=False,
        static_route_ready=True,
        tool_input={"command": "rm notes.txt extra.txt"},
    )
    assert message.startswith(NATIVE_STATIC_CONTROLLED_ROUTE_INSTRUCTION)
    assert "alternative=null" in message
    assert "not currently available" not in message
    assert "No controlled MCP route exists" not in message


def test_trusted_static_controlled_route_ready_matrix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, sandbox, downstream = init_redirect_contract_home(tmp_path)
    project = home.parent
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is True
    assert trusted_static_controlled_route_ready(home=None, project_root=project) is False
    assert trusted_static_controlled_route_ready(home=home, project_root=None) is False
    assert trusted_static_controlled_route_ready(home=True, project_root=project) is False  # type: ignore[arg-type]
    assert trusted_static_controlled_route_ready(home=home, project_root=1.0) is False  # type: ignore[arg-type]
    assert trusted_static_controlled_route_ready(home=str(home), project_root=project) is False  # type: ignore[arg-type]

    monkeypatch.setenv("AGENTVEIL_HOME", str(home))
    assert trusted_static_controlled_route_ready(home=None, project_root=project) is False

    missing = tmp_path / "missing-home"
    missing.mkdir()
    assert trusted_static_controlled_route_ready(home=missing, project_root=project) is False

    (home / "mcp-proxy" / "config.json").write_text("{", encoding="utf-8")
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "fresh")
    project = home.parent
    (home / "mcp-proxy" / "config.json").unlink()
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "named")
    project = home.parent
    broken = dict(downstream)
    broken["name"] = ""
    _rewrite_downstream(home, broken)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "startup")
    project = home.parent
    no_command = dict(downstream)
    no_command.pop("command", None)
    _rewrite_downstream(home, no_command)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "nows")
    project = home.parent
    no_workspace = dict(downstream)
    no_workspace["args"] = list(downstream["args"][:1])
    _rewrite_downstream(home, no_workspace)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    sibling = tmp_path / "sibling-project"
    home, sandbox, downstream = init_redirect_contract_home(sibling)
    assert trusted_static_controlled_route_ready(home=home, project_root=tmp_path) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "outside")
    project = home.parent
    outside = tmp_path / "outside-workspace"
    outside.mkdir()
    escaped = dict(downstream)
    escaped["args"] = [*list(downstream["args"][:-1]), str(outside)]
    _rewrite_downstream(home, escaped)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "escape-src")
    proj = tmp_path / "sym-project"
    proj.mkdir()
    linked_home = proj / "home"
    linked_home.symlink_to(home)
    assert trusted_static_controlled_route_ready(home=linked_home, project_root=proj) is False

    home, sandbox, downstream = init_redirect_contract_home(tmp_path / "wslink")
    project = home.parent
    outside_ws = tmp_path / "wslink-outside"
    outside_ws.mkdir()
    sandbox.rmdir()
    sandbox.symlink_to(outside_ws)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False


_OUTSIDE_CANARY_BYTES = b"outside-canary-static-route-v1\n"


def _outside_canary(path: Path) -> tuple[bytes, int]:
    path.write_bytes(_OUTSIDE_CANARY_BYTES)
    os.chmod(path, 0o640)
    return path.read_bytes(), stat.S_IMODE(path.stat().st_mode)


def _assert_canary_unchanged(path: Path, *, payload: bytes, mode: int) -> None:
    assert path.read_bytes() == payload
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_trusted_static_route_rejects_symlink_and_hardlink_custody(tmp_path: Path) -> None:
    canary = tmp_path / "outside-canary.bin"
    payload, mode = _outside_canary(canary)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "normal")
    assert trusted_static_controlled_route_ready(home=home, project_root=home.parent) is True
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "in-project-home")
    project = home.parent
    alias = project / "home-alias"
    alias.symlink_to(home)
    assert trusted_static_controlled_route_ready(home=alias, project_root=project) is False
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is True
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "external-home")
    proj = tmp_path / "external-home-project"
    proj.mkdir()
    linked_home = proj / "home"
    linked_home.symlink_to(home)
    assert trusted_static_controlled_route_ready(home=linked_home, project_root=proj) is False
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "proxy-dir")
    project = home.parent
    proxy = home / "mcp-proxy"
    real_proxy = home / "mcp-proxy-real"
    proxy.rename(real_proxy)
    proxy.symlink_to(real_proxy)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "config-symlink")
    project = home.parent
    config = home / "mcp-proxy" / "config.json"
    config.unlink()
    config.symlink_to(canary)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path / "config-hardlink")
    project = home.parent
    config = home / "mcp-proxy" / "config.json"
    config.unlink()
    os.link(canary, config)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False
    _assert_canary_unchanged(canary, payload=payload, mode=mode)

    home, sandbox, _downstream = init_redirect_contract_home(tmp_path / "workspace-escape")
    project = home.parent
    outside_ws = tmp_path / "workspace-escape-outside"
    outside_ws.mkdir()
    sandbox.rmdir()
    sandbox.symlink_to(outside_ws)
    assert trusted_static_controlled_route_ready(home=home, project_root=project) is False
    _assert_canary_unchanged(canary, payload=payload, mode=mode)


def test_static_suggestion_does_not_leak_config_or_absolute_paths(tmp_path: Path) -> None:
    home, sandbox, _downstream = init_redirect_contract_home(tmp_path)
    message = native_hook_deny_instruction(
        native_tool="apply_patch",
        risk_class="write",
        redirect_route_ready=False,
        static_route_ready=trusted_static_controlled_route_ready(home=home, project_root=home.parent),
        tool_input={"patch": _EXACT_DELETE_PATCH},
    )
    assert "suggestion_status=available" in message
    assert str(home) not in message
    assert str(sandbox) not in message
    assert _CANARY_ABS not in message
    assert "secret-canary-token" not in message


def test_exact_delete_live_redirect_registers_controlled_stage_delete(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.client_guidance import (
        NATIVE_CONTROLLED_STAGE_DELETE_PLAYBOOK_ID,
        register_exact_delete_redirect_origin,
    )
    from agentveil_mcp_proxy.controlled_alternatives import SEMANTIC_STAGE_DELETE_TOOL_NAME
    from redirect_hook_contract_fixtures import publish_live_hook_binding

    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        origin = register_exact_delete_redirect_origin(
            proxy_home=home,
            native_server="codex",
            native_tool="apply_patch",
            relative_path="notes.txt",
            action_family="filesystem",
            risk_class="write",
        )
        assert origin is not None
        assert origin.redirect_playbook_id == NATIVE_CONTROLLED_STAGE_DELETE_PLAYBOOK_ID
        assert origin.follow_up_tool == SEMANTIC_STAGE_DELETE_TOOL_NAME
        assert origin.redirect_context["redirect_playbook_id"] == "controlled_stage_delete"
    finally:
        fixture.lease.close()

@pytest.mark.parametrize(
    "name",
    [
        "agentveil_stage_delete",
        "agentveil_restore_staged",
        "agentveil_cleanup_staged",
        "agentveil_prepare_patch",
        "agentveil_apply_prepared_patch",
        "agentveil_prepare_git_change",
        "agentveil_git_operation",
        "agentveil_write_file",
        "mcp__agentveil__agentveil_stage_delete",
        "mcp__agentveil__agentveil_restore_staged",
        "mcp__agentveil__agentveil_cleanup_staged",
        "mcp__agentveil__agentveil_prepare_patch",
        "mcp__agentveil__agentveil_apply_prepared_patch",
        "mcp__agentveil__agentveil_prepare_git_change",
        "mcp__agentveil__agentveil_git_operation",
        "mcp__agentveil__agentveil_write_file",
        "mcp__agentveil-mcp-proxy__agentveil_restore_staged",
        "mcp__agentveil_mcp_proxy__agentveil_cleanup_staged",
        "mcp_agentveil_agentveil_stage_delete",
        "mcp_agentveil-mcp-proxy_agentveil_restore_staged",
        "mcp_agentveil_mcp_proxy_agentveil_cleanup_staged",
        "mcp_agentveil_agentveil_prepare_patch",
        "mcp_agentveil_agentveil_apply_prepared_patch",
        "mcp_agentveil_agentveil_prepare_git_change",
        "mcp_agentveil_agentveil_git_operation",
        "mcp_agentveil_agentveil_write_file",
        "MCP:agentveil_stage_delete",
        "agentveil:agentveil_restore_staged",
        "agentveil-mcp-proxy:agentveil_cleanup_staged",
        "agentveil:agentveil_prepare_patch",
        "agentveil:agentveil_apply_prepared_patch",
        "agentveil:agentveil_prepare_git_change",
        "agentveil:agentveil_git_operation",
        "agentveil:agentveil_write_file",
    ],
)
def test_helper_accepts_exact_agentveil_owned_controlled_mcp_tools(name: str) -> None:
    assert is_agentveil_owned_controlled_mcp_tool(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "agentveil_stage_delete_now",
        "agentveil_prepare_git_change_now",
        "agentveil_git_operation_now",
        "agentveil_write_file_now",
        "x_agentveil_stage_delete",
        "agentveil-stage-delete",
        "stage_delete",
        "delete_file",
        "apply_patch",
        "Delete",
        "rm",
        "agentveil_controlled_alternative",
        "mcp__filesystem__agentveil_stage_delete",
        "mcp__agentveil__delete_file",
        "mcp__agentveil__agentveil_stage_delete_x",
        "mcp__agentveil__x_agentveil_stage_delete",
        "mcp_filesystem_agentveil_stage_delete",
        "mcp_evil_not_agentveil_stage_delete",
        "mcp_agentveil_stage_delete",
        "filesystem:agentveil_stage_delete",
        "MCP:write_file",
        " agentveil_stage_delete",
        "agentveil_stage_delete ",
        "	agentveil_stage_delete",
        "mcp__agentveil__agentveil_stage_delete ",
        "MCP:agentveil_stage_delete ",
        "agentveil_stage_delete notes.txt",
        "please call agentveil_stage_delete",
        "rm -rf notes && agentveil_stage_delete",
        "",
    ],
)
def test_helper_rejects_lookalikes_native_and_shell_text(name: str) -> None:
    assert is_agentveil_owned_controlled_mcp_tool(name) is False


def test_helper_rejects_non_string_and_does_not_search_payload_text() -> None:
    for value in (
        None,
        123,
        True,
        ["agentveil_stage_delete"],
        {"tool": "agentveil_stage_delete"},
    ):
        assert is_agentveil_owned_controlled_mcp_tool(value) is False


def _init_git_project(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True, text=True)


def _git_porcelain(path: Path) -> str:
    completed = subprocess.run(
        # claim-check: allow exact git option used to expose untracked fixture files in disposable repos.
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _exclude_text(project: Path) -> str:
    exclude = project / ".git" / "info" / "exclude"
    if not exclude.exists():
        return ""
    return exclude.read_text(encoding="utf-8")


def test_owned_git_exclude_hides_exact_agentveil_control_files_only(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _init_git_project(project)
    for relpath in (
        ".codex/hooks.json",
        ".codex/agentveil/evidence.jsonl",
        ".claude/settings.json",
        ".cursor/hooks.json",
        ".cursor/mcp.json",
        ".gemini/settings.json",
    ):
        path = project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("agentveil-owned\n", encoding="utf-8")
    user_file = project / ".codex" / "agentveil" / "user-notes.md"
    user_file.write_text("user-owned\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("user instructions\n", encoding="utf-8")
    (project / "CLAUDE.md").write_text("user instructions\n", encoding="utf-8")
    (project / "GEMINI.md").write_text("user instructions\n", encoding="utf-8")

    added = add_agentveil_owned_git_excludes(
        project,
        [
            ".codex/hooks.json",
            ".codex/agentveil/evidence.jsonl",
            ".claude/settings.json",
            ".cursor/hooks.json",
            ".cursor/mcp.json",
            ".gemini/settings.json",
            ".codex/agentveil/user-notes.md",
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
            ".codex/",
            "*",
        ],
    )

    assert added == (
        ".claude/settings.json",
        ".codex/agentveil/evidence.jsonl",
        ".codex/hooks.json",
        ".cursor/hooks.json",
        ".cursor/mcp.json",
        ".gemini/settings.json",
    )
    porcelain = _git_porcelain(project)
    assert ".codex/hooks.json" not in porcelain
    assert ".cursor/mcp.json" not in porcelain
    assert ".codex/agentveil/user-notes.md" in porcelain
    assert "AGENTS.md" in porcelain
    assert "CLAUDE.md" in porcelain
    assert "GEMINI.md" in porcelain
    text = _exclude_text(project)
    lines = text.splitlines()
    assert ".codex/" not in lines
    assert "AGENTS.md" not in lines
    assert "CLAUDE.md" not in lines
    assert "GEMINI.md" not in lines
    assert "*" not in lines


def test_owned_git_exclude_uninstall_preserves_user_lines(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _init_git_project(project)
    exclude = project / ".git" / "info" / "exclude"
    exclude.write_text("user-cache/\n", encoding="utf-8")

    add_agentveil_owned_git_excludes(project, (".codex/hooks.json", ".codex/agentveil/evidence.jsonl"))
    removed = remove_agentveil_owned_git_excludes(project, (".codex/hooks.json",))
    assert removed == (".codex/hooks.json",)
    text = _exclude_text(project)
    assert "user-cache/" in text
    assert ".codex/hooks.json" not in text
    assert ".codex/agentveil/evidence.jsonl" in text

    evidence = project / ".codex" / "agentveil" / "evidence.jsonl"
    assert remove_agentveil_owned_git_exclude_if_target_missing(
        project,
        ".codex/agentveil/evidence.jsonl",
        evidence,
    ) == (".codex/agentveil/evidence.jsonl",)
    assert "user-cache/" in _exclude_text(project)


def test_owned_git_exclude_fail_closed_on_unsafe_exclude_file(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _init_git_project(project)
    outside = tmp_path / "outside-exclude"
    outside.write_text("outside\n", encoding="utf-8")
    exclude = project / ".git" / "info" / "exclude"
    exclude.unlink()
    exclude.symlink_to(outside)

    assert add_agentveil_owned_git_excludes(project, (".codex/hooks.json",)) == ()
    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_owned_git_exclude_non_git_project_is_noop(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    assert add_agentveil_owned_git_excludes(project, (".codex/hooks.json",)) == ()
    assert not (project / ".git").exists()
