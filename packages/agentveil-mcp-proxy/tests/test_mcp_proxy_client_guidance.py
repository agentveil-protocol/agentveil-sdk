# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded hook-deny guidance copy in client_guidance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.client_guidance import (
    NATIVE_CONTROLLED_ALTERNATIVE_ID_STAGE_DELETE,
    NATIVE_CONTROLLED_ALTERNATIVE_TOOL_CONTRACT,
    NATIVE_FILE_WRITE_REDIRECT_INSTRUCTION,
    NATIVE_FILE_WRITE_ROUTE_UNAVAILABLE_INSTRUCTION,
    NATIVE_SHELL_HARD_BLOCK_INSTRUCTION,
    NATIVE_SHELL_NO_MCP_ROUTE_INSTRUCTION,
    ControlledAlternativeSuggestion,
    NativeActionIntent,
    NativeControlledGuidanceEnvelope,
    build_native_controlled_guidance_envelope,
    format_native_controlled_guidance_text,
    native_action_intent_from_mapping,
    native_controlled_guidance_envelope_from_mapping,
    native_hook_deny_instruction,
    native_write_redirect_supported,
    normalize_native_action,
    select_controlled_alternative_suggestion,
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
    assert "alternative.id=filesystem.stage_delete.v1" in text
    assert "alternative.tool_contract=agentveil_controlled_alternative" in text
    assert "alternative.input.path=notes.txt" in text
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
            tool_contract="agentveil_controlled_alternative",
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
