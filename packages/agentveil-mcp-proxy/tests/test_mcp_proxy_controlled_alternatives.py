"""Bounded inert Controlled Alternatives provider seam tests (CA1)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import types
import zipfile
from importlib.metadata import Distribution
from pathlib import Path

import pytest

import agentveil_mcp_proxy.controlled_alternatives as ca_mod
from agentveil_mcp_proxy.controlled_alternatives import (
    AUTHORITY_FORBIDDEN_RESULT_KEYS,
    AUTHORITY_STATUS_ACTIVE,
    AUTHORITY_STATUS_DISABLED,
    AUTHORITY_STATUS_EXPIRED,
    AUTHORITY_STATUS_INVALID,
    AUTHORITY_STATUS_MISSING,
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
    CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE,
    CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_AUTHORITY_ENTRYPOINT_GROUP,
    CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
    CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE,
    CONTROLLED_ALTERNATIVE_IDS,
    CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP,
    CONTROLLED_ALTERNATIVE_PROVIDER_ID,
    CONTROLLED_ALTERNATIVES_PROFILE_ID,
    ERROR_AUTHORITY_DUPLICATE,
    ERROR_AUTHORITY_EXPIRED,
    ERROR_AUTHORITY_INVALID,
    ERROR_AUTHORITY_MISSING,
    ERROR_AUTHORITY_SCOPE_REJECTED,
    ERROR_CONTRACT_INCOMPATIBLE,
    ERROR_DESCRIPTOR_INVALID,
    ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT,
    ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED,
    ERROR_DISCOVERY_ENTRYPOINT_MISSING,
    ERROR_DISCOVERY_INELIGIBLE,
    ERROR_GIT_INTENT_DENIED,
    ERROR_REQUEST_MALFORMED,
    ERROR_RESULT_UNSAFE,
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    KNOWN_CONTROLLED_ALTERNATIVE_IDS,
    OPTIONAL_CONTROLLED_ALTERNATIVE_IDS,
    RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION,
    SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME,
    SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
    SEMANTIC_GIT_OPERATION_TOOL_NAME,
    SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
    SEMANTIC_PREPARE_PATCH_TOOL_NAME,
    SEMANTIC_RESTORE_STAGED_TOOL_NAME,
    SEMANTIC_STAGE_DELETE_TOOL_NAME,
    SEMANTIC_WRITE_FILE_TOOL_NAME,
    SEMANTIC_TOOL_BY_ALTERNATIVE_ID,
    ControlledAlternativeAuthoritySnapshot,
    ControlledAlternativeBoundedLocalInput,
    ControlledAlternativeProviderDescriptor,
    ControlledAlternativeProviderResult,
    ControlledAlternativeValidationError,
    build_controlled_alternative_tool_schema,
    build_agentveil_write_file_tool_schema,
    build_semantic_controlled_alternative_tool_schema,
    build_semantic_controlled_alternative_tool_schemas,
    discover_controlled_alternative_authority,
    discover_controlled_alternative_provider,
    git_intent_denied_local_payload,
    inject_agentveil_write_file_tool,
    is_controlled_alternative_tool_name,
    is_semantic_controlled_alternative_tool,
    normalize_agentveil_write_file_call,
    normalize_semantic_tool_call,
    projected_controlled_alternative_validation_payload,
    semantic_alternative_id_for_tool,
    semantic_tool_name_for_alternative_id,
    set_controlled_alternative_authority_loader,
    set_controlled_alternative_provider_loader,
    validate_controlled_alternative_authority,
    validate_controlled_alternative_local_input,
    validate_provider_descriptor,
    validate_provider_request,
    validate_provider_result,
    validate_resource_locator,
)
from agentveil_mcp_proxy.paid_install import (
    FreeBuilderInstallError,
    FreeBuilderWheelExpectations,
    install_state_path,
    install_wheel_to_vendor,
    run_free_builder_install_flow,
    sha256_hex,
    vendor_root,
    verify_free_builder_wheel_artifact,
    write_install_state,
)
from agentveil_mcp_proxy.paid_provider import (
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    PAID_PROVIDER_ENTRYPOINT_GROUP,
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_MISSING,
    PaidProviderSnapshot,
    discover_paid_provider,
    set_paid_provider_loader,
)

if os.name == "nt":
    WORKSPACE_ROOT = r"C:\Users\customer\project"
    STATE_ROOT = r"C:\Users\customer\project\.agentveil"
    SECRET_PATH = r"C:\Users\customer\project\secret.txt"
    SIBLING_WORKSPACE = r"C:\Users\customer\app"
    SIBLING_STATE_ROOT = r"C:\Users\customer\app-other"
    OUTSIDE_ROOT = r"C:\Users\other\workspace"
    RELATIVE_ROOT = r"Users\customer\project"
    NON_NORMALIZED_ROOT = r"C:\Users\customer\project\.\nested"
else:
    WORKSPACE_ROOT = "/Users/customer/project"
    STATE_ROOT = "/Users/customer/project/.agentveil"
    SECRET_PATH = "/Users/customer/project/secret.txt"
    SIBLING_WORKSPACE = "/Users/customer/app"
    SIBLING_STATE_ROOT = "/Users/customer/app-other"
    OUTSIDE_ROOT = "/Users/other/workspace"
    RELATIVE_ROOT = "Users/customer/project"
    NON_NORMALIZED_ROOT = "/Users/customer/project/./nested"

SECRET_PATCH = "password=super-secret-value"
QUARANTINE_ENTRY_ID_CANARY = "cafebabedeadbeef0123456789abcdef"
PREPARED_ARTIFACT_REF_CANARY = "d00df00ddeadbeef0123456789abcdef"
PREPARED_ARTIFACT_HASH_CANARY = "ab" * 32
ROUTE_CANARY = "route-secret-9f3a"
AUTHORITY_TOKEN_CANARY = "ca-upload-token-should-not-leak"
AUTHORITY_LICENSE_CANARY = "license-key-should-not-leak"
SUMMARY_CANARY = "customer-summary-should-not-leak"
STDEV_CANARY = 424242
PRIVATE_MARKER_PATH = "agentveil_private_policy/demo"

FAMILY_INPUTS: dict[str, dict[str, str]] = {
    "filesystem.stage_delete.v1": {"path": "notes.txt"},
    "filesystem.restore_staged.v1": {"quarantine_entry_id": "qe-1"},
    "filesystem.cleanup_staged.v1": {"quarantine_entry_id": "qe-1"},
    "protected_write.prepare_patch.v1": {"path": "notes.txt", "patch": "diff"},
    "git.prepare_local_change.v1": {"worktree_path": "repo"},
}

def _trusted_roots() -> dict[str, str]:
    return {"workspace_root": WORKSPACE_ROOT, "state_root": STATE_ROOT}


FAMILY_LOCATORS: dict[str, dict[str, object]] = {
    "filesystem.stage_delete.v1": {
        "locator_kind": "filesystem_path",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    },
    "filesystem.restore_staged.v1": {
        "locator_kind": "quarantine_entry",
        "quarantine_entry_id": "qe-1",
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    },
    "filesystem.cleanup_staged.v1": {
        "locator_kind": "quarantine_entry",
        "quarantine_entry_id": "qe-1",
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    },
    "protected_write.prepare_patch.v1": {
        "locator_kind": "protected_write_target",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    },
    "git.prepare_local_change.v1": {
        "locator_kind": "git_worktree",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    },
}


def _family_locator(alternative_id: str, **overrides: object) -> dict[str, object]:
    payload = dict(FAMILY_LOCATORS[alternative_id])
    payload.update(overrides)
    return payload


def _active_paid_snapshot(*, private_enabled: bool = True) -> PaidProviderSnapshot:
    return PaidProviderSnapshot(
        provider_present=True,
        provider_id=CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=private_enabled,
        public_fallback_available=True,
        summary="active paid provider",
        error_code=None,
    )


def _active_ca_authority_payload() -> dict[str, object]:
    return {
        "authority_present": True,
        "authority_id": CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
        "contract_version": CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
        "status": AUTHORITY_STATUS_ACTIVE,
        "scope": CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE,
    }


def _active_ca_authority() -> ControlledAlternativeAuthoritySnapshot:
    return validate_controlled_alternative_authority(_active_ca_authority_payload())


def _assert_no_authority_canaries(*values: object) -> None:
    blob = "".join(str(value) for value in values)
    for canary in (
        AUTHORITY_TOKEN_CANARY,
        AUTHORITY_LICENSE_CANARY,
        SECRET_PATH,
        WORKSPACE_ROOT,
        STATE_ROOT,
        ROUTE_CANARY,
        SUMMARY_CANARY,
        PRIVATE_MARKER_PATH,
        "bearer ",
        "/Users/",
    ):
        assert canary not in blob


def _valid_descriptor_payload() -> dict[str, object]:
    return {
        "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_ids": list(CONTROLLED_ALTERNATIVE_IDS),
    }


def _request_payload(alternative_id: str, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": "1",
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_id": alternative_id,
        "operation_ref": "op-1",
        "action_family": "delete",
        "semantic_category": "filesystem",
        "invocation_phase": "propose",
        "resource_locator": dict(FAMILY_LOCATORS[alternative_id]),
    }
    if alternative_id == "protected_write.prepare_patch.v1":
        payload["bounded_local_input"] = {"patch": FAMILY_INPUTS[alternative_id]["patch"]}
    payload.update(overrides)
    return payload


class _FakeProvider:
    def descriptor(self) -> dict[str, object]:
        return dict(_valid_descriptor_payload())


@pytest.fixture(autouse=True)
def _reset_provider_loader() -> None:
    set_controlled_alternative_provider_loader(None)
    set_controlled_alternative_authority_loader(None)
    yield
    set_controlled_alternative_provider_loader(None)
    set_controlled_alternative_authority_loader(None)


def _assert_bounded_error(
    exc_info: pytest.ExceptionInfo,
    code: str,
    *extra_canaries: str,
) -> None:
    assert exc_info.type is ControlledAlternativeValidationError
    assert str(exc_info.value) == code
    rendered = str(exc_info.value)
    for canary in (
        SECRET_PATH,
        SECRET_PATCH,
        WORKSPACE_ROOT,
        STATE_ROOT,
        SIBLING_WORKSPACE,
        SIBLING_STATE_ROOT,
        OUTSIDE_ROOT,
        RELATIVE_ROOT,
        NON_NORMALIZED_ROOT,
        QUARANTINE_ENTRY_ID_CANARY,
        PREPARED_ARTIFACT_REF_CANARY,
        PREPARED_ARTIFACT_HASH_CANARY,
        *extra_canaries,
    ):
        assert canary not in rendered


def test_constants_match_ca0_contract() -> None:
    assert CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP == (
        "agentveil_mcp_proxy.controlled_alternative_providers"
    )
    assert CONTROLLED_ALTERNATIVE_PROVIDER_ID == "private_v1"
    assert CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION == "1"
    assert CONTROLLED_ALTERNATIVES_PROFILE_ID == "controlled_alternatives_coding_v1"
    assert GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME == "agentveil_controlled_alternative"
    assert CONTROLLED_ALTERNATIVE_IDS == (
        "filesystem.stage_delete.v1",
        "filesystem.restore_staged.v1",
        "filesystem.cleanup_staged.v1",
        "protected_write.prepare_patch.v1",
        "git.prepare_local_change.v1",
    )
    assert ca_mod.MAX_RESOURCE_LOCATOR_FIELDS == 8
    assert ca_mod.MAX_RESULT_TOP_LEVEL_KEYS == 14
    assert ca_mod.MAX_QUARANTINE_ENTRY_ID_BYTES == 64
    assert ca_mod.MAX_PREPARED_ARTIFACT_REF_BYTES == 64
    assert ca_mod.MAX_PREPARED_ARTIFACT_REF_CHARS == 32
    assert ca_mod.MAX_PREPARED_ARTIFACT_HASH_CHARS == 64
    assert APPLY_PREPARED_PATCH_ALTERNATIVE_ID == "protected_write.apply_prepared_patch.v1"
    assert OPTIONAL_CONTROLLED_ALTERNATIVE_IDS == frozenset({APPLY_PREPARED_PATCH_ALTERNATIVE_ID})
    assert KNOWN_CONTROLLED_ALTERNATIVE_IDS == (
        frozenset(CONTROLLED_ALTERNATIVE_IDS) | OPTIONAL_CONTROLLED_ALTERNATIVE_IDS
    )
    assert APPLY_PREPARED_PATCH_ALTERNATIVE_ID not in CONTROLLED_ALTERNATIVE_IDS


@pytest.mark.parametrize("alternative_id, raw_input", list(FAMILY_INPUTS.items()))
def test_validate_local_input_accepts_all_five_families(
    alternative_id: str,
    raw_input: dict[str, str],
) -> None:
    parsed = validate_controlled_alternative_local_input(alternative_id, raw_input)
    assert parsed.alternative_id == alternative_id


def test_validate_local_input_rejects_extra_keys_overflow_and_missing() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as extra:
        validate_controlled_alternative_local_input(
            "filesystem.stage_delete.v1",
            {"path": "notes.txt", "secret": True},
        )
    _assert_bounded_error(extra, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_controlled_alternative_local_input("filesystem.stage_delete.v1", {})
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as overflow:
        validate_controlled_alternative_local_input(
            "filesystem.stage_delete.v1",
            {"path": "x" * 5000},
        )
    _assert_bounded_error(overflow, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as utf8:
        validate_controlled_alternative_local_input(
            "filesystem.stage_delete.v1",
            {"path": "é" * 2049},
        )
    _assert_bounded_error(utf8, ERROR_REQUEST_MALFORMED)
    accepted = validate_controlled_alternative_local_input(
        "filesystem.stage_delete.v1",
        {"path": "é" * 2048},
    )
    assert accepted.path is not None
    assert len(accepted.path.encode("utf-8")) == 4096


def test_local_private_marker_path_is_accepted() -> None:
    parsed = validate_controlled_alternative_local_input(
        "filesystem.stage_delete.v1",
        {"path": PRIVATE_MARKER_PATH},
    )
    assert parsed.path == PRIVATE_MARKER_PATH


def test_sensitive_repr_surfaces_are_redacted() -> None:
    local_input = validate_controlled_alternative_local_input(
        "protected_write.prepare_patch.v1",
        {"path": SECRET_PATH, "patch": SECRET_PATCH},
    )
    locator = validate_resource_locator(
        FAMILY_LOCATORS["protected_write.prepare_patch.v1"],
        alternative_id="protected_write.prepare_patch.v1",
    )
    request = validate_provider_request(
        _request_payload(
            "protected_write.prepare_patch.v1",
            bounded_local_input={"patch": SECRET_PATCH},
        )
    )
    bounded = request.bounded_local_input
    assert isinstance(bounded, ControlledAlternativeBoundedLocalInput)
    result = validate_provider_result(
        {
            "contract_version": "1",
            "alternative_id": "filesystem.stage_delete.v1",
            "operation_ref": "op-1",
            "result_status": "error",
            "outcome_class_candidate": "ALTERNATIVE_UNAVAILABLE",
            "target_reached": False,
            "rollback_available": False,
            "error_code": "mechanism_verification_failed",
            "bounded_summary": SUMMARY_CANARY,
        }
    )
    staged = validate_provider_result(
        {
            "contract_version": "1",
            "alternative_id": "filesystem.stage_delete.v1",
            "operation_ref": "op-1",
            "result_status": "success",
            "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
            "target_reached": True,
            "rollback_available": True,
            "quarantine_entry_id": QUARANTINE_ENTRY_ID_CANARY,
        }
    )
    prepared = validate_provider_result(
        {
            "contract_version": "1",
            "alternative_id": "protected_write.prepare_patch.v1",
            "operation_ref": "op-1",
            "result_status": "success",
            "outcome_class_candidate": "PREPARED_FOR_APPROVAL",
            "target_reached": False,
            "rollback_available": False,
            "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
            "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
        }
    )
    for value in (local_input, locator, request, bounded, result, staged, prepared):
        rendered = f"{value!r}{value}"
        assert SECRET_PATH not in rendered
        assert SECRET_PATCH not in rendered
        assert WORKSPACE_ROOT not in rendered
        assert STATE_ROOT not in rendered
        assert ROUTE_CANARY not in rendered
        assert SUMMARY_CANARY not in rendered
        assert QUARANTINE_ENTRY_ID_CANARY not in rendered
        assert PREPARED_ARTIFACT_REF_CANARY not in rendered
        assert PREPARED_ARTIFACT_HASH_CANARY not in rendered
        assert str(STDEV_CANARY) not in rendered
        assert not hasattr(value, "to_dict")


@pytest.mark.parametrize("alternative_id", list(CONTROLLED_ALTERNATIVE_IDS))
def test_validate_provider_request_accepts_locator_matrix(alternative_id: str) -> None:
    request = validate_provider_request(_request_payload(alternative_id))
    assert request.alternative_id == alternative_id
    assert request.resource_locator.workspace_root == WORKSPACE_ROOT
    assert request.resource_locator.state_root == STATE_ROOT
    assert request.resource_locator.st_dev == STDEV_CANARY
    assert SECRET_PATH not in repr(request)
    assert WORKSPACE_ROOT not in repr(request)
    assert STATE_ROOT not in repr(request)
    assert ROUTE_CANARY not in repr(request)
    if alternative_id == "protected_write.prepare_patch.v1":
        assert request.bounded_local_input is not None
        assert request.bounded_local_input.patch == "diff"
        assert not hasattr(request.bounded_local_input, "path")
        assert request.resource_locator.normalized_path == SECRET_PATH
    else:
        assert request.bounded_local_input is None


def test_locator_and_request_reject_cross_field_mismatches() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as bool_dev:
        validate_resource_locator(
            _family_locator("filesystem.stage_delete.v1", st_dev=True),
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(bool_dev, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as missing_path:
        validate_resource_locator(
            {
                "locator_kind": "filesystem_path",
                "workspace_root": WORKSPACE_ROOT,
                "state_root": STATE_ROOT,
                "route_id": "route-1",
                "st_dev": 1,
            },
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(missing_path, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as extra_field:
        validate_resource_locator(
            _family_locator("filesystem.stage_delete.v1", quarantine_entry_id="qe-1"),
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(extra_field, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as kind_mismatch:
        validate_provider_request(
            _request_payload(
                "filesystem.stage_delete.v1",
                resource_locator=FAMILY_LOCATORS["git.prepare_local_change.v1"],
            )
        )
    _assert_bounded_error(kind_mismatch, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as token_mismatch:
        validate_provider_request(
            _request_payload(
                "filesystem.stage_delete.v1",
                correlation_token="token-a",
                resource_locator={
                    **FAMILY_LOCATORS["filesystem.stage_delete.v1"],
                    "correlation_token": "token-b",
                },
            )
        )
    _assert_bounded_error(token_mismatch, ERROR_REQUEST_MALFORMED)

    payload = _request_payload("protected_write.prepare_patch.v1")
    del payload["bounded_local_input"]
    with pytest.raises(ControlledAlternativeValidationError) as omitted_patch:
        validate_provider_request(payload)
    _assert_bounded_error(omitted_patch, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as patch_on_delete:
        validate_provider_request(
            _request_payload(
                "filesystem.stage_delete.v1",
                bounded_local_input={"path": "notes.txt", "patch": "diff"},
            )
        )
    _assert_bounded_error(patch_on_delete, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize("alternative_id", list(CONTROLLED_ALTERNATIVE_IDS))
def test_locator_requires_and_preserves_trusted_roots(alternative_id: str) -> None:
    locator = validate_resource_locator(
        FAMILY_LOCATORS[alternative_id],
        alternative_id=alternative_id,
    )
    assert locator.workspace_root == WORKSPACE_ROOT
    assert locator.state_root == STATE_ROOT
    rendered = f"{locator!r}{locator}"
    assert WORKSPACE_ROOT not in rendered
    assert STATE_ROOT not in rendered
    assert SECRET_PATH not in rendered
    assert ROUTE_CANARY not in rendered
    assert str(STDEV_CANARY) not in rendered
    if alternative_id in {
        "filesystem.restore_staged.v1",
        "filesystem.cleanup_staged.v1",
    }:
        assert locator.normalized_path is None
    else:
        assert locator.normalized_path == SECRET_PATH


@pytest.mark.parametrize("missing_key", ["workspace_root", "state_root"])
@pytest.mark.parametrize("alternative_id", list(CONTROLLED_ALTERNATIVE_IDS))
def test_locator_rejects_missing_trusted_roots(missing_key: str, alternative_id: str) -> None:
    payload = _family_locator(alternative_id)
    del payload[missing_key]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_resource_locator(payload, alternative_id=alternative_id)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize("bad_value", [None, True, False, 1, "", "x" * 5000])
@pytest.mark.parametrize("root_key", ["workspace_root", "state_root"])
def test_locator_rejects_wrong_type_empty_and_oversized_roots(
    bad_value: object,
    root_key: str,
) -> None:
    if isinstance(bad_value, str) and len(bad_value) == 5000:
        bad_value = os.path.join(WORKSPACE_ROOT, bad_value)
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_resource_locator(
            _family_locator("filesystem.stage_delete.v1", **{root_key: bad_value}),
            alternative_id="filesystem.stage_delete.v1",
        )
    extra = (bad_value,) if isinstance(bad_value, str) and bad_value else ()
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED, *extra)


def test_locator_rejects_relative_and_non_normalized_roots() -> None:
    for root_key, bad_value in (
        ("workspace_root", RELATIVE_ROOT),
        ("state_root", RELATIVE_ROOT),
        ("workspace_root", NON_NORMALIZED_ROOT),
        ("state_root", NON_NORMALIZED_ROOT),
    ):
        with pytest.raises(ControlledAlternativeValidationError) as malformed:
            validate_resource_locator(
                _family_locator("filesystem.stage_delete.v1", **{root_key: bad_value}),
                alternative_id="filesystem.stage_delete.v1",
            )
        _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED)


def test_locator_rejects_equal_outside_and_sibling_prefix_state_roots() -> None:
    for bad_state in (WORKSPACE_ROOT, OUTSIDE_ROOT, SIBLING_STATE_ROOT):
        with pytest.raises(ControlledAlternativeValidationError) as malformed:
            validate_resource_locator(
                _family_locator("filesystem.stage_delete.v1", state_root=bad_state),
                alternative_id="filesystem.stage_delete.v1",
            )
        _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED)

    sibling_locator = _family_locator(
        "filesystem.stage_delete.v1",
        workspace_root=SIBLING_WORKSPACE,
        state_root=SIBLING_STATE_ROOT,
        normalized_path=os.path.join(SIBLING_WORKSPACE, "notes.txt"),
    )
    with pytest.raises(ControlledAlternativeValidationError) as sibling:
        validate_resource_locator(
            sibling_locator,
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(sibling, ERROR_REQUEST_MALFORMED)


def test_quarantine_locator_forbids_normalized_path_and_still_requires_roots() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as forbidden_path:
        validate_resource_locator(
            _family_locator("filesystem.restore_staged.v1", normalized_path=SECRET_PATH),
            alternative_id="filesystem.restore_staged.v1",
        )
    _assert_bounded_error(forbidden_path, ERROR_REQUEST_MALFORMED)

    payload = _family_locator("filesystem.cleanup_staged.v1")
    del payload["workspace_root"]
    with pytest.raises(ControlledAlternativeValidationError) as missing_root:
        validate_resource_locator(payload, alternative_id="filesystem.cleanup_staged.v1")
    _assert_bounded_error(missing_root, ERROR_REQUEST_MALFORMED)


def test_locator_rejects_ninth_field_beyond_eight_field_bound() -> None:
    payload = _family_locator(
        "filesystem.stage_delete.v1",
        correlation_token="tok-1",
        extra_one="x",
        extra_two="y",
    )
    assert len(payload) == 9
    with pytest.raises(ControlledAlternativeValidationError) as overflow:
        validate_resource_locator(payload, alternative_id="filesystem.stage_delete.v1")
    _assert_bounded_error(overflow, ERROR_REQUEST_MALFORMED, "tok-1", "extra_one")


@pytest.mark.parametrize(
    "alternative_id",
    [
        "filesystem.stage_delete.v1",
        "filesystem.restore_staged.v1",
        "filesystem.cleanup_staged.v1",
        "git.prepare_local_change.v1",
    ],
)
def test_non_patch_families_reject_bounded_local_input(alternative_id: str) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_request(
            _request_payload(
                alternative_id,
                bounded_local_input=dict(FAMILY_INPUTS[alternative_id]),
            )
        )
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)


def test_protected_provider_payload_is_patch_only() -> None:
    accepted = validate_provider_request(
        _request_payload(
            "protected_write.prepare_patch.v1",
            bounded_local_input={"patch": SECRET_PATCH},
        )
    )
    assert accepted.bounded_local_input is not None
    assert accepted.bounded_local_input.patch == SECRET_PATCH
    assert not hasattr(accepted.bounded_local_input, "path")
    assert accepted.resource_locator.normalized_path == SECRET_PATH
    assert accepted.resource_locator.workspace_root == WORKSPACE_ROOT
    assert accepted.resource_locator.state_root == STATE_ROOT
    assert SECRET_PATCH not in repr(accepted.bounded_local_input)
    assert SECRET_PATH not in repr(accepted)
    assert WORKSPACE_ROOT not in repr(accepted)
    assert STATE_ROOT not in repr(accepted)

    with pytest.raises(ControlledAlternativeValidationError) as raw_path:
        validate_provider_request(
            _request_payload(
                "protected_write.prepare_patch.v1",
                bounded_local_input={"path": "/different/raw/target", "patch": SECRET_PATCH},
            )
        )
    _assert_bounded_error(raw_path, ERROR_REQUEST_MALFORMED)
    assert "/different/raw/target" not in str(raw_path.value)
    assert SECRET_PATCH not in str(raw_path.value)


def test_validate_provider_result_status_and_authority_semantics() -> None:
    success = validate_provider_result(
        {
            "contract_version": "1",
            "alternative_id": "filesystem.stage_delete.v1",
            "operation_ref": "op-1",
            "result_status": "success",
            "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
            "target_reached": True,
            "rollback_available": True,
            "quarantine_entry_id": QUARANTINE_ENTRY_ID_CANARY,
        }
    )
    assert success.result_status == "success"
    assert success.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY

    with pytest.raises(ControlledAlternativeValidationError) as missing_code:
        validate_provider_result(
            {
                "contract_version": "1",
                "alternative_id": "filesystem.stage_delete.v1",
                "operation_ref": "op-1",
                "result_status": "error",
                "outcome_class_candidate": "ALTERNATIVE_UNAVAILABLE",
                "target_reached": False,
                "rollback_available": False,
            }
        )
    _assert_bounded_error(missing_code, ERROR_REQUEST_MALFORMED)

    unknown = validate_provider_result(
        {
            "contract_version": "1",
            "alternative_id": "filesystem.stage_delete.v1",
            "operation_ref": "op-1",
            "result_status": "error",
            "outcome_class_candidate": "ALTERNATIVE_UNAVAILABLE",
            "target_reached": False,
            "rollback_available": False,
            "error_code": "not_a_mechanism_code",
        }
    )
    assert unknown.error_code == "internal_error"

    with pytest.raises(ControlledAlternativeValidationError) as allow_key:
        validate_provider_result(
            {
                "contract_version": "1",
                "alternative_id": "filesystem.stage_delete.v1",
                "operation_ref": "op-1",
                "result_status": "success",
                "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
                "target_reached": True,
                "rollback_available": True,
                "ALLOW": True,
            }
        )
    _assert_bounded_error(allow_key, ERROR_RESULT_UNSAFE)

    with pytest.raises(ControlledAlternativeValidationError) as unsafe_summary:
        validate_provider_result(
            {
                "contract_version": "1",
                "alternative_id": "filesystem.stage_delete.v1",
                "operation_ref": "op-1",
                "result_status": "error",
                "outcome_class_candidate": "ALTERNATIVE_UNAVAILABLE",
                "target_reached": False,
                "rollback_available": False,
                "error_code": "internal_error",
                "bounded_summary": PRIVATE_MARKER_PATH,
            }
        )
    _assert_bounded_error(unsafe_summary, ERROR_RESULT_UNSAFE)


def _valid_result_dataclass(**overrides: object) -> ControlledAlternativeProviderResult:
    payload: dict[str, object] = {
        "contract_version": "1",
        "alternative_id": "filesystem.stage_delete.v1",
        "operation_ref": "op-1",
        "result_status": "success",
        "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
        "target_reached": True,
        "rollback_available": True,
        "error_code": None,
        "bounded_summary": None,
        "quarantine_entry_id": QUARANTINE_ENTRY_ID_CANARY,
    }
    payload.update(overrides)
    return ControlledAlternativeProviderResult(**payload)  # type: ignore[arg-type]


def _result_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": "1",
        "alternative_id": "filesystem.stage_delete.v1",
        "operation_ref": "op-1",
        "result_status": "success",
        "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
        "target_reached": True,
        "rollback_available": True,
        "quarantine_entry_id": QUARANTINE_ENTRY_ID_CANARY,
    }
    payload.update(overrides)
    return payload


def test_validate_provider_result_accepts_and_rechecks_dataclass() -> None:
    accepted = validate_provider_result(_valid_result_dataclass())
    assert accepted.result_status == "success"
    assert accepted.error_code is None
    assert accepted.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY
    round_trip = validate_provider_result(accepted)
    assert round_trip.result_status == "success"
    assert round_trip.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY
    assert QUARANTINE_ENTRY_ID_CANARY not in f"{accepted!r}{accepted}{round_trip!r}{round_trip}"

    with pytest.raises(ControlledAlternativeValidationError) as bad_contract:
        validate_provider_result(_valid_result_dataclass(contract_version="999"))
    _assert_bounded_error(bad_contract, ERROR_CONTRACT_INCOMPATIBLE)

    with pytest.raises(ControlledAlternativeValidationError) as bad_status:
        validate_provider_result(_valid_result_dataclass(result_status="not-a-status"))
    _assert_bounded_error(bad_status, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as success_error:
        validate_provider_result(_valid_result_dataclass(error_code="internal_error"))
    _assert_bounded_error(success_error, ERROR_REQUEST_MALFORMED)

    summary = validate_provider_result(
        _valid_result_dataclass(
            result_status="error",
            outcome_class_candidate="ALTERNATIVE_UNAVAILABLE",
            target_reached=False,
            rollback_available=False,
            error_code="internal_error",
            bounded_summary=SUMMARY_CANARY,
            quarantine_entry_id=None,
        )
    )
    rendered = f"{summary!r}{summary}"
    assert SUMMARY_CANARY not in rendered

    with pytest.raises(ControlledAlternativeValidationError) as leaking:
        validate_provider_result(
            _valid_result_dataclass(
                contract_version="999",
                bounded_summary=SUMMARY_CANARY,
            )
        )
    _assert_bounded_error(leaking, ERROR_CONTRACT_INCOMPATIBLE)
    assert SUMMARY_CANARY not in str(leaking.value)
    assert SUMMARY_CANARY not in repr(leaking.value)
    assert QUARANTINE_ENTRY_ID_CANARY not in str(leaking.value)


@pytest.mark.parametrize("result_status, outcome, extra", [
    ("success", "COMPLETED_WITH_ALTERNATIVE", {}),
    ("error", "ALTERNATIVE_UNAVAILABLE", {"error_code": "mechanism_verification_failed"}),
    ("unavailable", "ALTERNATIVE_UNAVAILABLE", {"error_code": "atomic_relocation_unavailable"}),
])
def test_stage_delete_true_true_requires_and_preserves_quarantine_id(
    result_status: str,
    outcome: str,
    extra: dict[str, str],
) -> None:
    mapping = _result_payload(
        result_status=result_status,
        outcome_class_candidate=outcome,
        **extra,
    )
    parsed = validate_provider_result(mapping)
    assert parsed.result_status == result_status
    assert parsed.target_reached is True
    assert parsed.rollback_available is True
    assert parsed.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY
    assert parsed.error_code == extra.get("error_code")
    rendered = f"{parsed!r}{parsed}"
    assert QUARANTINE_ENTRY_ID_CANARY not in rendered
    again = validate_provider_result(parsed)
    assert again.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY
    assert again.result_status == result_status


@pytest.mark.parametrize("result_status, outcome", [
    ("error", "ALTERNATIVE_UNAVAILABLE"),
    ("unavailable", "ALTERNATIVE_UNAVAILABLE"),
])
def test_stage_delete_true_true_failure_still_requires_error_code(
    result_status: str,
    outcome: str,
) -> None:
    payload = _result_payload(
        result_status=result_status,
        outcome_class_candidate=outcome,
    )
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_result(payload)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)


def test_stage_delete_false_false_forbids_quarantine_id() -> None:
    payload = _result_payload(
        result_status="error",
        outcome_class_candidate="ALTERNATIVE_UNAVAILABLE",
        target_reached=False,
        rollback_available=False,
        error_code="internal_error",
    )
    del payload["quarantine_entry_id"]
    accepted = validate_provider_result(payload)
    assert accepted.quarantine_entry_id is None
    assert accepted.result_status == "error"

    payload["quarantine_entry_id"] = QUARANTINE_ENTRY_ID_CANARY
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize("with_id", [False, True])
def test_stage_delete_false_true_is_malformed(with_id: bool) -> None:
    payload = _result_payload(
        result_status="error",
        outcome_class_candidate="ALTERNATIVE_UNAVAILABLE",
        target_reached=False,
        rollback_available=True,
        error_code="internal_error",
    )
    if not with_id:
        del payload["quarantine_entry_id"]
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(payload)
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize("with_id", [False, True])
def test_stage_delete_success_true_false_is_malformed(with_id: bool) -> None:
    payload = _result_payload(target_reached=True, rollback_available=False)
    if not with_id:
        del payload["quarantine_entry_id"]
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(payload)
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize("result_status", ["error", "unavailable"])
def test_stage_delete_failure_true_false_forbids_id_and_stays_failure(
    result_status: str,
) -> None:
    payload = _result_payload(
        result_status=result_status,
        outcome_class_candidate="ALTERNATIVE_UNAVAILABLE",
        target_reached=True,
        rollback_available=False,
        error_code="mechanism_verification_failed",
    )
    del payload["quarantine_entry_id"]
    parsed = validate_provider_result(payload)
    assert parsed.result_status == result_status
    assert parsed.quarantine_entry_id is None
    assert parsed.error_code == "mechanism_verification_failed"
    payload["quarantine_entry_id"] = QUARANTINE_ENTRY_ID_CANARY
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize(
    "alternative_id",
    [item for item in CONTROLLED_ALTERNATIVE_IDS if item != "filesystem.stage_delete.v1"],
)
def test_other_alternative_results_forbid_quarantine_id(alternative_id: str) -> None:
    payload = _result_payload(alternative_id=alternative_id)
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)
    del payload["quarantine_entry_id"]
    parsed = validate_provider_result(payload)
    assert parsed.alternative_id == alternative_id
    assert parsed.quarantine_entry_id is None


def test_stage_delete_true_true_rejects_absent_quarantine_id() -> None:
    payload = _result_payload()
    del payload["quarantine_entry_id"]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_result(payload)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as missing_dc:
        validate_provider_result(_valid_result_dataclass(quarantine_entry_id=None))
    _assert_bounded_error(missing_dc, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        True,
        1,
        "",
        "a" * 31,
        "a" * 33,
        "a" * 64,
        "A" * 32,
        "g" * 32,
        "a" * 31 + "/",
        "a" * 31 + "\\",
        ".." + "a" * 30,
        "a" * 31 + " ",
        " " + "a" * 31,
    ],
)
def test_stage_delete_rejects_malformed_quarantine_ids(bad_value: object) -> None:
    payload = _result_payload(quarantine_entry_id=bad_value)
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(payload)
    extra = (bad_value,) if isinstance(bad_value, str) and bad_value else ()
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED, *extra)


def test_result_dataclass_cannot_bypass_quarantine_id_validation() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(
            _valid_result_dataclass(quarantine_entry_id="A" * 32)
        )
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED, "A" * 32)
    with pytest.raises(ControlledAlternativeValidationError) as wrong_family:
        validate_provider_result(
            _valid_result_dataclass(
                alternative_id="filesystem.restore_staged.v1",
            )
        )
    _assert_bounded_error(wrong_family, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as invalid_tuple:
        validate_provider_result(
            _valid_result_dataclass(
                target_reached=False,
                rollback_available=True,
                quarantine_entry_id=None,
            )
        )
    _assert_bounded_error(invalid_tuple, ERROR_REQUEST_MALFORMED)


def _prepared_write_result_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": "1",
        "alternative_id": "protected_write.prepare_patch.v1",
        "operation_ref": "op-1",
        "result_status": "success",
        "outcome_class_candidate": "PREPARED_FOR_APPROVAL",
        "target_reached": False,
        "rollback_available": False,
        "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
        "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
    }
    payload.update(overrides)
    return payload


def _prepared_write_result_dataclass(**overrides: object) -> ControlledAlternativeProviderResult:
    payload: dict[str, object] = {
        "contract_version": "1",
        "alternative_id": "protected_write.prepare_patch.v1",
        "operation_ref": "op-1",
        "result_status": "success",
        "outcome_class_candidate": "PREPARED_FOR_APPROVAL",
        "target_reached": False,
        "rollback_available": False,
        "error_code": None,
        "bounded_summary": None,
        "quarantine_entry_id": None,
        "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
        "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
    }
    payload.update(overrides)
    return ControlledAlternativeProviderResult(**payload)  # type: ignore[arg-type]


def test_protected_write_prepared_result_accepts_mapping_and_dataclass() -> None:
    mapping = _prepared_write_result_payload()
    parsed = validate_provider_result(mapping)
    assert parsed.alternative_id == "protected_write.prepare_patch.v1"
    assert parsed.result_status == "success"
    assert parsed.outcome_class_candidate == "PREPARED_FOR_APPROVAL"
    assert parsed.target_reached is False
    assert parsed.rollback_available is False
    assert parsed.prepared_artifact_ref == PREPARED_ARTIFACT_REF_CANARY
    assert parsed.prepared_artifact_hash == PREPARED_ARTIFACT_HASH_CANARY
    assert parsed.quarantine_entry_id is None
    rendered = f"{parsed!r}{parsed}"
    assert PREPARED_ARTIFACT_REF_CANARY not in rendered
    assert PREPARED_ARTIFACT_HASH_CANARY not in rendered
    again = validate_provider_result(parsed)
    assert again.prepared_artifact_ref == PREPARED_ARTIFACT_REF_CANARY
    assert again.prepared_artifact_hash == PREPARED_ARTIFACT_HASH_CANARY

    accepted = validate_provider_result(_prepared_write_result_dataclass())
    assert accepted.prepared_artifact_ref == PREPARED_ARTIFACT_REF_CANARY
    assert accepted.prepared_artifact_hash == PREPARED_ARTIFACT_HASH_CANARY
    round_trip = validate_provider_result(accepted)
    assert round_trip.prepared_artifact_ref == parsed.prepared_artifact_ref
    assert round_trip.prepared_artifact_hash == parsed.prepared_artifact_hash
    assert PREPARED_ARTIFACT_REF_CANARY not in f"{accepted!r}{accepted}{round_trip!r}{round_trip}"


@pytest.mark.parametrize("missing_key", ["prepared_artifact_ref", "prepared_artifact_hash"])
def test_protected_write_prepared_result_requires_both_fields(missing_key: str) -> None:
    payload = _prepared_write_result_payload()
    del payload[missing_key]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_result(payload)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)
    dataclass_kwargs = {missing_key: None}
    with pytest.raises(ControlledAlternativeValidationError) as missing_dc:
        validate_provider_result(_prepared_write_result_dataclass(**dataclass_kwargs))
    _assert_bounded_error(missing_dc, ERROR_REQUEST_MALFORMED)


def test_protected_write_prepared_result_rejects_both_fields_absent() -> None:
    payload = _prepared_write_result_payload()
    del payload["prepared_artifact_ref"]
    del payload["prepared_artifact_hash"]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_result(payload)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)


@pytest.mark.parametrize(
    "overrides",
    [
        {"result_status": "error", "error_code": "internal_error"},
        {"result_status": "unavailable", "error_code": "atomic_relocation_unavailable"},
        {"outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE"},
        {"outcome_class_candidate": "COMPLETED_DIRECTLY"},
        {"target_reached": True},
        {"rollback_available": True},
        {"target_reached": True, "rollback_available": True},
    ],
)
def test_protected_write_wrong_tuple_forbids_prepared_fields(overrides: dict[str, object]) -> None:
    payload = _prepared_write_result_payload(**overrides)
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)
    del payload["prepared_artifact_ref"]
    del payload["prepared_artifact_hash"]
    if payload.get("result_status") == "success":
        parsed = validate_provider_result(payload)
        assert parsed.prepared_artifact_ref is None
        assert parsed.prepared_artifact_hash is None
    else:
        parsed = validate_provider_result(payload)
        assert parsed.result_status == payload["result_status"]
        assert parsed.prepared_artifact_ref is None
        assert parsed.prepared_artifact_hash is None


@pytest.mark.parametrize(
    "result_status, outcome",
    [
        ("error", "ALTERNATIVE_UNAVAILABLE"),
        ("unavailable", "ALTERNATIVE_UNAVAILABLE"),
        ("error", "DENIED"),
    ],
)
def test_protected_write_failure_forbids_prepared_fields(
    result_status: str,
    outcome: str,
) -> None:
    payload = _prepared_write_result_payload(
        result_status=result_status,
        outcome_class_candidate=outcome,
        error_code="internal_error",
    )
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)
    del payload["prepared_artifact_ref"]
    del payload["prepared_artifact_hash"]
    parsed = validate_provider_result(payload)
    assert parsed.result_status == result_status
    assert parsed.prepared_artifact_ref is None
    assert parsed.prepared_artifact_hash is None


@pytest.mark.parametrize(
    "alternative_id",
    [item for item in CONTROLLED_ALTERNATIVE_IDS if item != "protected_write.prepare_patch.v1"],
)
def test_other_alternative_results_forbid_prepared_artifact_fields(alternative_id: str) -> None:
    payload = _prepared_write_result_payload(alternative_id=alternative_id)
    if alternative_id == "filesystem.stage_delete.v1":
        payload["outcome_class_candidate"] = "COMPLETED_WITH_ALTERNATIVE"
        payload["target_reached"] = True
        payload["rollback_available"] = True
        payload["quarantine_entry_id"] = QUARANTINE_ENTRY_ID_CANARY
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)
    del payload["prepared_artifact_ref"]
    del payload["prepared_artifact_hash"]
    parsed = validate_provider_result(payload)
    assert parsed.alternative_id == alternative_id
    assert parsed.prepared_artifact_ref is None
    assert parsed.prepared_artifact_hash is None
    if alternative_id == "filesystem.stage_delete.v1":
        assert parsed.quarantine_entry_id == QUARANTINE_ENTRY_ID_CANARY


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        True,
        1,
        "",
        "a" * 31,
        "a" * 33,
        "A" * 32,
        "g" * 32,
        "a" * 31 + " ",
        " " + "a" * 31,
    ],
)
def test_protected_write_rejects_malformed_prepared_artifact_ref(bad_value: object) -> None:
    payload = _prepared_write_result_payload(prepared_artifact_ref=bad_value)
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(payload)
    extra = (bad_value,) if isinstance(bad_value, str) and bad_value else ()
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED, *extra)


def test_protected_write_rejects_oversized_path_like_and_authority_like_ref() -> None:
    oversized = "a" * (ca_mod.MAX_PREPARED_ARTIFACT_REF_BYTES + 1)
    with pytest.raises(ControlledAlternativeValidationError) as too_big:
        validate_provider_result(_prepared_write_result_payload(prepared_artifact_ref=oversized))
    _assert_bounded_error(too_big, ERROR_REQUEST_MALFORMED, oversized)

    for path_like in (SECRET_PATH, "../artifact", r"C:\artifact", "~artifact", "/tmp/artifact"):
        with pytest.raises(ControlledAlternativeValidationError) as path_exc:
            validate_provider_result(_prepared_write_result_payload(prepared_artifact_ref=path_like))
        _assert_bounded_error(path_exc, ERROR_REQUEST_MALFORMED, path_like)

    for authority_like in (
        "allow",
        "decision",
        "authority_grant",
        "approval_granted",
        "approval_id",
        "evidence_id",
        "bounded_summary",
        "operation_ref",
    ):
        with pytest.raises(ControlledAlternativeValidationError) as authority_exc:
            validate_provider_result(
                _prepared_write_result_payload(prepared_artifact_ref=authority_like)
            )
        _assert_bounded_error(authority_exc, ERROR_REQUEST_MALFORMED, authority_like)

    with pytest.raises(ControlledAlternativeValidationError) as same_as_op:
        validate_provider_result(_prepared_write_result_payload(prepared_artifact_ref="op-1"))
    _assert_bounded_error(same_as_op, ERROR_REQUEST_MALFORMED, "op-1")
    with pytest.raises(ControlledAlternativeValidationError) as same_as_summary:
        validate_provider_result(
            _prepared_write_result_payload(
                bounded_summary=SUMMARY_CANARY,
                prepared_artifact_ref=SUMMARY_CANARY,
            )
        )
    _assert_bounded_error(same_as_summary, ERROR_REQUEST_MALFORMED, SUMMARY_CANARY)


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        True,
        1,
        "",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        "ab" * 31 + "GG",
        PREPARED_ARTIFACT_HASH_CANARY.upper(),
    ],
)
def test_protected_write_rejects_malformed_prepared_artifact_hash(bad_value: object) -> None:
    payload = _prepared_write_result_payload(prepared_artifact_hash=bad_value)
    with pytest.raises(ControlledAlternativeValidationError) as malformed:
        validate_provider_result(payload)
    extra = (bad_value,) if isinstance(bad_value, str) and bad_value else ()
    _assert_bounded_error(malformed, ERROR_REQUEST_MALFORMED, *extra)


def test_protected_write_rejects_extra_and_authority_result_keys() -> None:
    payload = _prepared_write_result_payload(apply=True)
    with pytest.raises(ControlledAlternativeValidationError) as extra:
        validate_provider_result(payload)
    _assert_bounded_error(extra, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as allow_key:
        validate_provider_result(_prepared_write_result_payload(ALLOW=True))
    _assert_bounded_error(allow_key, ERROR_RESULT_UNSAFE)
    overflowing = _prepared_write_result_payload()
    while len(overflowing) <= ca_mod.MAX_RESULT_TOP_LEVEL_KEYS:
        overflowing[f"extra_{len(overflowing)}"] = "x"
    with pytest.raises(ControlledAlternativeValidationError) as too_many:
        validate_provider_result(overflowing)
    _assert_bounded_error(too_many, ERROR_REQUEST_MALFORMED)


def test_result_dataclass_cannot_bypass_prepared_artifact_validation() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as uppercase_hash:
        validate_provider_result(
            _prepared_write_result_dataclass(prepared_artifact_hash="AB" * 32)
        )
    _assert_bounded_error(uppercase_hash, ERROR_REQUEST_MALFORMED, "AB" * 32)
    with pytest.raises(ControlledAlternativeValidationError) as path_ref:
        validate_provider_result(
            _prepared_write_result_dataclass(prepared_artifact_ref=SECRET_PATH)
        )
    _assert_bounded_error(path_ref, ERROR_REQUEST_MALFORMED, SECRET_PATH)
    with pytest.raises(ControlledAlternativeValidationError) as wrong_family:
        validate_provider_result(
            _prepared_write_result_dataclass(
                alternative_id="filesystem.restore_staged.v1",
            )
        )
    _assert_bounded_error(wrong_family, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as wrong_tuple:
        validate_provider_result(
            _prepared_write_result_dataclass(
                target_reached=True,
                rollback_available=False,
            )
        )
    _assert_bounded_error(wrong_tuple, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_result(
            _prepared_write_result_dataclass(
                prepared_artifact_ref=None,
                prepared_artifact_hash=None,
            )
        )
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)


def test_validate_provider_descriptor_rejects_bypass_and_missing_fields() -> None:
    payload = _valid_descriptor_payload()
    payload["alternative_ids"] = list(CONTROLLED_ALTERNATIVE_IDS[:-1])
    with pytest.raises(ControlledAlternativeValidationError) as unknown:
        validate_provider_descriptor(payload)
    _assert_bounded_error(unknown, ERROR_DESCRIPTOR_INVALID)

    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_descriptor({})
    _assert_bounded_error(missing, ERROR_DESCRIPTOR_INVALID)

    bypass = ControlledAlternativeProviderDescriptor(
        provider_id="bad",
        contract_version="999",
        profile_id="bad",
        alternative_ids=("bad",),
    )
    with pytest.raises(ControlledAlternativeValidationError) as bypassed:
        validate_provider_descriptor(bypass)
    _assert_bounded_error(bypassed, ERROR_DESCRIPTOR_INVALID)

    incompatible = ControlledAlternativeProviderDescriptor(
        provider_id=CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        contract_version="999",
        profile_id=CONTROLLED_ALTERNATIVES_PROFILE_ID,
        alternative_ids=CONTROLLED_ALTERNATIVE_IDS,
    )
    with pytest.raises(ControlledAlternativeValidationError) as contract:
        validate_provider_descriptor(incompatible)
    _assert_bounded_error(contract, ERROR_CONTRACT_INCOMPATIBLE)


def test_discovery_paid_snapshot_alone_is_not_ca_authority() -> None:
    calls = {"provider": 0}

    def _count_provider() -> _FakeProvider:
        calls["provider"] += 1
        return _FakeProvider()

    set_controlled_alternative_provider_loader(_count_provider)
    active = _active_paid_snapshot()
    assert active.status == STATUS_ACTIVE
    assert active.private_provider_enabled is True
    result = discover_controlled_alternative_provider(active)
    assert result.available is False
    assert result.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert result.provider is None
    assert calls["provider"] == 0

    disabled_private = _active_paid_snapshot(private_enabled=False)
    disabled = discover_controlled_alternative_provider(disabled_private)
    assert disabled.available is False
    assert disabled.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert calls["provider"] == 0

    missing = PaidProviderSnapshot(provider_present=False, status=STATUS_MISSING)
    assert discover_controlled_alternative_provider(missing).error_code == ERROR_DISCOVERY_INELIGIBLE
    assert calls["provider"] == 0


def test_hybrid_auth_contract_constants() -> None:
    assert CONTROLLED_ALTERNATIVE_AUTHORITY_ENTRYPOINT_GROUP == (
        "agentveil_mcp_proxy.controlled_alternative_authorities"
    )
    assert CONTROLLED_ALTERNATIVE_AUTHORITY_ID == "ca_route_v1"
    assert CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION == "1"
    assert CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE == "controlled_alternatives_route_v1"
    assert CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE == "bounded_summary_upload"
    assert AUTHORITY_STATUS_ACTIVE == "active"
    assert AUTHORITY_STATUS_MISSING == "missing"
    assert AUTHORITY_STATUS_EXPIRED == "expired"
    assert AUTHORITY_STATUS_INVALID == "invalid"
    assert AUTHORITY_STATUS_DISABLED == "disabled"
    assert ca_mod.MAX_AUTHORITY_TOP_LEVEL_KEYS == 7
    assert "route_ready" in ca_mod.BOUNDED_AUTHORITY_INPUT_KEYS


def _provider_call_counter() -> tuple[dict[str, int], object]:
    calls = {"provider": 0}

    def _count_provider() -> _FakeProvider:
        calls["provider"] += 1
        return _FakeProvider()

    set_controlled_alternative_provider_loader(_count_provider)
    return calls, _count_provider


def test_discovery_active_authority_exposes_compatible_provider() -> None:
    calls, _loader = _provider_call_counter()
    result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=_active_ca_authority(),
    )
    assert result.available is True
    assert result.error_code is None
    assert result.descriptor is not None
    assert result.descriptor.provider_id == CONTROLLED_ALTERNATIVE_PROVIDER_ID
    assert result.provider is not None
    assert calls["provider"] == 1
    assert result.descriptor.alternative_ids == CONTROLLED_ALTERNATIVE_IDS


def test_discovery_rejects_console_bounded_summary_upload_scope() -> None:
    calls, _loader = _provider_call_counter()
    payload = _active_ca_authority_payload()
    payload["scope"] = CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE
    with pytest.raises(ControlledAlternativeValidationError) as exc_info:
        validate_controlled_alternative_authority(payload)
    _assert_bounded_error(exc_info, ERROR_AUTHORITY_SCOPE_REJECTED, AUTHORITY_TOKEN_CANARY)
    result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=payload,
    )
    assert result.available is False
    assert result.error_code == ERROR_AUTHORITY_SCOPE_REJECTED
    assert result.provider is None
    assert calls["provider"] == 0
    _assert_no_authority_canaries(result, repr(result), str(result))

    credential_shaped = {
        "schema_version": 1,
        "scope": CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE,
        "token": AUTHORITY_TOKEN_CANARY,
    }
    rejected = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=credential_shaped,
    )
    assert rejected.available is False
    assert rejected.error_code == ERROR_AUTHORITY_INVALID
    assert calls["provider"] == 0
    _assert_no_authority_canaries(rejected, repr(rejected), str(rejected))


def test_discovery_missing_invalid_expired_duplicate_authority_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _loader = _provider_call_counter()
    missing = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=None,
    )
    assert missing.available is False
    assert missing.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert missing.provider is None

    set_controlled_alternative_authority_loader(lambda: None)
    absent_authority = discover_controlled_alternative_authority()
    assert absent_authority.route_ready is False
    assert absent_authority.error_code == ERROR_AUTHORITY_MISSING
    set_controlled_alternative_authority_loader(None)

    malformed = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority={"authority_present": "yes"},
    )
    assert malformed.available is False
    assert malformed.error_code == ERROR_AUTHORITY_INVALID
    assert malformed.provider is None

    expired_payload = _active_ca_authority_payload()
    expired_payload["status"] = AUTHORITY_STATUS_EXPIRED
    expired = validate_controlled_alternative_authority(expired_payload)
    assert expired.route_ready is False
    assert expired.error_code == ERROR_AUTHORITY_EXPIRED
    expired_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=expired,
    )
    assert expired_result.available is False
    assert expired_result.error_code == ERROR_AUTHORITY_EXPIRED
    assert expired_result.provider is None

    invalid_payload = _active_ca_authority_payload()
    invalid_payload["status"] = AUTHORITY_STATUS_INVALID
    invalid_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=invalid_payload,
    )
    assert invalid_result.available is False
    assert invalid_result.error_code == ERROR_AUTHORITY_INVALID
    assert invalid_result.provider is None

    disabled_payload = _active_ca_authority_payload()
    disabled_payload["status"] = AUTHORITY_STATUS_DISABLED
    disabled_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=disabled_payload,
    )
    assert disabled_result.available is False
    assert disabled_result.provider is None

    class _NamedEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        def load(self) -> None:
            raise RuntimeError(AUTHORITY_TOKEN_CANARY)

    def _duplicate(*, group: str | None = None, **_kwargs):
        assert group == CONTROLLED_ALTERNATIVE_AUTHORITY_ENTRYPOINT_GROUP
        return [_NamedEntry(CONTROLLED_ALTERNATIVE_AUTHORITY_ID), _NamedEntry(CONTROLLED_ALTERNATIVE_AUTHORITY_ID)]

    monkeypatch.setattr(ca_mod, "entry_points", _duplicate)
    duplicate_authority = discover_controlled_alternative_authority()
    assert duplicate_authority.route_ready is False
    assert duplicate_authority.error_code == ERROR_AUTHORITY_DUPLICATE
    duplicate_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=duplicate_authority,
    )
    assert duplicate_result.available is False
    assert duplicate_result.error_code == ERROR_AUTHORITY_DUPLICATE
    assert calls["provider"] == 0
    _assert_no_authority_canaries(duplicate_authority, duplicate_result)


def test_validate_authority_rejects_unbounded_markers_and_unexpected_keys() -> None:
    payload = _active_ca_authority_payload()
    payload["authority_id"] = "x" * (ca_mod.MAX_AUTHORITY_ID_BYTES + 1)
    with pytest.raises(ControlledAlternativeValidationError) as oversized:
        validate_controlled_alternative_authority(payload)
    _assert_bounded_error(oversized, ERROR_AUTHORITY_INVALID)

    marked = _active_ca_authority_payload()
    marked["authority_id"] = PRIVATE_MARKER_PATH
    with pytest.raises(ControlledAlternativeValidationError) as marked_exc:
        validate_controlled_alternative_authority(marked)
    _assert_bounded_error(marked_exc, ERROR_AUTHORITY_INVALID, PRIVATE_MARKER_PATH)

    path_like = _active_ca_authority_payload()
    path_like["scope"] = WORKSPACE_ROOT
    with pytest.raises(ControlledAlternativeValidationError) as path_exc:
        validate_controlled_alternative_authority(path_like)
    _assert_bounded_error(path_exc, ERROR_AUTHORITY_INVALID, WORKSPACE_ROOT)

    extra = _active_ca_authority_payload()
    extra["token"] = AUTHORITY_TOKEN_CANARY
    extra["license"] = AUTHORITY_LICENSE_CANARY
    with pytest.raises(ControlledAlternativeValidationError) as extra_exc:
        validate_controlled_alternative_authority(extra)
    _assert_bounded_error(
        extra_exc,
        ERROR_AUTHORITY_INVALID,
        AUTHORITY_TOKEN_CANARY,
        AUTHORITY_LICENSE_CANARY,
    )

    self_asserted = ControlledAlternativeAuthoritySnapshot(
        authority_present=True,
        authority_id=CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
        contract_version=CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
        status=AUTHORITY_STATUS_ACTIVE,
        scope=CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE,
        route_ready=True,
        error_code=None,
    )
    forged = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=self_asserted,
    )
    assert forged.available is False
    assert forged.error_code == ERROR_AUTHORITY_SCOPE_REJECTED


def test_authority_to_dict_is_valid_mapping_input() -> None:
    snapshot = _active_ca_authority()
    exported = snapshot.to_dict()
    assert "route_ready" in exported
    assert exported["route_ready"] is True
    calls, _loader = _provider_call_counter()
    round_trip = validate_controlled_alternative_authority(exported)
    assert round_trip.route_ready is True
    assert round_trip.scope == CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE
    result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=exported,
    )
    assert result.available is True
    assert result.error_code is None
    assert result.provider is not None
    assert calls["provider"] == 1


def test_forged_route_ready_does_not_grant_ca_authority() -> None:
    calls, _loader = _provider_call_counter()
    upload = _active_ca_authority_payload()
    upload["scope"] = CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE
    upload["route_ready"] = True
    with pytest.raises(ControlledAlternativeValidationError) as upload_exc:
        validate_controlled_alternative_authority(upload)
    _assert_bounded_error(upload_exc, ERROR_AUTHORITY_SCOPE_REJECTED)
    upload_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=upload,
    )
    assert upload_result.available is False
    assert upload_result.error_code == ERROR_AUTHORITY_SCOPE_REJECTED
    assert upload_result.provider is None

    expired = _active_ca_authority_payload()
    expired["status"] = AUTHORITY_STATUS_EXPIRED
    expired["route_ready"] = True
    expired_snapshot = validate_controlled_alternative_authority(expired)
    assert expired_snapshot.route_ready is False
    assert expired_snapshot.error_code == ERROR_AUTHORITY_EXPIRED
    expired_result = discover_controlled_alternative_provider(
        _active_paid_snapshot(),
        authority=expired,
    )
    assert expired_result.available is False
    assert expired_result.error_code == ERROR_AUTHORITY_EXPIRED
    assert expired_result.provider is None
    assert calls["provider"] == 0

    not_bool = _active_ca_authority_payload()
    not_bool["route_ready"] = AUTHORITY_TOKEN_CANARY
    with pytest.raises(ControlledAlternativeValidationError) as type_exc:
        validate_controlled_alternative_authority(not_bool)
    _assert_bounded_error(type_exc, ERROR_AUTHORITY_INVALID, AUTHORITY_TOKEN_CANARY)


def test_authority_status_error_repr_hide_privacy_canaries() -> None:
    snapshot = _active_ca_authority()
    assert snapshot.route_ready is True
    rendered = f"{snapshot!r}{snapshot}{snapshot.to_dict()}"
    _assert_no_authority_canaries(rendered)

    set_controlled_alternative_authority_loader(
        lambda: {
            "authority_present": True,
            "authority_id": CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
            "contract_version": CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
            "status": AUTHORITY_STATUS_ACTIVE,
            "scope": CONSOLE_BOUNDED_SUMMARY_UPLOAD_SCOPE,
            "token": AUTHORITY_TOKEN_CANARY,
            "error_code": AUTHORITY_LICENSE_CANARY,
        }
    )
    discovered = discover_controlled_alternative_authority()
    assert discovered.route_ready is False
    assert discovered.error_code == ERROR_AUTHORITY_INVALID
    _assert_no_authority_canaries(discovered, repr(discovered), discovered.to_dict())

    def _boom() -> None:
        raise RuntimeError(f"secret {AUTHORITY_TOKEN_CANARY} {WORKSPACE_ROOT}")

    set_controlled_alternative_authority_loader(_boom)
    failed = discover_controlled_alternative_authority()
    assert failed.route_ready is False
    assert failed.error_code == ERROR_AUTHORITY_INVALID
    _assert_no_authority_canaries(failed, repr(failed), str(failed))


def test_discovery_returns_compatible_descriptor_from_loader() -> None:
    set_controlled_alternative_provider_loader(lambda: _FakeProvider())
    result = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert result.available is True
    assert result.descriptor is not None
    assert result.descriptor.alternative_ids == CONTROLLED_ALTERNATIVE_IDS
    assert result.error_code is None


def test_discovery_rejects_incompatible_descriptor_from_loader() -> None:
    class _BadProvider:
        def descriptor(self) -> dict[str, object]:
            payload = _valid_descriptor_payload()
            payload["contract_version"] = "999"
            return payload

    set_controlled_alternative_provider_loader(lambda: _BadProvider())
    result = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert result.available is False
    assert result.error_code == ERROR_CONTRACT_INCOMPATIBLE


def test_discovery_malformed_snapshot_and_entry_point_errors_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    none_result = discover_controlled_alternative_provider(None)
    assert none_result.available is False
    assert none_result.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert "provider_present" not in repr(none_result)

    malformed_result = discover_controlled_alternative_provider(object())  # type: ignore[arg-type]
    assert malformed_result.available is False
    assert malformed_result.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert "AttributeError" not in repr(malformed_result)

    canary = "CA1_ENUM_CANARY_SECRET"

    def _boom(*, group: str | None = None, **_kwargs):
        del group
        raise RuntimeError(canary)

    monkeypatch.setattr(ca_mod, "entry_points", _boom)
    enumerated = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert enumerated.available is False
    assert enumerated.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert canary not in repr(enumerated)
    assert canary not in str(enumerated)


def test_discovery_loader_none_and_exception_are_load_failed() -> None:
    set_controlled_alternative_provider_loader(lambda: None)
    none_result = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert none_result.available is False
    assert none_result.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED

    def _boom() -> None:
        raise RuntimeError("loader exploded")

    set_controlled_alternative_provider_loader(_boom)
    boom_result = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert boom_result.available is False
    assert boom_result.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert "exploded" not in str(boom_result)


def test_build_tool_schema_is_discriminated_and_deterministic() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    descriptor = validate_provider_descriptor(_valid_descriptor_payload())
    first = build_controlled_alternative_tool_schema(descriptor)
    second = build_controlled_alternative_tool_schema(descriptor)
    assert first == second
    assert first["name"] == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME
    schema = first["inputSchema"]
    assert "oneOf" in schema
    assert len(schema["oneOf"]) == len(CONTROLLED_ALTERNATIVE_IDS)
    for branch, alternative_id in zip(schema["oneOf"], CONTROLLED_ALTERNATIVE_IDS, strict=True):
        assert branch["additionalProperties"] is False
        assert branch["properties"]["alternative_id"] == {"const": alternative_id}
        assert branch["required"] == ["alternative_id", "input"]
        jsonschema.validate(
            {"alternative_id": alternative_id, "input": FAMILY_INPUTS[alternative_id]},
            branch,
        )
    assert SECRET_PATH not in json.dumps(first)
    assert "default" not in json.dumps(schema)


@pytest.mark.parametrize("alternative_id", list(CONTROLLED_ALTERNATIVE_IDS))
@pytest.mark.parametrize("other_id", list(CONTROLLED_ALTERNATIVE_IDS))
def test_tool_schema_rejects_mismatched_alternative_input_pairs(
    alternative_id: str,
    other_id: str,
) -> None:
    if alternative_id == other_id:
        pytest.skip("matched pair is the positive schema case")
    if set(FAMILY_INPUTS[alternative_id]) == set(FAMILY_INPUTS[other_id]):
        pytest.skip("identical input shape; alternative_id const is the discriminant")
    jsonschema = pytest.importorskip("jsonschema")
    schema = build_controlled_alternative_tool_schema(
        validate_provider_descriptor(_valid_descriptor_payload())
    )["inputSchema"]
    payload = {
        "alternative_id": alternative_id,
        "input": dict(FAMILY_INPUTS[other_id]),
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)


COMPATIBLE_PROVIDER_SOURCE = """
class _Provider:
    def descriptor(self):
        return {
            "provider_id": "private_v1",
            "contract_version": "1",
            "profile_id": "controlled_alternatives_coding_v1",
            "alternative_ids": [
                "filesystem.stage_delete.v1",
                "filesystem.restore_staged.v1",
                "filesystem.cleanup_staged.v1",
                "protected_write.prepare_patch.v1",
                "git.prepare_local_change.v1",
            ],
        }

def build_provider():
    return _Provider()
"""


def _write_disposable_distribution(
    tmp_path: Path,
    *,
    dist_name: str,
    module_name: str,
    source: str,
) -> Path:
    package = tmp_path / module_name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(source, encoding="utf-8")
    dist_info = tmp_path / f"{module_name}-0.1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Name: {dist_name}\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {module_name}:build_provider\n",
        encoding="utf-8",
    )
    return dist_info


def _entry_points_from_dist(dist_info: Path):
    dist = Distribution.at(dist_info)
    return [
        entry
        for entry in dist.entry_points
        if entry.group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
    ]


def test_importlib_metadata_discovery_loads_disposable_distribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist_info = _write_disposable_distribution(
        tmp_path,
        dist_name="ca1-disposable-provider",
        module_name="ca1_disposable_provider",
        source=COMPATIBLE_PROVIDER_SOURCE,
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    real_entries = _entry_points_from_dist(dist_info)
    assert [entry.name for entry in real_entries] == ["private_v1"]
    loaded = real_entries[0].load()
    provider = loaded() if callable(loaded) else loaded
    assert validate_provider_descriptor(provider.descriptor()).provider_id == "private_v1"

    proxy_src = str(Path(__file__).resolve().parents[1])
    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    probe = r"""
import json
import sys
import types
from pathlib import Path

tmp_root, proxy_src = sys.argv[1], sys.argv[2]
sys.path[:0] = [tmp_root, proxy_src]
sys.path[:] = [
    path
    for path in sys.path
    if "site-packages" not in path and "dist-packages" not in path
]
pkg = types.ModuleType("agentveil_mcp_proxy")
pkg.__path__ = [str(Path(proxy_src) / "agentveil_mcp_proxy")]
pkg.__file__ = str(Path(proxy_src) / "agentveil_mcp_proxy" / "__init__.py")
sys.modules["agentveil_mcp_proxy"] = pkg

from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
    CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE,
    CONTROLLED_ALTERNATIVE_IDS,
    discover_controlled_alternative_provider,
    validate_controlled_alternative_authority,
)
from agentveil_mcp_proxy.paid_provider import (
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    PaidProviderSnapshot,
)

authority = validate_controlled_alternative_authority({
    "authority_present": True,
    "authority_id": CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
    "contract_version": CONTROLLED_ALTERNATIVE_AUTHORITY_CONTRACT_VERSION,
    "status": "active",
    "scope": CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE,
})
result = discover_controlled_alternative_provider(
    PaidProviderSnapshot(
        provider_present=True,
        provider_id="private_v1",
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=True,
    ),
    authority=authority,
)
print(json.dumps({
    "available": result.available,
    "error_code": result.error_code,
    "alternative_ids": (
        list(result.descriptor.alternative_ids) if result.descriptor is not None else None
    ),
}))
"""
    completed = subprocess.run(
        [sys.executable, "-S", "-c", probe, str(tmp_path), proxy_src],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["available"] is True
    assert payload["error_code"] is None
    assert payload["alternative_ids"] == list(CONTROLLED_ALTERNATIVE_IDS)


def test_importlib_metadata_discovery_reports_missing_duplicate_and_load_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _missing(*, group: str | None = None, **_kwargs):
        del group
        return []

    monkeypatch.setattr(ca_mod, "entry_points", _missing)
    monkeypatch.setenv("AVP_HOME", str(tmp_path / "empty-home"))
    missing = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert missing.available is False
    assert missing.error_code == ERROR_DISCOVERY_ENTRYPOINT_MISSING

    first = _write_disposable_distribution(
        tmp_path / "one",
        dist_name="ca1-one",
        module_name="ca1_one_provider",
        source=COMPATIBLE_PROVIDER_SOURCE,
    )
    second = _write_disposable_distribution(
        tmp_path / "two",
        dist_name="ca1-two",
        module_name="ca1_two_provider",
        source=COMPATIBLE_PROVIDER_SOURCE,
    )
    monkeypatch.syspath_prepend(str(tmp_path / "one"))
    monkeypatch.syspath_prepend(str(tmp_path / "two"))
    duplicates = _entry_points_from_dist(first) + _entry_points_from_dist(second)

    def _duplicate(*, group: str | None = None, **_kwargs):
        assert group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
        return duplicates

    monkeypatch.setattr(ca_mod, "entry_points", _duplicate)
    duplicate = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert duplicate.available is False
    assert duplicate.error_code == ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT

    broken = _write_disposable_distribution(
        tmp_path / "broken",
        dist_name="ca1-broken",
        module_name="ca1_broken_provider",
        source="def build_provider():\n    raise RuntimeError('cannot load')\n",
    )
    monkeypatch.syspath_prepend(str(tmp_path / "broken"))

    def _broken(*, group: str | None = None, **_kwargs):
        assert group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
        return _entry_points_from_dist(broken)

    monkeypatch.setattr(ca_mod, "entry_points", _broken)
    load_failed = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert load_failed.available is False
    assert load_failed.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert "cannot load" not in str(load_failed)


VENDORED_CA_PACKAGE_NAME = "agentveil-private-policy"
VENDORED_CA_PACKAGE_VERSION = "0.1.0"
VENDORED_CA_MODULE_NAME = VENDORED_CA_PACKAGE_NAME.replace("-", "_")

VENDORED_CA_PROVIDER_SOURCE = '''
class _Provider:
    calls = []

    def descriptor(self):
        self.calls.append("descriptor")
        return {
            "provider_id": "private_v1",
            "contract_version": "1",
            "profile_id": "controlled_alternatives_coding_v1",
            "alternative_ids": [
                "filesystem.stage_delete.v1",
                "filesystem.restore_staged.v1",
                "filesystem.cleanup_staged.v1",
                "protected_write.prepare_patch.v1",
                "git.prepare_local_change.v1",
            ],
        }

    def propose(self, request):
        self.calls.append("propose")
        raise RuntimeError("CA1B_PHASE_CANARY")

    def execute(self, request):
        self.calls.append("execute")
        raise RuntimeError("CA1B_PHASE_CANARY")

    def verify(self, request):
        self.calls.append("verify")
        raise RuntimeError("CA1B_PHASE_CANARY")

def build_provider():
    return _Provider()
'''


def _controlled_alternative_entry_points_text(*, target: str) -> str:
    return (
        f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {target}\n"
    )


def _build_controlled_alternative_wheel(
    tmp_path: Path,
    *,
    source: str = VENDORED_CA_PROVIDER_SOURCE,
    entry_points: str | None = None,
) -> bytes:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.whl"
    if entry_points is None:
        entry_points = _controlled_alternative_entry_points_text(
            target=f"{VENDORED_CA_MODULE_NAME}.controlled_provider:build_provider",
        )
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{VENDORED_CA_MODULE_NAME}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{VENDORED_CA_MODULE_NAME}/controlled_provider.py", source)
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {VENDORED_CA_PACKAGE_NAME}\nVersion: {VENDORED_CA_PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/entry_points.txt",
            entry_points,
        )
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return wheel_path.read_bytes()


def _install_active_controlled_alternative_vendor(home: Path, *, wheel_bytes: bytes) -> None:
    metadata = verify_free_builder_wheel_artifact(
        wheel_bytes,
        expectations=FreeBuilderWheelExpectations(
            artifact_hash=sha256_hex(wheel_bytes),
            artifact_size_bytes=len(wheel_bytes),
            package_name=VENDORED_CA_PACKAGE_NAME,
            package_version=VENDORED_CA_PACKAGE_VERSION,
        ),
    )
    vendor_dir = vendor_root(home) / f"{metadata.package_name}-{metadata.package_version}"
    wheel_path = home / "paid" / "cache" / f"{metadata.package_name}-{metadata.package_version}.whl"
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    wheel_path.write_bytes(wheel_bytes)
    install_wheel_to_vendor(
        home=home,
        wheel_path=wheel_path,
        target_dir=vendor_dir,
        expected_package_name=metadata.package_name,
        expected_package_version=metadata.package_version,
        require_empty_target=True,
    )
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
            "package_name": metadata.package_name,
            "package_version": metadata.package_version,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )


def _no_global_controlled_entries(*, group: str | None = None, **_kwargs):
    assert group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
    return []


def test_discover_controlled_alternative_from_active_vendored_free_builder_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    monkeypatch.setattr(ca_mod, "entry_points", _no_global_controlled_entries)
    wheel_bytes = _build_controlled_alternative_wheel(tmp_path / "wheel")
    _install_active_controlled_alternative_vendor(home, wheel_bytes=wheel_bytes)

    result = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert result.available is True
    assert result.error_code is None
    assert result.descriptor is not None
    assert result.descriptor.provider_id == "private_v1"
    assert result.descriptor.alternative_ids == CONTROLLED_ALTERNATIVE_IDS
    assert SECRET_PATH not in repr(result)
    vendor_dir = vendor_root(home) / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}"
    assert str(vendor_dir.resolve()) not in sys.path
    assert not any(
        key == VENDORED_CA_MODULE_NAME or key.startswith(f"{VENDORED_CA_MODULE_NAME}.")
        for key in sys.modules
    )


def test_global_duplicate_and_load_failure_do_not_use_vendored_controlled_alternative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes = _build_controlled_alternative_wheel(tmp_path / "wheel")
    _install_active_controlled_alternative_vendor(home, wheel_bytes=wheel_bytes)

    first = _write_disposable_distribution(
        tmp_path / "one",
        dist_name="ca1b-one",
        module_name="ca1b_one_provider",
        source=COMPATIBLE_PROVIDER_SOURCE,
    )
    second = _write_disposable_distribution(
        tmp_path / "two",
        dist_name="ca1b-two",
        module_name="ca1b_two_provider",
        source=COMPATIBLE_PROVIDER_SOURCE,
    )
    duplicates = _entry_points_from_dist(first) + _entry_points_from_dist(second)

    def _duplicate(*, group: str | None = None, **_kwargs):
        assert group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
        return duplicates

    monkeypatch.setattr(ca_mod, "entry_points", _duplicate)
    duplicate = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert duplicate.available is False
    assert duplicate.error_code == ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT

    broken = _write_disposable_distribution(
        tmp_path / "broken",
        dist_name="ca1b-broken",
        module_name="ca1b_broken_provider",
        source="def build_provider():\n    raise RuntimeError('CA1B_GLOBAL_LOAD_CANARY')\n",
    )

    def _broken(*, group: str | None = None, **_kwargs):
        assert group == CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP
        return _entry_points_from_dist(broken)

    monkeypatch.setattr(ca_mod, "entry_points", _broken)
    load_failed = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert load_failed.available is False
    assert load_failed.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert "CA1B_GLOBAL_LOAD_CANARY" not in str(load_failed)
    assert "CA1B_GLOBAL_LOAD_CANARY" not in repr(load_failed)


def test_vendored_controlled_alternative_failures_map_to_bounded_ca1_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    monkeypatch.setattr(ca_mod, "entry_points", _no_global_controlled_entries)

    missing_wheel = _build_controlled_alternative_wheel(
        tmp_path / "missing",
        entry_points="[agentveil_mcp_proxy.paid_providers]\nprivate_v1 = agentveil_private_policy.controlled_provider:build_provider\n",
    )
    _install_active_controlled_alternative_vendor(home, wheel_bytes=missing_wheel)
    missing = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert missing.available is False
    assert missing.error_code == ERROR_DISCOVERY_ENTRYPOINT_MISSING

    factory_home = tmp_path / "factory-home"
    monkeypatch.setenv("AVP_HOME", str(factory_home))
    canary = "CA1B_FACTORY_CANARY"
    factory_wheel = _build_controlled_alternative_wheel(
        tmp_path / "factory",
        source=f"def build_provider():\n    raise RuntimeError({canary!r})\n",
    )
    _install_active_controlled_alternative_vendor(factory_home, wheel_bytes=factory_wheel)
    factory_failed = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert factory_failed.available is False
    assert factory_failed.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert canary not in str(factory_failed)
    assert canary not in repr(factory_failed)

    malformed_home = tmp_path / "malformed-home"
    monkeypatch.setenv("AVP_HOME", str(malformed_home))
    malformed_wheel = _build_controlled_alternative_wheel(
        tmp_path / "malformed",
        entry_points=(
            f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
            "private_v1 = not-a-valid-target\n"
        ),
    )
    _install_active_controlled_alternative_vendor(malformed_home, wheel_bytes=malformed_wheel)
    malformed = discover_controlled_alternative_provider(_active_paid_snapshot(), authority=_active_ca_authority())
    assert malformed.available is False
    assert malformed.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert "not-a-valid-target" not in str(malformed)
    assert "not-a-valid-target" not in repr(malformed)


FREE_BUILDER_CREDENTIAL = "ca1b-free-builder-credential"
PAID_PROVIDER_SOURCE = """
class _Provider:
    provider_id = "private_v1"
    provider_contract_version = "1"

    def status(self):
        return {
            "provider_present": True,
            "provider_id": self.provider_id,
            "provider_contract_version": self.provider_contract_version,
            "status": "active",
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "Vendored provider active.",
            "error_code": None,
        }

    def activate(self, *, license_key):
        del license_key
        return self.status()

    def deactivate(self):
        return {
            "provider_present": False,
            "provider_id": None,
            "provider_contract_version": self.provider_contract_version,
            "status": "missing",
            "private_provider_enabled": False,
            "public_fallback_available": True,
            "summary": None,
            "error_code": None,
        }

def build_vendored_provider():
    return _Provider()
"""
HANDOFF_HOOK_SOURCE = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""


def _assembled_entry_points_text(*, include_paid_provider: bool = True) -> str:
    lines = [
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]",
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = {VENDORED_CA_MODULE_NAME}.handoff_hook:run_activation_handoff",
        "",
        f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]",
        f"private_v1 = {VENDORED_CA_MODULE_NAME}.controlled_provider:build_provider",
    ]
    if include_paid_provider:
        lines.extend(
            [
                "",
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]",
                f"private_v1 = {VENDORED_CA_MODULE_NAME}.vendored_provider:build_vendored_provider",
            ]
        )
    return "\n".join(lines) + "\n"


def _build_assembled_free_builder_wheel(
    tmp_path: Path,
    *,
    include_paid_provider: bool = True,
    controlled_source: str = VENDORED_CA_PROVIDER_SOURCE,
) -> tuple[bytes, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{VENDORED_CA_MODULE_NAME}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{VENDORED_CA_MODULE_NAME}/handoff_hook.py", HANDOFF_HOOK_SOURCE)
        archive.writestr(f"{VENDORED_CA_MODULE_NAME}/controlled_provider.py", controlled_source)
        if include_paid_provider:
            archive.writestr(f"{VENDORED_CA_MODULE_NAME}/vendored_provider.py", PAID_PROVIDER_SOURCE)
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {VENDORED_CA_PACKAGE_NAME}\nVersion: {VENDORED_CA_PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/entry_points.txt",
            _assembled_entry_points_text(include_paid_provider=include_paid_provider),
        )
        archive.writestr(
            f"{VENDORED_CA_MODULE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    wheel_bytes = wheel_path.read_bytes()
    return wheel_bytes, sha256_hex(wheel_bytes)


def _free_builder_expectations(wheel_bytes: bytes, artifact_hash: str) -> FreeBuilderWheelExpectations:
    return FreeBuilderWheelExpectations(
        artifact_hash=artifact_hash,
        artifact_size_bytes=len(wheel_bytes),
        package_name=VENDORED_CA_PACKAGE_NAME,
        package_version=VENDORED_CA_PACKAGE_VERSION,
    )


def test_run_free_builder_install_flow_discovers_controlled_alternative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    monkeypatch.setattr(ca_mod, "entry_points", _no_global_controlled_entries)
    set_paid_provider_loader(None)
    wheel_bytes, artifact_hash = _build_assembled_free_builder_wheel(tmp_path / "wheel")
    before_path = list(sys.path)
    sentinel = types.ModuleType(VENDORED_CA_MODULE_NAME)
    monkeypatch.setitem(sys.modules, VENDORED_CA_MODULE_NAME, sentinel)

    result = run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=home,
        activation_credential=FREE_BUILDER_CREDENTIAL,
        expectations=_free_builder_expectations(wheel_bytes, artifact_hash),
    )
    assert result.install_state["status"] == STATUS_ACTIVE
    install_payload = json.loads(install_state_path(home).read_text(encoding="utf-8"))
    assert install_payload["status"] == STATUS_ACTIVE
    assert install_payload["package_name"] == VENDORED_CA_PACKAGE_NAME
    assert install_payload["package_version"] == VENDORED_CA_PACKAGE_VERSION
    vendor_dir = vendor_root(home) / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}"
    assert vendor_dir.is_dir()
    assert not vendor_dir.is_symlink()
    assert (home / "paid" / "cache" / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}.whl").is_file()

    paid_snapshot = discover_paid_provider()
    assert paid_snapshot.status == STATUS_ACTIVE
    assert paid_snapshot.private_provider_enabled is True
    from agentveil_mcp_proxy.paid_install import resolve_vendored_controlled_alternative_provider

    provider, resolve_error = resolve_vendored_controlled_alternative_provider(home=home)
    assert resolve_error is None
    assert provider is not None
    assert getattr(provider, "calls", None) == []

    paid_only = discover_controlled_alternative_provider(paid_snapshot)
    assert paid_only.available is False
    assert paid_only.error_code == ERROR_DISCOVERY_INELIGIBLE
    assert paid_only.provider is None
    assert getattr(provider, "calls", None) == []

    controlled = discover_controlled_alternative_provider(
        paid_snapshot,
        authority=_active_ca_authority(),
    )
    assert controlled.available is True
    assert controlled.error_code is None
    assert controlled.descriptor is not None
    assert controlled.descriptor.alternative_ids == CONTROLLED_ALTERNATIVE_IDS
    assert FREE_BUILDER_CREDENTIAL not in repr(controlled)
    assert str(home) not in repr(controlled)
    assert str(vendor_dir.resolve()) not in sys.path
    assert sys.path == before_path
    assert sys.modules.get(VENDORED_CA_MODULE_NAME) is sentinel


def test_run_free_builder_install_flow_restores_prior_state_when_provider_inactive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    prior = {
        "status": STATUS_MISSING,
        "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        "package_name": VENDORED_CA_PACKAGE_NAME,
        "package_version": VENDORED_CA_PACKAGE_VERSION,
        "public_fallback_available": True,
        "error_code": None,
        "last_installed_at": "2026-08-01T00:00:00+00:00",
        "install_safety_state": "verified",
        "install_safety_reason": None,
    }
    write_install_state(install_state_path(home), prior)
    prior_bytes = install_state_path(home).read_bytes()
    wheel_bytes, artifact_hash = _build_assembled_free_builder_wheel(
        tmp_path / "wheel",
        include_paid_provider=False,
    )
    with pytest.raises(FreeBuilderInstallError, match="provider_not_active"):
        run_free_builder_install_flow(
            wheel_bytes=wheel_bytes,
            home=home,
            activation_credential=FREE_BUILDER_CREDENTIAL,
            expectations=_free_builder_expectations(wheel_bytes, artifact_hash),
        )
    assert install_state_path(home).read_bytes() == prior_bytes
    vendor_dir = vendor_root(home) / f"{VENDORED_CA_PACKAGE_NAME}-{VENDORED_CA_PACKAGE_VERSION}"
    assert not vendor_dir.exists()
    assert FREE_BUILDER_CREDENTIAL not in install_state_path(home).read_text(encoding="utf-8")


def test_semantic_tool_constants_and_mapping() -> None:
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME == "agentveil_stage_delete"
    assert SEMANTIC_RESTORE_STAGED_TOOL_NAME == "agentveil_restore_staged"
    assert SEMANTIC_CLEANUP_STAGED_TOOL_NAME == "agentveil_cleanup_staged"
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME == "agentveil_prepare_patch"
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME == "agentveil_prepare_git_change"
    assert semantic_alternative_id_for_tool(SEMANTIC_STAGE_DELETE_TOOL_NAME) == (
        "filesystem.stage_delete.v1"
    )
    assert semantic_alternative_id_for_tool(SEMANTIC_PREPARE_PATCH_TOOL_NAME) == (
        "protected_write.prepare_patch.v1"
    )
    assert semantic_alternative_id_for_tool(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME) == (
        "git.prepare_local_change.v1"
    )
    assert semantic_alternative_id_for_tool(SEMANTIC_GIT_OPERATION_TOOL_NAME) == (
        "git.prepare_local_change.v1"
    )
    assert semantic_tool_name_for_alternative_id("git.prepare_local_change.v1") == (
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME
    )
    assert is_semantic_controlled_alternative_tool(SEMANTIC_STAGE_DELETE_TOOL_NAME)
    assert is_semantic_controlled_alternative_tool(SEMANTIC_PREPARE_PATCH_TOOL_NAME)
    assert is_semantic_controlled_alternative_tool(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME)
    assert is_semantic_controlled_alternative_tool(SEMANTIC_GIT_OPERATION_TOOL_NAME)
    assert is_controlled_alternative_tool_name(GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME)
    assert is_controlled_alternative_tool_name(SEMANTIC_STAGE_DELETE_TOOL_NAME)
    assert is_controlled_alternative_tool_name(SEMANTIC_PREPARE_PATCH_TOOL_NAME)
    assert is_controlled_alternative_tool_name(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME)
    assert is_controlled_alternative_tool_name(SEMANTIC_GIT_OPERATION_TOOL_NAME)
    assert not is_semantic_controlled_alternative_tool(GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME)


def test_semantic_schemas_project_filesystem_and_prepare_when_advertised() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    descriptor = validate_provider_descriptor(_valid_descriptor_payload())
    schemas = build_semantic_controlled_alternative_tool_schemas(descriptor)
    assert [schema["name"] for schema in schemas] == [
        SEMANTIC_STAGE_DELETE_TOOL_NAME,
        SEMANTIC_RESTORE_STAGED_TOOL_NAME,
        SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
        SEMANTIC_PREPARE_PATCH_TOOL_NAME,
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        SEMANTIC_GIT_OPERATION_TOOL_NAME,
    ]
    stage = schemas[0]
    assert stage["inputSchema"]["additionalProperties"] is False
    assert "alternative_id" not in json.dumps(stage["inputSchema"])
    jsonschema.validate({"path": "notes.txt"}, stage["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"path": "notes.txt", "alternative_id": "x"}, stage["inputSchema"])
    prepare = schemas[3]
    jsonschema.validate({"path": "notes.txt", "patch": "diff"}, prepare["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"path": "notes.txt"}, prepare["inputSchema"])
    dumped = json.dumps(prepare)
    assert "workspace_root" not in dumped
    assert "state_root" not in dumped
    assert "route_id" not in dumped
    assert "st_dev" not in dumped
    assert "prepared_artifact_ref" not in prepare["inputSchema"]["properties"]
    git_schema = schemas[4]
    assert git_schema["name"] == SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME
    assert git_schema["inputSchema"]["additionalProperties"] is False
    assert set(git_schema["inputSchema"]["required"]) == {"worktree_path"}
    assert set(git_schema["inputSchema"]["properties"]) == {"worktree_path", "intent"}
    jsonschema.validate({"worktree_path": "."}, git_schema["inputSchema"])
    jsonschema.validate(
        {"worktree_path": ".", "intent": "prepare_for_review"},
        git_schema["inputSchema"],
    )
    jsonschema.validate(
        {"worktree_path": ".", "intent": "commit"},
        git_schema["inputSchema"],
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"worktree_path": ".", "alternative_id": "x"}, git_schema["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"path": "repo"}, git_schema["inputSchema"])
    git_dumped = json.dumps(git_schema)
    assert "workspace_root" not in git_dumped
    assert "state_root" not in git_dumped
    assert "route_id" not in git_dumped
    assert "st_dev" not in git_dumped
    assert "diff" not in git_dumped.lower()
    assert "remote" not in git_dumped.lower()
    assert "branch" not in git_dumped.lower()
    assert "agentveil_private_policy" not in git_dumped
    git_operation = schemas[5]
    assert git_operation["name"] == SEMANTIC_GIT_OPERATION_TOOL_NAME
    assert git_operation["inputSchema"]["additionalProperties"] is False
    assert set(git_operation["inputSchema"]["required"]) == {"worktree_path", "operation"}
    assert set(git_operation["inputSchema"]["properties"]) == {"worktree_path", "operation"}
    jsonschema.validate(
        {"worktree_path": ".", "operation": "prepare_for_review"},
        git_operation["inputSchema"],
    )
    jsonschema.validate(
        {"worktree_path": ".", "operation": "commit"},
        git_operation["inputSchema"],
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"worktree_path": "."}, git_operation["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"worktree_path": ".", "operation": "prepare_for_review", "intent": "commit"},
            git_operation["inputSchema"],
        )
    op_dumped = json.dumps(git_operation)
    assert "bounded denial is the controlled completion signal" in op_dumped
    assert "workspace_root" not in op_dumped
    assert "state_root" not in op_dumped
    assert "route_id" not in op_dumped
    assert "remote" not in op_dumped.lower()
    assert "branch" not in op_dumped.lower()
    assert "agentveil_private_policy" not in op_dumped


def test_normalize_semantic_tool_call_maps_to_generic_shape() -> None:
    mapped = normalize_semantic_tool_call(
        SEMANTIC_STAGE_DELETE_TOOL_NAME,
        {"path": "notes.txt"},
    )
    assert mapped == {
        "alternative_id": "filesystem.stage_delete.v1",
        "input": {"path": "notes.txt"},
    }
    prepared = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_PATCH_TOOL_NAME,
        {"path": "notes.txt", "patch": "diff"},
    )
    assert prepared == {
        "alternative_id": "protected_write.prepare_patch.v1",
        "input": {"path": "notes.txt", "patch": "diff"},
    }
    git_prepared = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": "."},
    )
    assert git_prepared == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": "."},
    }


def test_normalize_semantic_tool_call_rejects_malformed_input() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as exc:
        normalize_semantic_tool_call(SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": "notes.txt", "extra": 1})
    _assert_bounded_error(exc, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as wrong_type:
        normalize_semantic_tool_call(SEMANTIC_RESTORE_STAGED_TOOL_NAME, {"quarantine_entry_id": 123})
    _assert_bounded_error(wrong_type, ERROR_REQUEST_MALFORMED)


def test_semantic_mapping_is_immutable_and_total() -> None:
    with pytest.raises(TypeError):
        SEMANTIC_TOOL_BY_ALTERNATIVE_ID["filesystem.stage_delete.v1"] = "mutated"  # type: ignore[index]
    assert not hasattr(ca_mod, "_SEMANTIC_TOOL_BY_ALTERNATIVE_ID_RAW")
    for name, value in vars(ca_mod).items():
        if name.startswith("_SEMANTIC") and isinstance(value, dict):
            pytest.fail(f"mutable semantic backing dict exposed: {name}")
    assert semantic_alternative_id_for_tool(1) is None
    assert semantic_alternative_id_for_tool("unknown") is None
    assert semantic_tool_name_for_alternative_id(1) is None
    assert semantic_tool_name_for_alternative_id("unknown") is None
    with pytest.raises(ControlledAlternativeValidationError) as unknown_alt:
        build_semantic_controlled_alternative_tool_schema("unknown")
    _assert_bounded_error(unknown_alt, ERROR_DESCRIPTOR_INVALID)
    stage = build_semantic_controlled_alternative_tool_schema("filesystem.stage_delete.v1")
    assert "agentveil_stage_delete" in stage["description"]
    assert "native destructive delete may be denied" in stage["description"]
    restore = build_semantic_controlled_alternative_tool_schema("filesystem.restore_staged.v1")
    assert "agentveil_restore_staged(quarantine_entry_id)" in restore["description"]
    cleanup = build_semantic_controlled_alternative_tool_schema("filesystem.cleanup_staged.v1")
    assert "agentveil_cleanup_staged(quarantine_entry_id)" in cleanup["description"]
    assert "approval" in cleanup["description"]
    prepare = build_semantic_controlled_alternative_tool_schema("protected_write.prepare_patch.v1")
    assert "agentveil_prepare_patch" in prepare["description"]
    assert "does not apply the patch" in prepare["description"]
    assert "not authority" in prepare["description"]
    assert "existing workspace file" in prepare["description"]
    assert "ordinary file creation" in prepare["description"]
    assert "Prefer this AgentVeil tool" not in prepare["description"]
    assert "create a new file" in prepare["inputSchema"]["properties"]["path"]["description"]
    git_tool = build_semantic_controlled_alternative_tool_schema("git.prepare_local_change.v1")
    assert "agentveil_prepare_git_change" in git_tool["description"]
    assert "does not commit" in git_tool["description"]
    assert "not authority" in git_tool["description"]
    assert "push" in git_tool["description"]
    assert "prepare_for_review" in git_tool["description"]
    assert "intent=commit" in git_tool["description"]
    assert "those intents are denied" in git_tool["description"]
    assert "bounded denial is the controlled completion signal" in git_tool["description"]
    assert SECRET_PATH not in git_tool["description"]
    assert WORKSPACE_ROOT not in git_tool["description"]
    assert "agentveil_private_policy" not in git_tool["description"]


_RESTORE_HANDOFF_PRIVACY_CANARIES = (
    "/Users/",
    "/private/",
    "/var/folders/",
    "agentveil_private_policy",
    "Codex",
    "Claude",
    "Cursor",
    "Gemini",
)


def _assert_restore_handoff_surface_is_bounded(text: str) -> None:
    lowered = text.lower()
    for canary in _RESTORE_HANDOFF_PRIVACY_CANARIES:
        assert canary not in text
    assert "authority_grant" not in lowered
    assert "approval_granted" not in lowered
    assert "approval_binding_ref" not in lowered


def test_semantic_restore_handoff_schema_pair_is_self_describing() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    stage = build_semantic_controlled_alternative_tool_schema("filesystem.stage_delete.v1")
    restore = build_semantic_controlled_alternative_tool_schema("filesystem.restore_staged.v1")
    cleanup = build_semantic_controlled_alternative_tool_schema("filesystem.cleanup_staged.v1")
    generic = build_controlled_alternative_tool_schema(validate_provider_descriptor(_valid_descriptor_payload()))

    assert RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION in stage["description"]
    assert "quarantine_entry_id" in stage["description"]
    assert RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION in restore["description"]
    restore_id = restore["inputSchema"]["properties"]["quarantine_entry_id"]["description"]
    assert restore_id.startswith(RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION)
    assert "not authority" in restore_id
    jsonschema.validate({"quarantine_entry_id": "a" * 32}, restore["inputSchema"])

    assert "Requires explicit approval" in cleanup["description"]
    assert "not the autonomous next step" in cleanup["description"].lower()
    cleanup_id = cleanup["inputSchema"]["properties"]["quarantine_entry_id"]["description"]
    assert "approval" in cleanup_id.lower()
    assert "autonomous next step" in cleanup_id.lower()

    assert generic["name"] == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME
    dumped = json.dumps([stage, restore, cleanup, generic])
    _assert_restore_handoff_surface_is_bounded(dumped)
    for schema in (stage, restore, cleanup, generic):
        assert AUTHORITY_FORBIDDEN_RESULT_KEYS.isdisjoint(schema)
        props = schema.get("inputSchema", {}).get("properties", {})
        assert AUTHORITY_FORBIDDEN_RESULT_KEYS.isdisjoint(props)
    assert '"allow"' not in dumped
    assert '"authority_grant"' not in dumped


def test_malformed_restore_id_fails_closed_without_handoff_fields() -> None:
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        normalize_semantic_tool_call(SEMANTIC_RESTORE_STAGED_TOOL_NAME, {})
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as wrong_type:
        normalize_semantic_tool_call(SEMANTIC_RESTORE_STAGED_TOOL_NAME, {"quarantine_entry_id": 123})
    _assert_bounded_error(wrong_type, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as extra:
        normalize_semantic_tool_call(
            SEMANTIC_RESTORE_STAGED_TOOL_NAME,
            {"quarantine_entry_id": "a" * 32, "path": "notes.txt"},
        )
    _assert_bounded_error(extra, ERROR_REQUEST_MALFORMED)


def test_normalize_semantic_prepare_rejects_malformed_and_untrusted_input() -> None:
    valid = {"path": "notes.txt", "patch": "diff"}
    cases = (
        {"path": "notes.txt"},
        {"patch": "diff"},
        {"path": "notes.txt", "patch": "diff", "extra": 1},
        {"path": "notes.txt", "patch": "diff", "workspace_root": "/tmp"},
        {"path": "notes.txt", "patch": "diff", "route_id": "r1"},
        {"path": "notes.txt", "patch": "diff", "st_dev": 1},
        {"path": 123, "patch": "diff"},
        {"path": "notes.txt", "patch": 123},
        {"path": "/tmp/notes.txt", "patch": "diff"},
        {"path": "../notes.txt", "patch": "diff"},
        {"path": "notes.txt/../secret.txt", "patch": "diff"},
        {"path": r"C:\secret.txt", "patch": "diff"},
        {"path": "C:/secret.txt", "patch": "diff"},
        {"path": "notes.txt\n", "patch": "diff"},
        {"path": "notes\x00.txt", "patch": "diff"},
        {"path": "notes.txt", "patch": "diff\0more"},
        {"path": "notes.txt", "patch": "x" * (ca_mod.MAX_PATCH_BYTES + 1)},
        {"path": SECRET_PATH, "patch": SECRET_PATCH},
    )
    for payload in cases:
        with pytest.raises(ControlledAlternativeValidationError) as exc:
            normalize_semantic_tool_call(SEMANTIC_PREPARE_PATCH_TOOL_NAME, payload)
        _assert_bounded_error(exc, ERROR_REQUEST_MALFORMED, "diff", "diff\0more")
    accepted = normalize_semantic_tool_call(SEMANTIC_PREPARE_PATCH_TOOL_NAME, valid)
    assert accepted["input"]["path"] == "notes.txt"
    dumped = f"{accepted!r}{accepted}"
    assert SECRET_PATH not in dumped
    assert WORKSPACE_ROOT not in dumped
    assert STATE_ROOT not in dumped
    assert "agentveil_private_policy" not in dumped


@pytest.mark.parametrize(
    "drive_path",
    [
        r"C:\secret.txt",
        "C:/secret.txt",
    ],
)
def test_normalize_semantic_prepare_rejects_windows_drive_paths_on_any_host(
    drive_path: str,
) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as exc:
        normalize_semantic_tool_call(
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": drive_path, "patch": "diff"},
        )
    _assert_bounded_error(exc, ERROR_REQUEST_MALFORMED, drive_path, r"C:\secret.txt", "C:/secret.txt")
    accepted = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_PATCH_TOOL_NAME,
        {"path": "notes.txt", "patch": "diff"},
    )
    assert accepted == {
        "alternative_id": "protected_write.prepare_patch.v1",
        "input": {"path": "notes.txt", "patch": "diff"},
    }


def test_normalize_semantic_git_rejects_malformed_and_untrusted_input() -> None:
    valid = {"worktree_path": "."}
    cases = (
        {},
        {"worktree_path": "." , "extra": 1},
        {"path": "repo"},
        {"worktree_path": ".", "alternative_id": "git.prepare_local_change.v1"},
        {"worktree_path": ".", "workspace_root": "/tmp"},
        {"worktree_path": ".", "state_root": "/tmp"},
        {"worktree_path": ".", "route_id": "r1"},
        {"worktree_path": ".", "st_dev": 1},
        {"worktree_path": 123},
        {"worktree_path": None},
        {"worktree_path": ["."]},
        {"worktree_path": "/tmp/repo"},
        {"worktree_path": "../repo"},
        {"worktree_path": "repo/../secret"},
        {"worktree_path": r"C:\secret"},
        {"worktree_path": "C:/secret"},
        {"worktree_path": "repo\n"},
        {"worktree_path": "repo\x00"},
        {"worktree_path": "~repo"},
        {"worktree_path": SECRET_PATH},
        {"worktree_path": " . "},
        {"worktree_path": " repo"},
        {"worktree_path": "repo "},
        {"worktree_path": "\t."},
        {"worktree_path": ".\t"},
        {"worktree_path": ".", "approval_granted": True},
        {"worktree_path": ".", "allow": True},
    )
    for payload in cases:
        with pytest.raises(ControlledAlternativeValidationError) as exc:
            normalize_semantic_tool_call(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, payload)
        code = str(exc.value)
        assert code in {ERROR_REQUEST_MALFORMED, ERROR_RESULT_UNSAFE}
        _assert_bounded_error(exc, code, "diff", "origin", "main")
    accepted = normalize_semantic_tool_call(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, valid)
    assert accepted == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": "."},
    }
    rel = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": "repo"},
    )
    assert rel["input"]["worktree_path"] == "repo"
    dumped = f"{accepted!r}{accepted}{rel!r}{rel}"
    assert SECRET_PATH not in dumped
    assert WORKSPACE_ROOT not in dumped
    assert STATE_ROOT not in dumped
    assert "agentveil_private_policy" not in dumped
    assert ROUTE_CANARY not in dumped


def test_git_intent_prepare_for_review_normalizes_to_existing_path() -> None:
    omitted = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": "."},
    )
    explicit = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": ".", "intent": "prepare_for_review"},
    )
    parsed = validate_controlled_alternative_local_input(
        "git.prepare_local_change.v1",
        {"worktree_path": ".", "intent": "prepare_for_review"},
    )
    assert omitted == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": "."},
    }
    assert explicit == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": ".", "intent": "prepare_for_review"},
    }
    assert parsed.alternative_id == "git.prepare_local_change.v1"
    assert parsed.worktree_path == "."
    assert "intent" not in parsed.__dict__ or parsed.__dict__.get("intent") is None
    rendered = f"{parsed!r}{parsed}{explicit!r}{explicit}"
    assert SECRET_PATH not in rendered
    assert WORKSPACE_ROOT not in rendered
    assert "/Users/" not in rendered
    assert "agentveil_private_policy" not in rendered


@pytest.mark.parametrize("forbidden_intent", ["commit", "push"])
def test_git_intent_commit_and_push_are_denied(forbidden_intent: str) -> None:
    payload = {"worktree_path": ".", "intent": forbidden_intent}
    with pytest.raises(ControlledAlternativeValidationError) as local_denied:
        validate_controlled_alternative_local_input("git.prepare_local_change.v1", payload)
    _assert_bounded_error(
        local_denied,
        ERROR_GIT_INTENT_DENIED,
        forbidden_intent,
        "/Users/",
        "origin",
        "origin/main",
    )
    with pytest.raises(ControlledAlternativeValidationError) as semantic_denied:
        normalize_semantic_tool_call(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, payload)
    _assert_bounded_error(
        semantic_denied,
        ERROR_GIT_INTENT_DENIED,
        forbidden_intent,
        "/Users/",
        "origin",
        "origin/main",
    )
    payload = git_intent_denied_local_payload()
    assert payload == {
        "mechanism_status": "error",
        "error_code": ERROR_GIT_INTENT_DENIED,
        "result_status": "denied",
        "decision": "denied",
        "target_reached": False,
        "rollback_available": False,
        "verification_level": "not_verified",
    }
    projected = projected_controlled_alternative_validation_payload(semantic_denied.value)
    assert projected == payload
    malformed = projected_controlled_alternative_validation_payload(
        ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    )
    assert malformed["error_code"] == ERROR_REQUEST_MALFORMED
    assert malformed.get("result_status") != "denied"
    assert "decision" not in malformed


def test_git_operation_prepare_for_review_maps_to_existing_path() -> None:
    mapped = normalize_semantic_tool_call(
        SEMANTIC_GIT_OPERATION_TOOL_NAME,
        {"worktree_path": ".", "operation": "prepare_for_review"},
    )
    assert mapped == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": ".", "intent": "prepare_for_review"},
    }
    compat = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": "."},
    )
    assert compat == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": "."},
    }
    dumped = f"{mapped!r}{mapped}{compat!r}{compat}"
    assert SECRET_PATH not in dumped
    assert "/Users/" not in dumped
    assert "agentveil_private_policy" not in dumped


@pytest.mark.parametrize("forbidden_operation", ["commit", "push"])
def test_git_operation_commit_and_push_are_denied(forbidden_operation: str) -> None:
    payload = {"worktree_path": ".", "operation": forbidden_operation}
    with pytest.raises(ControlledAlternativeValidationError) as denied:
        normalize_semantic_tool_call(SEMANTIC_GIT_OPERATION_TOOL_NAME, payload)
    _assert_bounded_error(
        denied,
        ERROR_GIT_INTENT_DENIED,
        forbidden_operation,
        "/Users/",
        "origin",
        "origin/main",
    )
    assert projected_controlled_alternative_validation_payload(denied.value) == (
        git_intent_denied_local_payload()
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"worktree_path": "."},
        {"operation": "prepare_for_review"},
        {"worktree_path": ".", "operation": "rebase"},
        {"worktree_path": ".", "operation": "COMMIT"},
        {"worktree_path": ".", "operation": " commit"},
        {"worktree_path": ".", "operation": "commit\n"},
        {"worktree_path": ".", "operation": 123},
        {"worktree_path": ".", "operation": None},
        {"worktree_path": ".", "operation": "prepare_for_review", "intent": "commit"},
        {"worktree_path": ".", "operation": "prepare_for_review", "extra": 1},
        {"worktree_path": ".", "operation": "prepare_for_review", "allow": True},
        {"worktree_path": "/tmp/repo", "operation": "prepare_for_review"},
        {"worktree_path": "../repo", "operation": "prepare_for_review"},
    ],
)
def test_git_operation_malformed_fields_fail_closed(payload: dict[str, object]) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as denied:
        normalize_semantic_tool_call(SEMANTIC_GIT_OPERATION_TOOL_NAME, payload)
    code = str(denied.value)
    assert code in {ERROR_REQUEST_MALFORMED, ERROR_RESULT_UNSAFE}
    assert code != ERROR_GIT_INTENT_DENIED


@pytest.mark.parametrize(
    "payload",
    [
        {"worktree_path": ".", "intent": "rebase"},
        {"worktree_path": ".", "intent": "COMMIT"},
        {"worktree_path": ".", "intent": "Push"},
        {"worktree_path": ".", "intent": " commit"},
        {"worktree_path": ".", "intent": "commit "},
        {"worktree_path": ".", "intent": "\tcommit"},
        {"worktree_path": ".", "intent": "commit\n"},
        {"worktree_path": ".", "intent": "commit\x00"},
        {"worktree_path": ".", "intent": ""},
        {"worktree_path": ".", "intent": " "},
        {"worktree_path": ".", "intent": 123},
        {"worktree_path": ".", "intent": None},
        {"worktree_path": ".", "intent": ["commit"]},
        {"worktree_path": ".", "intent": {"commit": True}},
        {"worktree_path": ".", "intent": "prepare_for_review", "extra": 1},
        {"worktree_path": ".", "intent": "allow"},
        {"worktree_path": ".", "approval_granted": True},
        {"worktree_path": ".", "intent": "prepare_for_review", "allow": True},
    ],
)
def test_git_intent_malformed_and_authority_fields_fail_closed(payload: dict[str, object]) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as denied:
        validate_controlled_alternative_local_input("git.prepare_local_change.v1", payload)
    code = str(denied.value)
    assert code in {ERROR_REQUEST_MALFORMED, ERROR_RESULT_UNSAFE}
    extra = tuple(
        value for value in payload.values() if isinstance(value, str) and value
    )
    _assert_bounded_error(denied, code, *extra, "/Users/", "origin/main")
    with pytest.raises(ControlledAlternativeValidationError) as semantic:
        normalize_semantic_tool_call(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, payload)
    assert str(semantic.value) in {ERROR_REQUEST_MALFORMED, ERROR_RESULT_UNSAFE}


@pytest.mark.parametrize(
    "drive_path",
    [
        r"C:\secret",
        "C:/secret",
    ],
)
def test_normalize_semantic_git_rejects_windows_drive_paths_on_any_host(
    drive_path: str,
) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as exc:
        normalize_semantic_tool_call(
            SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
            {"worktree_path": drive_path},
        )
    _assert_bounded_error(exc, ERROR_REQUEST_MALFORMED, drive_path, r"C:\secret", "C:/secret")
    accepted = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
        {"worktree_path": "."},
    )
    assert accepted == {
        "alternative_id": "git.prepare_local_change.v1",
        "input": {"worktree_path": "."},
    }


def _apply_descriptor_payload() -> dict[str, object]:
    payload = _valid_descriptor_payload()
    payload["alternative_ids"] = list(CONTROLLED_ALTERNATIVE_IDS) + [
        APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    ]
    return payload


def _apply_locator(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "locator_kind": "prepared_write_artifact",
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
        **_trusted_roots(),
    }
    payload.update(overrides)
    return payload


def _apply_local_input(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
        "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
    }
    payload.update(overrides)
    return payload


def _apply_request_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": "1",
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_id": APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
        "operation_ref": "op-1",
        "action_family": "write",
        "semantic_category": "filesystem",
        "invocation_phase": "propose",
        "resource_locator": _apply_locator(),
        "bounded_local_input": {
            "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
            "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
        },
    }
    payload.update(overrides)
    return payload


def test_optional_apply_descriptor_is_backward_compatible() -> None:
    required = validate_provider_descriptor(_valid_descriptor_payload())
    assert required.alternative_ids == CONTROLLED_ALTERNATIVE_IDS
    advertised = validate_provider_descriptor(_apply_descriptor_payload())
    assert advertised.alternative_ids == (
        *CONTROLLED_ALTERNATIVE_IDS,
        APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
    )
    missing_required = _valid_descriptor_payload()
    missing_required["alternative_ids"] = list(CONTROLLED_ALTERNATIVE_IDS[:-1]) + [
        APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    ]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_descriptor(missing_required)
    _assert_bounded_error(missing, ERROR_DESCRIPTOR_INVALID)
    unknown_extra = _valid_descriptor_payload()
    unknown_extra["alternative_ids"] = list(CONTROLLED_ALTERNATIVE_IDS) + ["unknown.apply.v1"]
    with pytest.raises(ControlledAlternativeValidationError) as unknown:
        validate_provider_descriptor(unknown_extra)
    _assert_bounded_error(unknown, ERROR_DESCRIPTOR_INVALID)
    apply_in_middle = list(CONTROLLED_ALTERNATIVE_IDS)
    apply_in_middle.insert(2, APPLY_PREPARED_PATCH_ALTERNATIVE_ID)
    middle = _valid_descriptor_payload()
    middle["alternative_ids"] = apply_in_middle
    with pytest.raises(ControlledAlternativeValidationError) as misplaced:
        validate_provider_descriptor(middle)
    _assert_bounded_error(misplaced, ERROR_DESCRIPTOR_INVALID)


def test_semantic_apply_tool_appears_only_when_advertised() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    old_schemas = build_semantic_controlled_alternative_tool_schemas(
        validate_provider_descriptor(_valid_descriptor_payload())
    )
    old_names = [schema["name"] for schema in old_schemas]
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in old_names
    assert SEMANTIC_RESTORE_STAGED_TOOL_NAME in old_names
    assert SEMANTIC_CLEANUP_STAGED_TOOL_NAME in old_names
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in old_names
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME in old_names
    assert SEMANTIC_GIT_OPERATION_TOOL_NAME in old_names
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME not in old_names
    advertised = build_semantic_controlled_alternative_tool_schemas(
        validate_provider_descriptor(_apply_descriptor_payload())
    )
    names = [schema["name"] for schema in advertised]
    assert names[-1] == SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME
    apply_schema = advertised[-1]
    assert apply_schema["name"] == SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME
    assert set(apply_schema["inputSchema"]["required"]) == {
        "prepared_artifact_ref",
        "prepared_artifact_hash",
    }
    assert set(apply_schema["inputSchema"]["properties"]) == {
        "prepared_artifact_ref",
        "prepared_artifact_hash",
    }
    assert apply_schema["inputSchema"]["additionalProperties"] is False
    jsonschema.validate(_apply_local_input(), apply_schema["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY}, apply_schema["inputSchema"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {**_apply_local_input(), "path": "notes.txt"},
            apply_schema["inputSchema"],
        )
    dumped = json.dumps(apply_schema)
    assert "patch" not in dumped.lower() or "prepared" in dumped.lower()
    assert "workspace_root" not in dumped
    assert "state_root" not in dumped
    assert "route_id" not in dumped
    assert "st_dev" not in dumped
    assert SECRET_PATH not in dumped
    assert "not authority" in apply_schema["description"]
    generic = build_controlled_alternative_tool_schema(
        validate_provider_descriptor(_apply_descriptor_payload())
    )
    assert generic["name"] == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME
    assert APPLY_PREPARED_PATCH_ALTERNATIVE_ID in json.dumps(generic["inputSchema"])


def test_semantic_apply_constants_and_mapping() -> None:
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME == "agentveil_apply_prepared_patch"
    assert semantic_alternative_id_for_tool(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME) == (
        APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    )
    assert semantic_tool_name_for_alternative_id(APPLY_PREPARED_PATCH_ALTERNATIVE_ID) == (
        SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME
    )
    assert is_semantic_controlled_alternative_tool(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME)
    assert is_controlled_alternative_tool_name(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME)


def test_normalize_semantic_apply_maps_ref_and_hash_only() -> None:
    mapped = normalize_semantic_tool_call(
        SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME,
        _apply_local_input(),
    )
    assert mapped == {
        "alternative_id": APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
        "input": {
            "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
            "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
        },
    }
    dumped = f"{mapped!r}{mapped}"
    assert SECRET_PATH not in dumped
    assert WORKSPACE_ROOT not in dumped
    assert STATE_ROOT not in dumped
    assert SECRET_PATCH not in dumped


def test_normalize_semantic_apply_rejects_malformed_path_like_and_authority_input() -> None:
    valid = _apply_local_input()
    malformed = (
        {},
        {"prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY},
        {"prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {**valid, "extra": 1},
        {**valid, "path": "notes.txt"},
        {**valid, "patch": SECRET_PATCH},
        {**valid, "workspace_root": WORKSPACE_ROOT},
        {**valid, "state_root": STATE_ROOT},
        {**valid, "route_id": ROUTE_CANARY},
        {**valid, "st_dev": STDEV_CANARY},
        {"prepared_artifact_ref": 123, "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY, "prepared_artifact_hash": 123},
        {"prepared_artifact_ref": "/tmp/artifact", "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": "../artifact", "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": r"C:\artifact", "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": SECRET_PATH, "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": "allow", "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": "approval_granted", "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": "a" * 31, "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
        {"prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY, "prepared_artifact_hash": "ab" * 31},
        {"prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY, "prepared_artifact_hash": "AB" * 32},
        {"prepared_artifact_ref": "A" * 32, "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY},
    )
    for payload in malformed:
        with pytest.raises(ControlledAlternativeValidationError) as exc:
            normalize_semantic_tool_call(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, payload)
        _assert_bounded_error(exc, ERROR_REQUEST_MALFORMED, SECRET_PATCH)
    for payload in (
        {**valid, "approval_granted": True},
        {**valid, "allow": True},
    ):
        with pytest.raises(ControlledAlternativeValidationError) as authority:
            normalize_semantic_tool_call(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, payload)
        _assert_bounded_error(authority, ERROR_RESULT_UNSAFE)
    accepted = normalize_semantic_tool_call(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, valid)
    assert accepted["input"]["prepared_artifact_ref"] == PREPARED_ARTIFACT_REF_CANARY


def test_apply_local_input_and_locator_accept_bounded_ref_hash() -> None:
    parsed = validate_controlled_alternative_local_input(
        APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
        _apply_local_input(),
    )
    assert parsed.alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    assert parsed.prepared_artifact_ref == PREPARED_ARTIFACT_REF_CANARY
    assert parsed.prepared_artifact_hash == PREPARED_ARTIFACT_HASH_CANARY
    assert parsed.path is None
    assert parsed.patch is None
    locator = validate_resource_locator(
        _apply_locator(),
        alternative_id=APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
    )
    assert locator.locator_kind == "prepared_write_artifact"
    assert locator.normalized_path is None
    assert locator.workspace_root == WORKSPACE_ROOT
    assert locator.state_root == STATE_ROOT
    with pytest.raises(ControlledAlternativeValidationError) as with_path:
        validate_resource_locator(
            _apply_locator(normalized_path=SECRET_PATH),
            alternative_id=APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
        )
    _assert_bounded_error(with_path, ERROR_REQUEST_MALFORMED)


def test_apply_provider_request_is_ref_hash_only() -> None:
    accepted = validate_provider_request(_apply_request_payload())
    assert accepted.alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    assert accepted.bounded_local_input is not None
    assert accepted.bounded_local_input.prepared_artifact_ref == PREPARED_ARTIFACT_REF_CANARY
    assert accepted.bounded_local_input.prepared_artifact_hash == PREPARED_ARTIFACT_HASH_CANARY
    assert accepted.bounded_local_input.patch is None
    assert accepted.resource_locator.normalized_path is None
    assert PREPARED_ARTIFACT_REF_CANARY not in repr(accepted)
    assert PREPARED_ARTIFACT_HASH_CANARY not in repr(accepted)
    assert WORKSPACE_ROOT not in repr(accepted)
    omitted = _apply_request_payload()
    del omitted["bounded_local_input"]
    with pytest.raises(ControlledAlternativeValidationError) as missing:
        validate_provider_request(omitted)
    _assert_bounded_error(missing, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as patch_only:
        validate_provider_request(
            _apply_request_payload(bounded_local_input={"patch": SECRET_PATCH})
        )
    _assert_bounded_error(patch_only, ERROR_REQUEST_MALFORMED)
    with pytest.raises(ControlledAlternativeValidationError) as with_path:
        validate_provider_request(
            _apply_request_payload(resource_locator=_apply_locator(normalized_path=SECRET_PATH))
        )
    _assert_bounded_error(with_path, ERROR_REQUEST_MALFORMED)


def test_apply_result_forbids_prepared_artifact_fields() -> None:
    payload = {
        "contract_version": "1",
        "alternative_id": APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
        "operation_ref": "op-1",
        "result_status": "success",
        "outcome_class_candidate": "COMPLETED_WITH_ALTERNATIVE",
        "target_reached": False,
        "rollback_available": False,
        "prepared_artifact_ref": PREPARED_ARTIFACT_REF_CANARY,
        "prepared_artifact_hash": PREPARED_ARTIFACT_HASH_CANARY,
    }
    with pytest.raises(ControlledAlternativeValidationError) as forbidden:
        validate_provider_result(payload)
    _assert_bounded_error(forbidden, ERROR_REQUEST_MALFORMED)
    del payload["prepared_artifact_ref"]
    del payload["prepared_artifact_hash"]
    parsed = validate_provider_result(payload)
    assert parsed.alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID
    assert parsed.prepared_artifact_ref is None
    assert parsed.prepared_artifact_hash is None
    assert parsed.target_reached is False


@pytest.mark.parametrize(
    ("alternative_id", "raw_input"),
    [
        ("filesystem.stage_delete.v1", {"path": "secrets.env"}),
        ("filesystem.stage_delete.v1", {"path": ".env"}),
        ("filesystem.stage_delete.v1", {"path": ".env.local"}),
        ("filesystem.stage_delete.v1", {"path": "dir/secrets.env"}),
        ("filesystem.stage_delete.v1", {"path": "SECRETS.ENV"}),
        ("filesystem.stage_delete.v1", {"path": "credentials.json"}),
        ("filesystem.stage_delete.v1", {"path": "id_rsa"}),
        ("filesystem.stage_delete.v1", {"path": "cert.pem"}),
        ("filesystem.stage_delete.v1", {"path": " secrets.env"}),
        ("filesystem.stage_delete.v1", {"path": "secrets.env\n"}),
        ("filesystem.stage_delete.v1", {"path": "../secrets.env"}),
        ("protected_write.prepare_patch.v1", {"path": "locked_config.yaml", "patch": "diff"}),
        ("protected_write.prepare_patch.v1", {"path": "config/locked_config.yaml", "patch": "diff"}),
        ("protected_write.prepare_patch.v1", {"path": "LOCKED_CONFIG.YAML", "patch": "diff"}),
        ("protected_write.prepare_patch.v1", {"path": "locked_config.yaml\n", "patch": "diff"}),
    ],
)
def test_validate_local_input_rejects_unsafe_redirect_targets(
    alternative_id: str,
    raw_input: dict[str, str],
) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as denied:
        validate_controlled_alternative_local_input(alternative_id, raw_input)
    canaries = tuple(value for value in raw_input.values() if isinstance(value, str))
    _assert_bounded_error(denied, ERROR_REQUEST_MALFORMED, *canaries)


@pytest.mark.parametrize(
    ("alternative_id", "raw_input"),
    [
        ("filesystem.stage_delete.v1", {"path": "notes.txt"}),
        ("filesystem.stage_delete.v1", {"path": "secret.txt"}),
        ("filesystem.stage_delete.v1", {"path": "generated.log"}),
        ("protected_write.prepare_patch.v1", {"path": "notes.txt", "patch": "diff"}),
        ("protected_write.prepare_patch.v1", {"path": "config.yaml", "patch": "diff"}),
    ],
)
def test_validate_local_input_keeps_safe_redirect_targets(
    alternative_id: str,
    raw_input: dict[str, str],
) -> None:
    parsed = validate_controlled_alternative_local_input(alternative_id, raw_input)
    assert parsed.alternative_id == alternative_id
    assert parsed.path == raw_input["path"]


def test_normalize_semantic_stage_delete_rejects_unsafe_and_untrusted_paths() -> None:
    cases = (
        {"path": "secrets.env"},
        {"path": ".env.local"},
        {"path": "/tmp/notes.txt"},
        {"path": "../notes.txt"},
        {"path": "notes.txt\n"},
        {"path": r"C:\secret.txt"},
    )
    for payload in cases:
        with pytest.raises(ControlledAlternativeValidationError) as denied:
            normalize_semantic_tool_call(SEMANTIC_STAGE_DELETE_TOOL_NAME, payload)
        _assert_bounded_error(denied, ERROR_REQUEST_MALFORMED, *payload.values())
    mapped = normalize_semantic_tool_call(SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": "notes.txt"})
    assert mapped == {
        "alternative_id": "filesystem.stage_delete.v1",
        "input": {"path": "notes.txt"},
    }


def test_agentveil_write_file_schema_and_injection_are_owned_channel_only() -> None:
    schema = build_agentveil_write_file_tool_schema()
    assert schema["name"] == SEMANTIC_WRITE_FILE_TOOL_NAME
    assert schema["inputSchema"]["additionalProperties"] is False
    assert set(schema["inputSchema"]["required"]) == {"path", "content"}
    assert set(schema["inputSchema"]["properties"]) == {"path", "content"}
    dumped = json.dumps(schema)
    assert "write_file" in dumped
    assert "AgentVeil MCP proxy route" in dumped
    assert "not a controlled alternative" in dumped
    assert "approval_granted" not in dumped
    assert "workspace_root" not in dumped
    assert "state_root" not in dumped
    assert "route_id" not in dumped
    assert "agentveil_private_policy" not in dumped

    listed = {"result": {"tools": [{"name": "write_file", "inputSchema": {"type": "object"}}]}}
    injected = inject_agentveil_write_file_tool(listed)
    assert [tool["name"] for tool in injected["result"]["tools"]] == [
        "write_file",
        SEMANTIC_WRITE_FILE_TOOL_NAME,
    ]
    no_downstream = {"result": {"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}}
    assert inject_agentveil_write_file_tool(no_downstream) == no_downstream
    collision = {"result": {"tools": [{"name": SEMANTIC_WRITE_FILE_TOOL_NAME}]}}
    assert inject_agentveil_write_file_tool(collision) == collision


def test_normalize_agentveil_write_file_call_preserves_exact_content() -> None:
    mapped = normalize_agentveil_write_file_call(
        {"path": "todo.txt", "content": "first line\nsecond line\n"}
    )
    assert mapped == {"path": "todo.txt", "content": "first line\nsecond line\n"}
    empty = normalize_agentveil_write_file_call({"path": "empty.txt", "content": ""})
    assert empty == {"path": "empty.txt", "content": ""}
    ordinary = normalize_agentveil_write_file_call({"path": "notes.txt", "content": "ok\n"})
    assert ordinary == {"path": "notes.txt", "content": "ok\n"}
    config = normalize_agentveil_write_file_call({"path": "config.yaml", "content": "ok\n"})
    assert config == {"path": "config.yaml", "content": "ok\n"}


@pytest.mark.parametrize(
    ("payload", "error_code"),
    [
        ({}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt"}, ERROR_REQUEST_MALFORMED),
        ({"content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt", "content": "x", "extra": "y"}, ERROR_REQUEST_MALFORMED),
        ({"path": " todo.txt", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt ", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "../todo.txt", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "/tmp/todo.txt", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": r"C:\todo.txt", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt\n", "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt", "content": "x\0"}, ERROR_REQUEST_MALFORMED),
        ({"path": 123, "content": "x"}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt", "content": 123}, ERROR_REQUEST_MALFORMED),
        ({"path": "todo.txt", "content": "x", "approval_granted": True}, ERROR_RESULT_UNSAFE),
        ({"path": "locked_config.yaml", "content": "overwrite-canary"}, ERROR_REQUEST_MALFORMED),
        ({"path": "config/locked_config.yaml", "content": "overwrite-canary"}, ERROR_REQUEST_MALFORMED),
        ({"path": "LOCKED_CONFIG.YAML", "content": "overwrite-canary"}, ERROR_REQUEST_MALFORMED),
        ({"path": "secrets.env", "content": "token=do-not-copy"}, ERROR_REQUEST_MALFORMED),
        ({"path": ".env", "content": "token=do-not-copy"}, ERROR_REQUEST_MALFORMED),
        ({"path": "credentials.json", "content": "token=do-not-copy"}, ERROR_REQUEST_MALFORMED),
    ],
)
def test_normalize_agentveil_write_file_call_rejects_untrusted_input(
    payload: dict[str, object],
    error_code: str,
) -> None:
    with pytest.raises(ControlledAlternativeValidationError) as denied:
        normalize_agentveil_write_file_call(payload)
    extra = [value for value in payload.values() if isinstance(value, str)]
    _assert_bounded_error(denied, error_code, "todo.txt", "/tmp", r"C:\todo", *extra)


_ADD_FILE_PATCH = "*** Begin Patch\n*** Add File: created.txt\n+hello\n*** End Patch"
_UPDATE_FILE_PATCH = "*** Begin Patch\n*** Update File: notes.txt\n*** End Patch"


def test_prepare_patch_rejects_clear_create_file_payloads() -> None:
    cases = (
        {"path": "created.txt", "patch": _ADD_FILE_PATCH},
        {"path": "notes.txt", "patch": "*** Add File: notes.txt\n+x"},
        {
            "path": "notes.txt",
            "patch": "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** Update File: notes.txt\n*** End Patch",
        },
        {"path": "notes.txt", "patch": "  *** Add File: notes.txt\n+x"},
    )
    for payload in cases:
        with pytest.raises(ControlledAlternativeValidationError) as denied:
            validate_controlled_alternative_local_input(
                "protected_write.prepare_patch.v1",
                payload,
            )
        _assert_bounded_error(denied, ERROR_REQUEST_MALFORMED, *payload.values())
        with pytest.raises(ControlledAlternativeValidationError) as semantic:
            normalize_semantic_tool_call(SEMANTIC_PREPARE_PATCH_TOOL_NAME, payload)
        _assert_bounded_error(semantic, ERROR_REQUEST_MALFORMED, *payload.values())


def test_prepare_patch_keeps_existing_file_update_payloads() -> None:
    update = validate_controlled_alternative_local_input(
        "protected_write.prepare_patch.v1",
        {"path": "notes.txt", "patch": _UPDATE_FILE_PATCH},
    )
    assert update.path == "notes.txt"
    assert update.patch == _UPDATE_FILE_PATCH
    mapped = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_PATCH_TOOL_NAME,
        {"path": "notes.txt", "patch": _UPDATE_FILE_PATCH},
    )
    assert mapped == {
        "alternative_id": "protected_write.prepare_patch.v1",
        "input": {"path": "notes.txt", "patch": _UPDATE_FILE_PATCH},
    }
    plain = normalize_semantic_tool_call(
        SEMANTIC_PREPARE_PATCH_TOOL_NAME,
        {"path": "notes.txt", "patch": "diff"},
    )
    assert plain["input"]["patch"] == "diff"
    literal = "*** Begin Patch\n*** Update File: notes.txt\n@@\n *** Add File: literal content\n*** End Patch"
    literal_update = validate_controlled_alternative_local_input(
        "protected_write.prepare_patch.v1",
        {"path": "notes.txt", "patch": literal},
    )
    assert literal_update.patch == literal
