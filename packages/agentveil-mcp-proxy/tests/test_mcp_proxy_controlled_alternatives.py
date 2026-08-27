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
    CONTROLLED_ALTERNATIVE_IDS,
    CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP,
    CONTROLLED_ALTERNATIVE_PROVIDER_ID,
    CONTROLLED_ALTERNATIVES_PROFILE_ID,
    ERROR_CONTRACT_INCOMPATIBLE,
    ERROR_DESCRIPTOR_INVALID,
    ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT,
    ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED,
    ERROR_DISCOVERY_ENTRYPOINT_MISSING,
    ERROR_DISCOVERY_INELIGIBLE,
    ERROR_REQUEST_MALFORMED,
    ERROR_RESULT_UNSAFE,
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    ControlledAlternativeBoundedLocalInput,
    ControlledAlternativeProviderDescriptor,
    ControlledAlternativeProviderResult,
    ControlledAlternativeValidationError,
    build_controlled_alternative_tool_schema,
    discover_controlled_alternative_provider,
    set_controlled_alternative_provider_loader,
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
ROUTE_CANARY = "route-secret-9f3a"
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
    yield
    set_controlled_alternative_provider_loader(None)


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
    for value in (local_input, locator, request, bounded, result):
        rendered = f"{value!r}{value}"
        assert SECRET_PATH not in rendered
        assert SECRET_PATCH not in rendered
        assert WORKSPACE_ROOT not in rendered
        assert STATE_ROOT not in rendered
        assert ROUTE_CANARY not in rendered
        assert SUMMARY_CANARY not in rendered
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
        }
    )
    assert success.result_status == "success"

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
    }
    payload.update(overrides)
    return ControlledAlternativeProviderResult(**payload)  # type: ignore[arg-type]


def test_validate_provider_result_accepts_and_rechecks_dataclass() -> None:
    accepted = validate_provider_result(_valid_result_dataclass())
    assert accepted.result_status == "success"
    assert accepted.error_code is None
    round_trip = validate_provider_result(accepted)
    assert round_trip.result_status == "success"

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


def test_discovery_requires_active_private_paid_snapshot() -> None:
    inactive = PaidProviderSnapshot(
        provider_present=True,
        provider_id=CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=False,
        public_fallback_available=True,
    )
    result = discover_controlled_alternative_provider(inactive)
    assert result.available is False
    assert result.error_code == ERROR_DISCOVERY_INELIGIBLE

    missing = PaidProviderSnapshot(provider_present=False, status=STATUS_MISSING)
    assert discover_controlled_alternative_provider(missing).error_code == ERROR_DISCOVERY_INELIGIBLE


def test_discovery_returns_compatible_descriptor_from_loader() -> None:
    set_controlled_alternative_provider_loader(lambda: _FakeProvider())
    result = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    result = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    enumerated = discover_controlled_alternative_provider(_active_paid_snapshot())
    assert enumerated.available is False
    assert enumerated.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    assert canary not in repr(enumerated)
    assert canary not in str(enumerated)


def test_discovery_loader_none_and_exception_are_load_failed() -> None:
    set_controlled_alternative_provider_loader(lambda: None)
    none_result = discover_controlled_alternative_provider(_active_paid_snapshot())
    assert none_result.available is False
    assert none_result.error_code == ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED

    def _boom() -> None:
        raise RuntimeError("loader exploded")

    set_controlled_alternative_provider_loader(_boom)
    boom_result = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    CONTROLLED_ALTERNATIVE_IDS,
    discover_controlled_alternative_provider,
)
from agentveil_mcp_proxy.paid_provider import (
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    PaidProviderSnapshot,
)

result = discover_controlled_alternative_provider(
    PaidProviderSnapshot(
        provider_present=True,
        provider_id="private_v1",
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=True,
    )
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
    missing = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    duplicate = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    load_failed = discover_controlled_alternative_provider(_active_paid_snapshot())
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

    result = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    duplicate = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    load_failed = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    missing = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    factory_failed = discover_controlled_alternative_provider(_active_paid_snapshot())
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
    malformed = discover_controlled_alternative_provider(_active_paid_snapshot())
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

    controlled = discover_controlled_alternative_provider(paid_snapshot)
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
