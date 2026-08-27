"""Bounded inert Controlled Alternatives provider seam tests (CA1)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
from agentveil_mcp_proxy.paid_provider import (
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_MISSING,
    PaidProviderSnapshot,
)

SECRET_PATH = "/Users/customer/project/secret.txt"
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

FAMILY_LOCATORS: dict[str, dict[str, object]] = {
    "filesystem.stage_delete.v1": {
        "locator_kind": "filesystem_path",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
    },
    "filesystem.restore_staged.v1": {
        "locator_kind": "quarantine_entry",
        "quarantine_entry_id": "qe-1",
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
    },
    "filesystem.cleanup_staged.v1": {
        "locator_kind": "quarantine_entry",
        "quarantine_entry_id": "qe-1",
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
    },
    "protected_write.prepare_patch.v1": {
        "locator_kind": "protected_write_target",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
    },
    "git.prepare_local_change.v1": {
        "locator_kind": "git_worktree",
        "normalized_path": SECRET_PATH,
        "route_id": ROUTE_CANARY,
        "st_dev": STDEV_CANARY,
    },
}


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


def _assert_bounded_error(exc_info: pytest.ExceptionInfo, code: str) -> None:
    assert exc_info.type is ControlledAlternativeValidationError
    assert str(exc_info.value) == code
    assert SECRET_PATH not in str(exc_info.value)
    assert SECRET_PATCH not in str(exc_info.value)


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
        assert ROUTE_CANARY not in rendered
        assert SUMMARY_CANARY not in rendered
        assert str(STDEV_CANARY) not in rendered
        assert not hasattr(value, "to_dict")


@pytest.mark.parametrize("alternative_id", list(CONTROLLED_ALTERNATIVE_IDS))
def test_validate_provider_request_accepts_locator_matrix(alternative_id: str) -> None:
    request = validate_provider_request(_request_payload(alternative_id))
    assert request.alternative_id == alternative_id
    assert request.resource_locator.st_dev == STDEV_CANARY
    assert SECRET_PATH not in repr(request)
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
            {
                "locator_kind": "filesystem_path",
                "normalized_path": "notes.txt",
                "route_id": "route-1",
                "st_dev": True,
            },
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(bool_dev, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as missing_path:
        validate_resource_locator(
            {"locator_kind": "filesystem_path", "route_id": "route-1", "st_dev": 1},
            alternative_id="filesystem.stage_delete.v1",
        )
    _assert_bounded_error(missing_path, ERROR_REQUEST_MALFORMED)

    with pytest.raises(ControlledAlternativeValidationError) as extra_field:
        validate_resource_locator(
            {
                "locator_kind": "filesystem_path",
                "normalized_path": "notes.txt",
                "route_id": "route-1",
                "st_dev": 1,
                "quarantine_entry_id": "qe-1",
            },
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
    assert SECRET_PATCH not in repr(accepted.bounded_local_input)
    assert SECRET_PATH not in repr(accepted)

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
