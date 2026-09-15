"""Generic CA policy and explicit migration preserve existing authority."""
import hashlib
import json

import pytest

from agentveil_mcp_proxy.ca_policy_migration import CAPolicyMigrationError, migrate_filesystem_ca_policy
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.cli import _build_config_payload, main
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError, PolicyDecision, PolicyMatch

GENERIC = "agentveil_controlled_alternative"
STAGE = "filesystem.stage_delete.v1"


def config_payload():
    return _build_config_payload(
        base_url="https://agentveil.example", agent_name="test",
        trusted_signer_dids=("did:key:test-signer",), policy_pack="filesystem",
        role_preset="reviewer", setup_profile="safe_autopilot",
        downstream_config={"name": "filesystem", "command": "python", "args": []},
    )


def legacy_file(tmp_path):
    path = tmp_path.resolve() / "config.json"
    payload = config_payload()
    payload["policy"]["rules"] = [r for r in payload["policy"]["rules"] if not r["id"].startswith("filesystem-ca-")]
    payload["policy"]["rules"].append({
        "id": "user-deny", "source": "user", "decision": "block",
        "match": {"tool": ["dangerous_*"], "role": ["reviewer"], "action_family": ["delete"]},
    })
    path.write_text(json.dumps(payload))
    return path, payload


def classify(payload, tool, alternative=STAGE):
    args = {"alternative_id": alternative, "input": {"path": "note.txt"}} if tool == GENERIC else {"path": "note.txt"}
    return ToolCallClassifier(ProxyConfig.from_dict(payload), server_name="filesystem").classify(tool=tool, arguments=args)


@pytest.mark.parametrize("alternative,expected", [
    (STAGE, PolicyDecision.ALLOW),
    ("filesystem.restore_staged.v1", PolicyDecision.ALLOW),
    ("filesystem.cleanup_staged.v1", PolicyDecision.APPROVAL),
    ("protected_write.prepare_patch.v1", PolicyDecision.ASK_BACKEND),
    ("not.implemented.v1", PolicyDecision.ASK_BACKEND),
])
def test_generic_exact_operation_policy(alternative, expected):
    assert classify(config_payload(), GENERIC, alternative).policy_evaluation.decision is expected


@pytest.mark.parametrize("restriction", ["block", "approval", "ask_backend"])
@pytest.mark.parametrize("match_key", ["tool", "action"])
@pytest.mark.parametrize("restricted_tool,called_tool", [(GENERIC, "agentveil_stage_delete"), ("agentveil_stage_delete", GENERIC)])
def test_restrictions_survive_switching_call_form(restriction, match_key, restricted_tool, called_tool):
    payload = config_payload()
    payload["policy"]["rules"].append({"id": "user-explicit", "source": "user", "decision": restriction,
        "match": {match_key: [restricted_tool if match_key == "tool" else "filesystem." + restricted_tool]}})
    assert classify(payload, called_tool).policy_evaluation.decision.value == restriction


def test_preview_apply_preserves_all_other_config_and_identity(tmp_path):
    path, original = legacy_file(tmp_path)
    identity = tmp_path / "identity.json"
    identity.write_bytes(b"unchanged-identity-canary")
    raw = path.read_bytes()
    before_names = set(tmp_path.iterdir())
    plan = migrate_filesystem_ca_policy(path)
    assert not plan["applied"] and len(plan["added_rule_ids"]) == 4
    assert path.read_bytes() == raw and set(tmp_path.iterdir()) == before_names
    result = migrate_filesystem_ca_policy(path, apply=True, expected_sha256=plan["config_sha256"])
    assert result["applied"] and result["reload_required"]
    updated = json.loads(path.read_bytes())
    assert updated["policy"]["rules"][:len(original["policy"]["rules"])] == original["policy"]["rules"]
    updated["policy"]["rules"] = original["policy"]["rules"]
    assert updated == original
    assert identity.read_bytes() == b"unchanged-identity-canary"
    assert next(tmp_path.glob("*.bak")).read_bytes() == raw
    new_raw = path.read_bytes()
    again = migrate_filesystem_ca_policy(path, apply=True, expected_sha256=hashlib.sha256(new_raw).hexdigest())
    assert again["applied"] is False and path.read_bytes() == new_raw


def test_stale_hash_refuses_write(tmp_path):
    path, _ = legacy_file(tmp_path)
    plan = migrate_filesystem_ca_policy(path)
    path.write_bytes(path.read_bytes() + b"\n")
    changed = path.read_bytes()
    with pytest.raises(CAPolicyMigrationError, match="config_changed"):
        migrate_filesystem_ca_policy(path, apply=True, expected_sha256=plan["config_sha256"])
    assert path.read_bytes() == changed
    assert not list(tmp_path.glob("*.bak"))


def test_generic_without_binding_cannot_execute(tmp_path):
    from agentveil_mcp_proxy.passthrough import McpPassthrough, DownstreamConfig
    proxy = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="filesystem"),
        classifier=ToolCallClassifier(ProxyConfig.from_dict(config_payload()), server_name="filesystem"),
    )
    responses = proxy.handle_client_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": GENERIC, "arguments": {"alternative_id": STAGE, "input": {"path": "note.txt"}},
        },
    }))
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert proxy._downstream_tool_calls_forwarded == 0


def test_apply_without_expected_hash_does_not_write(tmp_path, capsys):
    path, _ = legacy_file(tmp_path)
    raw = path.read_bytes()
    assert main(["upgrade-ca-policy", "--config", str(path), "--apply"]) == 2
    capsys.readouterr()
    assert path.read_bytes() == raw


def test_fifo_config_is_rejected_without_blocking(tmp_path):
    import os
    path = tmp_path.resolve() / "fifo"
    os.mkfifo(path)
    with pytest.raises(CAPolicyMigrationError, match="invalid_config_file"):
        migrate_filesystem_ca_policy(path)


@pytest.mark.parametrize("where", ["source", "parent", "backup"])
def test_symlinks_fail_closed(tmp_path, where):
    real = tmp_path / "real"
    real.mkdir()
    path, _ = legacy_file(real)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if where == "source":
        selected = tmp_path / "config.json"
        selected.symlink_to(path)
    elif where == "parent":
        alias = tmp_path / "alias"
        alias.symlink_to(real, target_is_directory=True)
        selected = alias / "config.json"
    else:
        selected = path
        path.with_name(path.name + ".ca-policy." + digest + ".bak").symlink_to(path)
    with pytest.raises(CAPolicyMigrationError):
        migrate_filesystem_ca_policy(selected, apply=True, expected_sha256=digest)
    assert path.read_bytes() == raw


def test_rule_id_conflict_is_not_overwritten(tmp_path):
    path, payload = legacy_file(tmp_path)
    payload["policy"]["rules"].append({"id": "filesystem-ca-recoverable-v1", "decision": "block", "match": {}})
    path.write_text(json.dumps(payload))
    raw = path.read_bytes()
    with pytest.raises(CAPolicyMigrationError, match="rule_id_conflict"):
        migrate_filesystem_ca_policy(path)
    assert path.read_bytes() == raw


def test_concurrent_change_before_replace_is_preserved(tmp_path, monkeypatch):
    from agentveil_mcp_proxy import ca_policy_migration as migration
    path, _ = legacy_file(tmp_path)
    raw = path.read_bytes()
    changed = raw + b"\n"
    writer = migration._write_exclusive
    def change_during_staging(fd, name, data):
        writer(fd, name, data)
        if name.endswith(".tmp"):
            path.write_bytes(changed)
    monkeypatch.setattr(migration, "_write_exclusive", change_during_staging)
    with pytest.raises(CAPolicyMigrationError, match="config_changed"):
        migrate_filesystem_ca_policy(path, apply=True, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert path.read_bytes() == changed
    assert not list(tmp_path.glob("*.tmp"))


def test_backup_conflict_preserves_source(tmp_path):
    path, _ = legacy_file(tmp_path)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    backup = path.with_name(path.name + ".ca-policy." + digest + ".bak")
    backup.write_bytes(b"existing unrelated backup")
    with pytest.raises(CAPolicyMigrationError, match="backup_conflict"):
        migrate_filesystem_ca_policy(path, apply=True, expected_sha256=digest)
    assert path.read_bytes() == raw and backup.read_bytes() == b"existing unrelated backup"


def test_non_filesystem_policy_is_not_migrated(tmp_path):
    path, data = legacy_file(tmp_path)
    data["policy"]["id"] = "custom"
    path.write_text(json.dumps(data))
    raw = path.read_bytes()
    with pytest.raises(CAPolicyMigrationError, match="unsupported_policy"):
        migrate_filesystem_ca_policy(path)
    assert path.read_bytes() == raw


def test_cli_preview_and_hash_bound_apply(tmp_path, capsys):
    path, _ = legacy_file(tmp_path)
    assert main(["upgrade-ca-policy", "--config", str(path), "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert str(path) not in json.dumps(plan)
    assert main(["upgrade-ca-policy", "--config", str(path), "--apply", "--expected-config-sha256", plan["config_sha256"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"] is True


@pytest.mark.parametrize("value", [["filesystem.*"], ["/Users/canary"], [None]])
def test_operation_matcher_rejects_patterns_and_unbounded_values(value):
    with pytest.raises(ProxyConfigError):
        PolicyMatch.from_dict({"controlled_alternative_id": value})
