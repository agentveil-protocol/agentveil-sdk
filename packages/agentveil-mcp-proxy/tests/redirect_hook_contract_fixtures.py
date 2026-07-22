"""Shared fixtures for native-hook redirect connector contract tests."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from agentveil_mcp_proxy.approval.server import OwnerClaimLease, build_owner_client_id, publish_owner_claim
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream
from agentveil_mcp_proxy.client_guidance import (
    build_hook_runtime_binding,
    hook_runtime_binding_path,
    write_hook_runtime_binding,
)

CONTRACT_SESSION_ID = "redirect-contract-session"
CONTRACT_INSTANCE_TOKEN = "redirect-contract-inst"
CONTRACT_OWNER_NAME = "filesystem"


@dataclass
class LiveHookBindingFixture:
    home: Path
    sandbox: Path
    lease: OwnerClaimLease
    session_id: str
    client_id: str
    instance_token: str
    owner_pid: int


def init_redirect_contract_home(tmp_path: Path) -> tuple[Path, Path, dict]:
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    downstream = quickstart_filesystem_downstream(sandbox)
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = downstream
    init.config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return home, sandbox, downstream


def publish_live_hook_binding(
    home: Path,
    *,
    downstream: dict,
    owner_pid: int | None = None,
    session_id: str = CONTRACT_SESSION_ID,
    instance_token: str = CONTRACT_INSTANCE_TOKEN,
) -> LiveHookBindingFixture:
    owner_pid = owner_pid or os.getpid()
    client_id = build_owner_client_id(CONTRACT_OWNER_NAME, pid=owner_pid, instance_token=instance_token)
    claim_dir = home / "mcp-proxy" / "owner_claims"
    lease = publish_owner_claim(
        claim_dir,
        pid=owner_pid,
        instance_token=instance_token,
        session_id=session_id,
    )
    binding = build_hook_runtime_binding(
        owner_pid=owner_pid,
        instance_token=instance_token,
        session_id=session_id,
        client_id=client_id,
        downstream=downstream,
    )
    assert binding is not None
    write_hook_runtime_binding(home, binding)
    sandbox = Path(downstream["args"][-1]).resolve()
    return LiveHookBindingFixture(
        home=home,
        sandbox=sandbox,
        lease=lease,
        session_id=session_id,
        client_id=client_id,
        instance_token=instance_token,
        owner_pid=owner_pid,
    )


def durable_original_metadata(home: Path, original_request_id: str) -> dict | None:
    db = home / "mcp-proxy" / "evidence.sqlite"
    if not db.is_file():
        return None
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT action_gate_metadata_jcs FROM pending_approvals WHERE request_id = ?",
            (original_request_id,),
        ).fetchone()
    if row is None:
        return None
    parsed = json.loads(row[0])
    return parsed if isinstance(parsed, dict) else None


def binding_path_for(fixture: LiveHookBindingFixture) -> Path:
    return hook_runtime_binding_path(
        fixture.home,
        owner_pid=fixture.owner_pid,
        instance_token=fixture.instance_token,
    )
