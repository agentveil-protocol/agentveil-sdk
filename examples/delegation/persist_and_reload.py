#!/usr/bin/env python3
"""Persist a DelegationReceipt as JSON, reload it, then verify offline."""

import json
import tempfile
from datetime import timedelta
from pathlib import Path

from agentveil import AVPAgent


owner = AVPAgent.create(mock=True, name="workflow-owner")
agent = AVPAgent.create(mock=True, name="service-agent")

receipt = owner.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["infrastructure"],
    valid_for=timedelta(hours=1),
    purpose="Allow bounded infrastructure maintenance",
)

path = Path(tempfile.gettempdir()) / "agentveil-delegation-receipt.json"
path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

loaded = json.loads(path.read_text(encoding="utf-8"))
verification = agent.verify_delegation_receipt(loaded)

print("saved:", path)
print("valid:", verification["valid"])
print("receipt_id:", verification["id"])
