#!/usr/bin/env python3
"""Issue and verify a DelegationReceipt locally with no backend."""

from datetime import timedelta

from agentveil import AVPAgent


owner = AVPAgent.create(mock=True, name="workflow-owner")
agent = AVPAgent.create(mock=True, name="deploy-agent")

receipt = owner.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["deploy"],
    valid_for=timedelta(minutes=15),
    purpose="Allow one short-lived deploy workflow",
)

verification = agent.verify_delegation_receipt(receipt)

print("valid:", verification["valid"])
print("issuer:", verification["issuer"])
print("subject:", verification["subject"])
print("category:", verification["scope"][0]["value"])
