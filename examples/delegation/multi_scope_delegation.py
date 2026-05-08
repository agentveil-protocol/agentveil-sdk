#!/usr/bin/env python3
"""Issue one receipt with multiple categories and an optional spend cap."""

from datetime import timedelta

from agentveil import AVPAgent


owner = AVPAgent.create(mock=True, name="workflow-owner")
agent = AVPAgent.create(mock=True, name="release-agent")

receipt = owner.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["deploy", "infrastructure"],
    max_spend={"currency": "USD", "amount": 250},
    valid_for=timedelta(minutes=45),
    purpose="Deploy service changes and inspect infrastructure resources",
)

verification = agent.verify_delegation_receipt(receipt)
categories = [
    entry["value"]
    for entry in verification["scope"]
    if entry["predicate"] == "allowed_category"
]
spend_caps = [
    entry
    for entry in verification["scope"]
    if entry["predicate"] == "max_spend"
]

print("valid:", verification["valid"])
print("categories:", ", ".join(categories))
print("max_spend:", spend_caps[0]["currency"], spend_caps[0]["amount"])
