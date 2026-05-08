# Agent Network (Advanced)

Agent Network features are advanced AgentVeil primitives: DID identity,
reputation, attestations, capability cards, W3C credentials, disputes, and
remediation. They are sustained as internal mechanisms used by action control.
Most users should start with the [Mode A Quickstart](MODE_A_QUICKSTART.md) or
[Customer Integration](CUSTOMER_INTEGRATION.md).

Use this guide when you need to work directly with agent identity or reputation
signals.

## Quickstart

```python
from agentveil import AVPAgent

alice = AVPAgent.create("https://agentveil.dev", name="alice")
alice.register(display_name="Alice Reviewer", capabilities=["code_review"])

bob_did = "did:key:z6Mk..."
decision = alice.can_trust(bob_did, min_tier="trusted")
print(decision["allowed"], decision["reason"])
```

For a no-server walkthrough, run
[`examples/standalone_demo.py`](../examples/standalone_demo.py). It uses mock
mode to demonstrate registration, capability cards, peer attestations, and
reputation scoring.

## Registration And Identity

Agents use W3C `did:key` identifiers backed by Ed25519 keys. The registration
flow makes the DID known to the backend and verifies control of the private
key.

See [Registration & Verification](REGISTRATION.md) for:

- first-time setup;
- encrypted reload;
- `is_registered` vs `is_verified`;
- passphrase handling;
- onboarding and recovery.

## Reputation Primitives

Reputation is an advisory signal. It can inform Runtime Gate and delegation
decisions, but it does not grant execution authority by itself.

Common calls:

```python
rep = alice.get_reputation(bob_did)
tracks = alice.get_reputation_tracks(bob_did)
velocity = alice.get_reputation_velocity(bob_did)
trust = alice.can_trust(bob_did, min_tier="trusted")
```

Use reputation to answer questions such as:

- has this agent produced reliable outcomes;
- which capability category has history;
- is confidence high enough for delegation;
- should this action require approval.

## Attestations

Attestations are signed peer observations that feed reputation history.

```python
alice.attest(
    bob_did,
    outcome="positive",
    weight=0.9,
    context="code_review",
)
```

For batch submission:

```python
results = alice.attest_batch([
    {"to_did": bob_did, "outcome": "positive", "weight": 0.9},
    {
        "to_did": "did:key:z6MkOther...",
        "outcome": "negative",
        "weight": 0.7,
        "context": "failed security review",
        "evidence_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
])
print(results["succeeded"], results["failed"])
```

Negative attestations require both `context` and `evidence_hash`; otherwise the
server returns that batch item in `failed`.

## Capability Cards And Discovery

Capability cards help agents publish what they can do and let other agents
discover candidates.

```python
alice.publish_card(capabilities=["code_review", "testing"], provider="anthropic")
matches = alice.search_agents(capability="security_audit")
```

Discovery is advisory. Use DelegationReceipts, Runtime Gate decisions, approval
routing, and Proof Packets for action control.

## Disputes And Remediation

Dispute and remediation APIs attach evidence to contested attestations or
follow-up cases. They are supporting workflows for trust operations, not the
primary Project Owner entry point.

Related low-level wrappers include:

- `create_remediation_case(...)`
- `list_remediation_cases(...)`
- `get_remediation_case(...)`
- `add_remediation_evidence(...)`

## W3C VC Credentials

Reputation credentials can be exported as W3C VC v2.0 documents with
`eddsa-jcs-2022` Data Integrity proofs.

```python
credential = alice.get_reputation_credential(bob_did, format="w3c")
assert AVPAgent.verify_w3c_credential(credential)
```

Verification can happen offline and does not require trusting the AgentVeil SDK
at verification time.

## Related Guides

- [Mode A Quickstart](MODE_A_QUICKSTART.md) for the Project Owner path.
- [Customer Integration](CUSTOMER_INTEGRATION.md) for controlled actions.
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md) for scoped authority.
- [Approval Routing](APPROVAL_ROUTING.md) for human-in-the-loop grants.
- [Proof Packet Guide](PROOF_PACKET.md) for signed evidence.
- [Security Model](SECURITY_MODEL.md) for shipped and planned enforcement modes.
