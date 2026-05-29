# MCP Proxy Design Principles

AgentVeil MCP Proxy applies foundational security engineering principles from
Saltzer and Schroeder's 1975 paper [The Protection of Information in Computer
Systems](https://www.cs.virginia.edu/~evans/cs551/saltzer/) to the agent
action control domain. This document maps the eight principles to specific
architecture decisions in the proxy and AVP control plane.

The principles have remained useful for more than 50 years because they provide
a compact vocabulary for reviewing protection mechanisms: simple mechanisms,
deny-by-default decisions, complete mediation, open design, separation of
privilege, least privilege, least common mechanism, and psychological
acceptability. This mapping makes AVP's MCP Proxy design reviewable against a
framework that security and compliance teams already use for operating systems,
containers, infrastructure, and cloud control planes.

This is not a proof that every possible policy is safe. Harrison, Ruzzo, and
Ullman's 1976 paper [Protection in Operating Systems](https://cacm.acm.org/research/protection-in-operating-systems/)
shows that the general access-control safety problem is undecidable under weak
assumptions. AVP's claim is narrower and operational: constrain agent actions
to an explicit policy vocabulary, mediate them before downstream execution,
bind approvals to signed evidence, and make decisions auditable and reversible
inside that bounded subset.

## 1. Economy Of Mechanism

Saltzer and Schroeder's economy of mechanism principle asks security designs to
stay small enough to inspect and reason about.

AgentVeil MCP Proxy keeps the trusted primitive set intentionally narrow:

- Ed25519 `did:key` identity for proxy identity and backend signer identity.
- JCS canonical JSON for signed DecisionReceipts and exported proof material.
- SHA-256 hashes for payload binding, evidence record hashes, and chain links.
- Local SQLite evidence with one hash-chain construction.
- JSON policy rules with explicit decision ranks.

The proxy avoids stacking multiple unrelated crypto formats or authorization
protocols into the same path. For example, offline verification does not need a
JWT parser, OAuth introspection, or a proprietary binary format. It validates a
JCS string, an Ed25519 signature, trusted signer DIDs, and record-to-receipt
field bindings.

This makes review narrower: if a DecisionReceipt verifies, the auditor can
inspect the same canonical body that the signer signed. If an evidence chain
verifies, the auditor can trace record order and mutation history through one
hash construction.

## 2. Fail-Safe Defaults

Fail-safe defaults mean access starts denied and becomes allowed only through
an explicit rule, signed decision, or approval.

The MCP Proxy applies this in several places:

- Built-in policy packs block or require approval for higher-risk actions.
- The `filesystem` pack blocks destructive tool patterns such as `delete_*`,
  `purge_*`, `truncate_*`, `wipe_*`, `format_*`, `rm`, `rmdir_*`, `unlink_*`,
  and `clean_*`.
- Runtime Gate fallback behavior blocks destructive, production, and financial
  risk classes when the backend cannot provide a trusted decision.
- Approval timeout behavior defaults to deny; the timeout path does not become
  an implicit allow.
- New local proxy identities are encrypted by default. Plaintext identity
  storage requires the explicit `--plaintext` opt-out.
- Headless mode denies by default unless a bounded policy grants a specific
  pre-approval.

The practical result is that missing policy, missing approval, missing trusted
signature, missing receipt binding, and unavailable Runtime Gate responses move
toward denial or explicit operator review, not silent forwarding.

## 3. Complete Mediation

Complete mediation requires every protected access to be checked.

For tool calls routed through the MCP Proxy, the downstream server is not called
directly. Each client JSON-RPC request passes through the same mediation path:

1. Parse and bound the client message.
2. Classify the tool call by action and risk.
3. Evaluate local policy rules and built-in policy packs.
4. Call AVP Runtime Gate when policy requires an authoritative decision.
5. Route to the local approval surface when a human decision is required.
6. Write durable evidence before forwarding or terminal denial.
7. Forward only allowed or approved calls to the downstream MCP server.

This mediation boundary is precise: calls that bypass the proxy cannot be
mediated by the proxy. That is why Lurkr remains a separate pre-runtime scanner:
it finds bypass paths, exposed credentials, and uncontrolled integrations before
deployment.

## 4. Open Design

Open design says protection should not depend on hiding the algorithm or
protocol.

The public SDK repository exposes the MCP Proxy source, policy DSL, receipt
schema handling, JCS canonicalization choices, evidence-chain format, and
offline verifier. Auditors can inspect the implementation instead of trusting a
black-box statement that an action was controlled.

The protected secrets are the correct trust anchors and private keys:

- The customer's encrypted proxy identity key.
- The local control grant scoped to that proxy identity.
- The pinned AVP backend signer DID set used for DecisionReceipt verification.

If an exported bundle includes an attacker-controlled signer DID, strict offline
verification rejects it: `verify` trusts only the operator-supplied
`--trusted-signer-did` set and never the bundle's embedded signer list, so a
receipt-bearing bundle fails closed when no external pin is supplied instead of
falling back to a warning.

## 5. Separation Of Privilege

Separation of privilege reduces reliance on a single authority.

The MCP Proxy path separates three key roles:

- **Proxy identity key:** the local Ed25519 key identifying one proxy instance.
  It is encrypted at rest by default.
- **Control grant:** the tenant-scoped delegation receipt authorizing that
  proxy identity to ask Runtime Gate for decisions in allowed categories.
- **Backend signer DID:** the AVP signing identity that issues authoritative
  DecisionReceipts.

A leaked proxy identity cannot forge backend decisions. A backend signing key
cannot impersonate a customer's local proxy identity without the customer's
control grant and local state. A stale or missing control grant cannot silently
turn into permission to execute downstream calls.

This separation also appears in the local approval path: browser approval
requires a path token, an HMAC cookie, and a per-request CSRF token. Evidence
records are written separately from transient browser state.

## 6. Least Privilege

Least privilege means each component and authorization should carry only the
authority needed for its task.

The proxy's approval model treats approvals as capability tokens, not flat
permissions:

- **Signed:** authoritative decisions are signed by the AVP backend signer DID.
- **Scoped:** receipts bind risk class, policy context hash, payload hash, and
  request metadata.
- **Time-bounded:** follow-on grants such as `similar_5m` expire quickly.
- **Replay-resistant:** the local replay cache rejects repeated signed receipts
  within the proxy's retention window, and offline verification rejects duplicate
  receipt references in a bundle.
- **Attenuatable:** cache-hit records reference `granted_by_request_id`; they
  inherit a narrower follow-on scope rather than broadening authority.

High-risk headless pre-approvals also require exact payload binding unless the
operator explicitly opts into a narrow-match exception. Destructive,
production, and financial approvals are therefore tied to concrete action
evidence, not broad standing rights.

## 7. Least Common Mechanism

Least common mechanism asks designs to minimize shared mutable machinery that
many users depend on.

The documented deployment pattern is one proxy process per IDE client:

- Each proxy process has its own local approval server port.
- Each proxy home has its own identity, control grant, and evidence database.
- Each proxy process has independent circuit breaker state.
- Each process starts and supervises one downstream MCP server.

This avoids turning a single local proxy into shared mutable control state for
multiple IDEs. Cross-IDE isolation is not absolute because all processes still
share the host operating system, but the AVP component itself does not add a
shared approval queue or shared downstream subprocess across IDE clients.

For centralized policy across multiple developers, enforce policy in the AVP
backend or deployment environment. Do not multiplex unrelated developer IDEs
through one local proxy as a shortcut.

## 8. Psychological Acceptability

Psychological acceptability means people should be able to use the protection
mechanism correctly without fighting the interface.

The proxy keeps the first-use path familiar:

- `agentveil-mcp-proxy init` creates identity, config, and control grant.
- `agentveil-mcp-proxy doctor` validates local state.
- `agentveil-mcp-proxy run` starts the stdio proxy used by MCP clients.

Built-in policy packs (`default`, `github`, `filesystem`, and `shell`) let
operators start from reviewable defaults before writing custom policy rules.
The browser approval surface uses conventional form semantics: review a
privacy-filtered action, approve, deny, or let it expire. The operations guide
documents the trade-offs between TTY passphrases, passphrase files, command-line
arguments, and environment variables instead of presenting them as equivalent.

The intended customer experience is constrained but not obscure: users can see
what is being requested, why a policy decision happened, where evidence is
stored, and how to export proof for offline verification.

## Capability References

The proxy's capability-token framing aligns with Mark Miller's
[Robust Composition](https://isr.uci.edu/content/robust-composition-towards-unified-approach-access-control-and-concurrency-control)
work on object-capability security and with Macaroons' contextual caveat model
from [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/).

AVP does not implement macaroons directly. The comparison is architectural:
authority is expressed as bounded, signed, context-specific evidence rather
than as a broad ambient permission. The practical enforcement fields are AVP
DecisionReceipt signatures, policy context hashes, payload hashes, risk classes,
request IDs, expiry timestamps, local replay cache state, and evidence-chain
records.

For operational details, see [`MCP_PROXY_OPERATIONS.md`](MCP_PROXY_OPERATIONS.md).
For security context and known limitations, see the
[v0.1 release notes](../CHANGELOG.md) and the security sections in the
operations guide.
