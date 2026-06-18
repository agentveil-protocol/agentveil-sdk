# AgentVeil Data Handling

AgentVeil's privacy posture is based on data minimization:

> AgentVeil does not train models on customer data and does not sell customer
> data. Local tools stay local. Hosted control services store the minimum
> operational metadata and signed evidence needed to gate, prove, and audit
> agent actions. Raw prompts, source code, secrets, credentials, and sensitive
> customer payloads should not be sent to AgentVeil unless a hosted workflow
> explicitly requires that content.

## Local Tools

| Surface | Default behavior |
|---|---|
| SDK local identity/signing | Creates keys and signs requests locally. Private keys stay under the caller's control. |
| MCP Proxy local operations | Classifies tool calls locally, computes hashes, and stores local approval evidence without raw MCP arguments by default. |
| Offline proof verification | Verifies signed receipts and proof packets locally without calling AgentVeil. |

Lurkr, the separate pre-runtime scanner, is also local-only: it does not upload
source code, scan reports, findings, or usage telemetry to AgentVeil and does
not make network calls during scan.

## Hosted AgentVeil Ledger

Runtime Gate, receipts, approvals, delegation, reputation, governance, and audit
APIs are designed around bounded operational metadata and signed evidence:

- agent identifiers, public keys, display names, and registration metadata;
- action name, resource identifier, environment, decision, reason, timestamps;
- payload/resource/request hashes;
- signed decision, execution, approval, and audit receipts;
- reputation, delegation, governance policy, and risk-signal metadata;
- API request metadata needed for security, abuse prevention, and rate limits.

This ledger is intended to prove who requested an action, what action was
evaluated, which policy or risk class applied, who or what approved or blocked
it, when it happened, and which exact payload was involved if the customer later
presents the raw artifact for hash verification.

## Customer Evidence Store

Raw evidence should normally remain with the customer:

- local files or local MCP Proxy evidence bundles;
- customer SIEM;
- customer-owned S3, GCS, Azure Blob, or equivalent object storage;
- enterprise deployment with customer-managed keys or customer-owned storage.

AgentVeil links to that evidence through hash binding:

1. The client or MCP Proxy observes raw arguments, prompts, outputs, or other
   workflow data locally.
2. It computes `payload_hash`, `params_hash`, `result_hash`, or a resource hash.
3. Runtime Gate receives action metadata, risk class, resource identifier or
   hash, and payload hash, not the raw sensitive artifact.
4. AgentVeil signs a decision receipt that includes the hash.
5. Execution and approval receipts bind later states to the same hash chain.
6. During an audit, the customer can present the raw artifact; the auditor
   recomputes the hash and compares it with the signed receipt.

This preserves proof value without requiring AgentVeil to retain raw sensitive
history.

## Reputation Data

Reputation needs behavioral history, not private payload content. Useful
reputation inputs include:

- allowed, denied, blocked, completed, failed, or disputed outcomes;
- severity and risk class;
- evidence hash;
- reporter, verifier, and agent DIDs;
- attestations;
- approval history;
- policy violations;
- signed receipt references.

Reputation should not require raw prompts, source code, secrets, tool outputs, or
private logs.

## Hosted Content Surfaces

Some SDK/API paths can process user-provided content because that content is the
workflow input:

- direct SDK execution parameters passed through `controlled_action(...)`,
  `execute(...)`, or `execute_after_approval(...)`;
- legacy or experimental hosted workflows, only when explicitly enabled;
- support requests and similar hosted content workflows;
- user-provided configuration or metadata fields.

Do not describe these paths as metadata-only. Use them only when the content is
intentionally part of the hosted workflow.

## What Not To Send

Do not place secrets, credentials, private prompts, source code, private logs,
personal data, confidential business content, or sensitive customer payloads in:

- action names;
- resource names;
- metadata fields;
- policy fields;
- denial reasons;
- support messages;
- legacy or experimental hosted workflow fields;
- direct execution `params`.

For sensitive actions, prefer resource IDs, content hashes, request hashes, and
bounded metadata. MCP Proxy is the preferred path for MCP clients when raw tool
arguments should remain local.

## MCP Proxy Privacy Boundary

MCP Proxy keeps raw MCP arguments, prompts, outputs, tokens, source code,
secrets, and private logs out of its local evidence store by default. It sends
Runtime Gate only the privacy-filtered metadata required for a decision, such as
server/tool names, action class, risk class, resource hash, payload hash, policy
context hash, and timestamps.

If a proxy privacy option displays plain action or resource details in a local
approval UI, that affects the local UI. It should not turn hosted Runtime Gate
metadata into raw MCP payload storage.

## Model Training and Sale

AgentVeil does not use customer data, source code, prompts, legacy or
experimental hosted workflow content, execution parameters, action metadata,
receipts, or scan reports to train AI models. AgentVeil does not sell customer
data.

## Retention

During preview, AgentVeil's hosted operational-data retention target is 30 days.
Security, abuse-prevention, legal, or customer-requested audit evidence records
may need longer retention. Treat this as a product retention target, not a
zero-retention or zero-knowledge claim.

## Claims To Avoid

Do not claim:

- "AgentVeil cannot access your data";
- "AgentVeil stores no customer data";
- "all hosted AgentVeil APIs are metadata-only";
- "zero retention" or "zero knowledge" for hosted workflows.

The accurate claim is narrower and stronger: AgentVeil minimizes data, does not
train on customer data, does not sell customer data, keeps local tools local, and
uses hashes and signed evidence for control/audit workflows wherever possible.
