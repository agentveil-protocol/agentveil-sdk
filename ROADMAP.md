# AVP Roadmap

## Current — Public SDK 0.7.8 + Production API

- [x] Public Python SDK 0.7.8 on PyPI: `pip install agentveil`
- [x] Production API for agent identity, advisory reputation, credentials, cards, audit verification, and Runtime Gate flows
- [x] W3C DID identity (`did:key`, Ed25519)
- [x] AVP-Sig request signing for authenticated protocol calls
- [x] Posture/setup readiness checks with `integration_preflight()`
- [x] Runtime Gate controlled-action flow with `controlled_action(...)`
- [x] Local DelegationReceipt v1 issuance with `issue_delegation_receipt(...)`
- [x] Signed runtime receipts and proof packet verification
- [x] AVP JSON and W3C reputation credentials with offline verification
- [ ] Public security model: SDK mode vs gateway enforcement mode
- [x] MCP server: 12 tools in local/full mode, with 8 read-only tools available in hosted mode
- [x] Framework examples for CrewAI, LangGraph, AutoGen, OpenAI, Claude MCP, Paperclip, Gemini, PydanticAI, and AWS Bedrock
- [x] AVPProvider merged into Microsoft Agent Governance Toolkit (PR #1010)

## Rollout

- [x] Human approval and execution receipt proof model
- [x] Proof packet verification for signed runtime evidence
- [ ] Broader controlled-action rollout for customer workflows
- [ ] Operator-facing documentation for production adoption
- [ ] Customer-facing DelegationReceipt issuance UX and examples

## Planned

- [ ] Public agent reputation dashboard
- [ ] Expanded hosted MCP catalog metadata and recrawl
- [ ] Deployment documentation for approved customer environments
- [ ] Formal protocol specification v1.0
- [ ] Expanded Runtime Gate examples for common agent stacks
- [ ] Execution boundary and gateway adapter contract
- [ ] CLI: `agentveil demo controlled-action`
- [ ] CLI: `agentveil proof export` and `agentveil proof verify --offline`
- [ ] Posture Check report for risky tools, write access, credentials location, and bypass paths

## Research / Future

- [ ] Runtime proof and offline verification publication
- [ ] ERC-8004 bridge exploration
- [ ] Federation between AVP nodes
