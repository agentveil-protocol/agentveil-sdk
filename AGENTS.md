# AGENTS.md

## Project overview

AVP SDK — Python client for Agent Veil Protocol. Trust enforcement for autonomous agents: identity (W3C DID), reputation (EigenTrust), sybil resistance (NetFlow), attestations, audit trail, webhook alerts, jobs delegation.

Production API: https://agentveil.dev
PyPI: `pip install agentveil`

## Setup

```bash
pip install agentveil
# or with test deps:
pip install agentveil[test]
```

No external services needed for development — the SDK connects to the public API at agentveil.dev by default.

## Build and test

```bash
# Run tests
pytest tests/ -v

# Run live E2E smoke test against production
python tests/test_live_e2e.py

# Run against local server
AVP_URL=http://localhost:8000 pytest tests/ -v
```

## CI policy

Follow [`docs/CI_POLICY.md`](docs/CI_POLICY.md).

- Run relevant local tests before pushing code changes.
- The push fast gate is not release verification.
- The full OS/Python compatibility gate must pass before release tags or PyPI publication.
- Do not use `[skip ci]` for code, packaging, security, or behavior changes.
- When reporting done, state the local commands and CI gates that actually ran.

## Code style

- Python 3.10+
- Type hints on all public methods
- Docstrings on all public classes and methods
- No external dependencies beyond httpx, pynacl, base58
- Defensive parsing: always `.get()` on external API responses, never direct `dict["key"]`

## Testing

- Unit tests with mocked API: `tests/test_e2e_mock.py`
- Live E2E test: `tests/test_live_e2e.py` (creates real agents, cleans up after)
- Contract test: `tests/test_openapi_contract.py` (validates SDK endpoints vs server)

## Agent capabilities

This SDK provides AI agents with:

| Capability | Method | Description |
|---|---|---|
| Identity | `AVPAgent.create()` + `.register()` | W3C DID (did:key), Ed25519 signatures |
| Reputation | `.get_reputation(did)` | EigenTrust score, confidence, tier, risk factors |
| Trust decision | `.can_trust(did)` | Advisory yes/no with tier check |
| Attestation | `.attest(to_did, outcome)` | Peer-to-peer trust rating |
| Search | `.search_agents(capability)` | Find agents by capability |
| Alerts | `.set_alert(webhook_url, threshold)` | Score drop notifications |
| Audit | `.get_audit_trail()` | Hash-chained, IPFS-anchored event log |

## MCP server

Built-in MCP server for Claude Desktop, Cursor, Windsurf, VS Code:

```bash
pip install 'agentveil[mcp]'
agentveil-mcp
```

20 local/full tools: 8 public read-only tools, 4 identity/write tools, and 8
explicit action-control tools for Runtime Gate, approvals, and signed receipts.
Hosted `AVP_MCP_READONLY=1` exposes only the 8 read-only tools. The MCP server
is an explicit toolbox, not an automatic proxy for other MCP tool calls.

Glama directory: https://glama.ai/mcp/servers/agentveil-protocol/agentveil-sdk

## DID support

Agents are identified by W3C Decentralized Identifiers:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Format: Ed25519 public key, multicodec-encoded, base58btc. Generated locally — no registry needed for creation. Registered on AVP for reputation tracking.

## Examples

| File | Framework | Description |
|---|---|---|
| `quickstart.py` | — | 5-step minimal demo |
| `two_agents.py` | — | Multi-agent attestation flow |
| `aws_bedrock.py` | AWS Bedrock | Trust-gated delegation via Converse API |
| `openai_example.py` | OpenAI | Function calling with AVP tools |
| `claude_mcp_example.py` | Claude MCP | MCP server integration |
| `langgraph_example.py` | LangGraph | Trust-aware graph agent |
| `crewai_example.py` | CrewAI | Governed crew with reputation |
| `autogen_example.py` | AutoGen | Microsoft AutoGen integration |

## Security considerations

- All write operations require Ed25519 signature (`AVP-Sig` header)
- Proof-of-Work (24-bit) required at registration to prevent spam
- Never hardcode private keys — use `agent.save(passphrase="...")` for encrypted storage
- API responses should always be validated before acting on them
