# Security Context for Agent Action Control

AgentVeil's product focus is action control: mediating configured agent
actions, requiring approval where needed, redirecting agents to controlled
paths, blocking unsafe mutations, and recording bounded evidence.

Identity, DID, attestations, and reputation remain useful protocol primitives,
but they are advisory and supporting signals. They do not replace action
control and do not grant execution authority by themselves.

## The Problem in Numbers

- **88%** of organizations experienced confirmed or suspected security incidents
  involving AI agents in the past year
  *(Gravitee "State of AI Agent Security 2026", n=750 CIO/CTO/VP, Feb 2026)*

- Only **21.9%** treat AI agents as independent, identity-bearing entities.
  The rest share credentials between agents or merge them with existing
  service accounts
  *(Gravitee, Feb 2026)*

- Only **14.4%** of AI agents reached production with full security/IT approval
  *(Gravitee, Feb 2026)*

- Machine-to-human identity ratio in enterprise: **100:1** and growing
  *(Cloud Security Alliance, "State of Cloud and AI Security", March 2026)*

*Note: Gravitee has a commercial interest in agent security infrastructure.
Their survey data is cited as industry context, not as independent research.*


## Recent CVEs Demonstrating the Gap

### MCP Server Vulnerabilities (mcp-server-git)

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2025-68143 | 6.5 Medium | Path traversal — `git_init` accepted arbitrary paths, creating repos anywhere on the filesystem |
| CVE-2025-68144 | 6.3 Medium | Argument injection — user-controlled args passed to git CLI without sanitization |
| CVE-2025-68145 | 6.4 Medium | Repository scoping bypass — `--repository` flag did not validate subsequent tool call paths |

All three fixed in mcp-server-git 2025.12.17. Published by GitHub via NVD.

### Agent Runtime Vulnerabilities (Claude Code)

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2025-59536 | 8.7 High | Code injection — malicious project files executed before user accepted trust dialog. Fixed in v1.0.111 |
| CVE-2026-21852 | 5.3 Medium | API token exfiltration — modified config files redirected API calls to attacker endpoints before security prompts. Fixed in v2.0.65 |

*These CVEs are not an attack on Anthropic — they demonstrate that agent runtime
vulnerabilities are real even at the best organizations in the industry.*


## Agent Identity Attacks in the Wild

### Moltbook Incident (January 2026)

Moltbook, an AI agent social network, suffered an unsecured database
vulnerability discovered by Wiz Research:

- **Supabase API key** exposed in client-side JavaScript
- **1.5 million** API authentication tokens accessible without authentication
- **35,000** email addresses exposed
- Private messages between agents readable by anyone

The viral "secret language" post — where agents appeared to create an
encrypted communication protocol — turned out to be a human posting under
an agent's credentials, made possible by the platform's complete lack of
agent identity verification.

Meta Platforms acquired Moltbook on March 10, 2026.

*(Sources: 404 Media, Jan 31, 2026; Wiz Research disclosure)*


## The Structural Problem

These incidents point to a structural control gap: agents increasingly operate
with credentials, tools, and workflow access, but risky actions are often not
mediated before execution and are hard to prove after the fact.

Current state of many agent deployments:
- Agents authenticate with **static API keys** (long-lived, shared, easily stolen)
- Mutating actions may bypass project-local approval or policy checks
- Logs often show that something happened without binding the exact action,
  decision, approval, and payload evidence
- Identity and reputation signals are useful context, but they do not by
  themselves constrain what an agent can do next


## What AVP Addresses

Primary action-control mitigations:

| Risk | AVP mitigation |
|------|----------------|
| Risky agent mutation | Project connector or routed MCP boundary mediates configured actions before execution |
| Missing human review | Approval-required decisions route sensitive actions to a review step |
| Unsafe path available | Redirect or hard-block decisions steer the agent toward controlled tools or stop the action |
| Weak audit trail | Bounded evidence records decision, action context, hashes, and timestamps |
| Overbroad authority | Scoped receipts and capability-token patterns bind authority to concrete action context |

Supporting protocol primitives:

| Signal | Role |
|--------|------|
| DID (`did:key`) + Ed25519 | Local identity and signed request authentication |
| Per-agent keypair | Reduces credential sharing inside AVP-controlled flows |
| Advisory reputation / EigenTrust-style scoring | Selection and risk input, not execution permission |
| Attestations and disputes | Supporting trust operations for contested outcomes |
| Credentials and proof artifacts | Portable evidence for advanced integrations |


## References

1. Gravitee. "State of AI Agent Security 2026." February 4, 2026.
   Survey conducted by Opinion Matters, n=750 CIO/CTO/VP, US+UK.
2. Cloud Security Alliance. "State of Cloud and AI Security." March 2026.
3. NIST NVD. CVE-2025-68143, CVE-2025-68144, CVE-2025-68145 (mcp-server-git).
4. NIST NVD. CVE-2025-59536, CVE-2026-21852 (Claude Code, Anthropic).
5. 404 Media. Moltbook vulnerability disclosure. January 31, 2026.
6. Wiz Research. Moltbook database exposure analysis. January 2026.
