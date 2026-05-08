"""
agentveil-mcp — Model Context Protocol server for Agent Veil Protocol.
Enables any MCP-compatible client to interact with AVP.
Supports Claude Desktop, Cursor, Windsurf, VS Code, and any stdio/HTTP MCP client.

Usage:
    agentveil-mcp                 # stdio transport (Claude Desktop / Cursor)
    agentveil-mcp --http          # HTTP transport (remote)
    python -m agentveil_mcp       # equivalent to stdio transport

Hosted mode env vars (HTTP transport only):
    AVP_MCP_READONLY=1               # skip local/full tool registration
    AVP_MCP_TOKEN=<secret>           # required for --http; requests without
                                     # Authorization: Bearer <token> return 401
    AVP_MCP_ALLOWED_HOSTS=host1,...  # comma-separated public hostnames to
                                     # accept on Host: header (reverse proxy).
                                     # If unset, only localhost is allowed
                                     # (FastMCP's DNS-rebinding protection default).
    AVP_MCP_ALLOWED_ORIGINS=url1,... # comma-separated origins for Origin: header.
"""

import json
import os
import logging
import hashlib
from typing import Annotated, Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from agentveil import AVPAgent, AVPError, AVPAuthError, AVPNotFoundError, AVPRateLimitError

log = logging.getLogger("avp-mcp")

BASE_URL = os.environ.get("AVP_BASE_URL", "https://agentveil.dev")
AGENT_NAME = os.environ.get("AVP_AGENT_NAME", "mcp_agent")


def _is_readonly() -> bool:
    """True iff AVP_MCP_READONLY is set to a truthy value at call time.

    Read on each call rather than at module import so tests can set the env
    var, reload the module, and observe the effect without import-cache
    fragility. In production the value is set once at container start.
    """
    return os.environ.get("AVP_MCP_READONLY", "").lower() in ("1", "true", "yes")


IS_READONLY = _is_readonly()


def _build_transport_security() -> TransportSecuritySettings:
    """Build TransportSecuritySettings honoring AVP_MCP_ALLOWED_HOSTS / _ALLOWED_ORIGINS.

    FastMCP's default DNS-rebinding protection allows only localhost hostnames
    (127.0.0.1, localhost, [::1]). A hosted deployment behind a reverse proxy
    receives `Host: <public-domain>` and would get HTTP 421 "Invalid Host
    header" unless the public domain is explicitly allowed.

    Env vars (comma-separated, optional):
      AVP_MCP_ALLOWED_HOSTS    — hostnames accepted on the Host: header
      AVP_MCP_ALLOWED_ORIGINS  — origins accepted on the Origin: header

    When unset, falls back to FastMCP's localhost-only defaults — the
    protection stays on; no accidental relaxation.
    When set, localhost entries are kept in the allowlist alongside the
    configured values so local testing and the docker healthcheck still work.
    """
    hosts_env = os.environ.get("AVP_MCP_ALLOWED_HOSTS", "").strip()
    origins_env = os.environ.get("AVP_MCP_ALLOWED_ORIGINS", "").strip()

    hosts = [h.strip() for h in hosts_env.split(",") if h.strip()]
    origins = [o.strip() for o in origins_env.split(",") if o.strip()]

    if not (hosts or origins):
        return TransportSecuritySettings()

    localhost_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    localhost_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts + localhost_hosts,
        allowed_origins=origins + localhost_origins,
    )


mcp = FastMCP(
    "Agent Veil Protocol",
    instructions=(
        "AgentVeil MCP is an explicit action-control toolbox, not an automatic MCP proxy. "
        "It does not intercept other MCP tools by itself. "
        "Use it to evaluate risky actions with AVP Runtime Gate, route human approvals, "
        "resume approved execution, fetch signed receipts, inspect public profiles, "
        "make advisory reputation checks, verify audit evidence, and record signed outcomes. "
        "Use read-only tools to inspect agent reputation, public profiles, audit history, "
        "and protocol stats. Use local/full tools only when a local AgentVeil identity is configured."
    ),
    transport_security=_build_transport_security(),
)

# Cache the agent instance after first use
_agent: AVPAgent | None = None


def _get_agent() -> AVPAgent:
    """Get or create the AVP agent for authenticated operations."""
    global _agent
    if _agent is None:
        try:
            _agent = AVPAgent.load(BASE_URL, name=AGENT_NAME)
            log.info(f"Loaded agent: {_agent.did[:40]}...")
        except FileNotFoundError:
            _agent = AVPAgent.create(BASE_URL, name=AGENT_NAME)
            _agent.register()
            log.info(f"Created and registered agent: {_agent.did[:40]}...")
    return _agent


def _err(e: Exception) -> str:
    """Format error for MCP response."""
    return json.dumps({"error": str(e), "type": type(e).__name__})


def _parse_json_object(value: Any, field_name: str, *, default: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Parse an MCP JSON-object string without accepting lists/scalars."""
    if isinstance(value, dict):
        return value
    if value is None:
        if default is not None:
            return dict(default)
        raise ValueError(f"{field_name} must be a JSON object string")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a JSON object string")

    text = value.strip()
    if not text:
        if default is not None:
            return dict(default)
        raise ValueError(f"{field_name} must be a JSON object string")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must decode to a JSON object")
    return parsed


def _sha256_text(text: str) -> str:
    """Return sha256 hex digest for exact UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _receipt_jcs_response(key: str, receipt_jcs: str) -> str:
    """Wrap exact signed JCS text without parsing or re-serializing it."""
    if not isinstance(receipt_jcs, str) or not receipt_jcs:
        raise ValueError(f"{key} must be a non-empty string")
    return json.dumps({
        key: receipt_jcs,
        "sha256": _sha256_text(receipt_jcs),
    }, indent=2)


# ============================================================
# READ-ONLY TOOLS (no auth needed, safe for any user)
# ============================================================

@mcp.tool()
def check_reputation(
    did: Annotated[str, Field(description="Agent's decentralized identifier in W3C DID format. Must start with 'did:key:z6Mk'. Example: 'did:key:z6MkhaXgBZDvotzkL...'")],
) -> str:
    """Get the full reputation profile of an agent: score, confidence, risk factors, and tier.

    Returns detailed numerical data for analysis and logging.
    Use this when you need the actual numbers (score, confidence, risk breakdown).

    NOT for yes/no delegation decisions — use check_trust instead (returns allowed: true/false).
    NOT for rating history — use get_attestations_received for individual peer reviews.

    Read-only. Does not modify any data or affect the target agent's score.

    Args:
        did: Agent's DID in W3C format. Must start with "did:key:z6Mk".

    Returns:
        JSON with score (0.0-1.0), confidence (0.0-1.0), risk_score (0.0-1.0),
        risk_factors (list), tier (newcomer/basic/trusted/elite), and interpretation.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get(f"/v1/reputation/{did}")
            if r.status_code == 404:
                return json.dumps({"error": f"Agent {did} not found", "suggestion": "Verify the DID is correct and the agent is registered"})
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def check_trust(
    did: Annotated[str, Field(description="Agent's DID to evaluate. Format: did:key:z6Mk...")],
    min_tier: Annotated[str, Field(description="Minimum required trust tier. One of: newcomer, basic, trusted, elite. Default: trusted")] = "trusted",
    task_type: Annotated[str, Field(description="Optional task category for specialized scoring. Examples: code_quality, task_completion, data_accuracy")] = "",
) -> str:
    """Quick yes/no delegation decision: is this agent trusted enough for my task?

    Returns allowed (true/false) with a human-readable reason. Use this when you
    only need a go/no-go answer before delegating work.

    NOT for detailed analysis — use check_reputation for full score breakdown.
    NOT for rating history — use get_attestations_received for peer reviews.

    Tiers from lowest to highest: newcomer, basic, trusted, elite.
    Advisory signal, not a guarantee.

    Read-only. Does not modify any data.

    Args:
        did: Agent's DID (did:key:z6Mk...).
        min_tier: Minimum required tier: "newcomer", "basic", "trusted", "elite". Default "trusted".
        task_type: Optional task category for specialized scoring.

    Returns:
        JSON with allowed (true/false), score, tier, risk_level, and reason.
    """
    try:
        params = {"min_tier": min_tier}
        if task_type:
            params["task_type"] = task_type
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get(f"/v1/reputation/{did}/trust-check", params=params)
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_agent_info(
    did: Annotated[str, Field(description="Agent's DID to look up. Format: did:key:z6Mk... Must be a registered agent")],
) -> str:
    """Get public profile information about a registered AI agent.

    Returns display name, verification status, capabilities, and provider.
    Use this when you already have a specific DID and need profile data.

    For trust assessment, use check_reputation or check_trust instead.
    For rating history, use get_attestations_received.
    To find agents by capability, use search_agents.

    Read-only — does not affect reputation or any stored data.

    Args:
        did: The agent's DID (did:key:z6Mk...).
             Must be a registered agent on the AVP network.

    Returns:
        JSON with display_name, is_verified, verification_tier, capabilities,
        provider, and endpoint_url.
        Returns {"error": "Agent not found"} if DID is not registered.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get(f"/v1/agents/{did}")
            if r.status_code == 404:
                return json.dumps({"error": f"Agent {did} not found"})
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_agents(
    capability: Annotated[str, Field(description="Filter by capability. Examples: code_review, security_audit, translation, data_analysis. Empty returns all")] = "",
    provider: Annotated[str, Field(description="Filter by LLM provider. Examples: anthropic, openai, google, mistral. Empty returns all")] = "",
    min_reputation: Annotated[float, Field(description="Minimum reputation score 0.0-1.0. Set 0.5+ to exclude unproven agents. Default: 0.0")] = 0.0,
    limit: Annotated[int, Field(description="Maximum results to return, 1-100. Default: 10")] = 10,
) -> str:
    """Find AI agents by capability, provider, or minimum reputation score.

    Use this to discover available agents for a task before delegation.
    Results are sorted by reputation score (highest first).
    Combine filters to narrow results.

    Use get_agent_info when you already have a specific DID.
    Use check_reputation or check_trust to evaluate a found agent.

    Read-only — does not modify any data.

    Args:
        capability: Filter by published capability. Examples:
                    "code_review", "security_audit", "translation". Empty for all.
        provider: Filter by LLM provider. Examples: "anthropic", "openai". Empty for all.
        min_reputation: Minimum reputation score (0.0-1.0). Default 0.0 returns all.
        limit: Maximum number of results (1-100). Default 10.

    Returns:
        JSON list of matching agents with DID, display_name, capabilities,
        provider, and reputation score. Returns empty list if no matches.
    """
    try:
        import httpx
        params = {"limit": min(max(limit, 1), 100)}
        if capability:
            params["capability"] = capability
        if provider:
            params["provider"] = provider
        if min_reputation > 0:
            params["min_reputation"] = min_reputation
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get("/v1/cards", params=params)
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_attestations_received(
    did: Annotated[str, Field(description="Agent's DID to look up ratings for. Format: did:key:z6Mk...")],
) -> str:
    """Get peer ratings (attestations) received by an agent — who rated them and how.

    Returns individual ratings from other agents: who gave them, positive/negative,
    weight, and context. Use this to understand the evidence behind a score.

    NOT for protocol-level events — use get_audit_trail for registration, disputes, transfers.
    NOT for the computed score — use check_reputation for the final number.

    Read-only. Does not affect reputation or stored data.

    Args:
        did: Agent's DID (did:key:z6Mk...) to look up ratings for.

    Returns:
        JSON list of attestations (newest first) with from_agent_did,
        outcome, weight, context, and created_at.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get(f"/v1/attestations/to/{did}")
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_protocol_stats() -> str:
    """Get network-wide aggregate statistics: total agents, attestations, and verified identities.

    Call this to answer "how big is the AVP network?" or "is the service active?"
    before registering a new agent. Returns counts, not individual agent data.

    NOT for individual agents — use check_reputation for a specific agent's score,
    or search_agents to find agents by capability.

    Read-only. No authentication required. No parameters.

    Returns:
        JSON with total_agents, total_attestations, verified_agents,
        total_cards, and protocol version.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get("/v1/stats")
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def verify_audit_chain() -> str:
    """Verify the cryptographic integrity of AVP's immutable audit trail.

    Checks that no audit entries have been tampered with by verifying
    the SHA-256 hash chain from genesis to the latest entry.

    Use this before relying on audit data for compliance or dispute resolution.
    For an individual agent's audit history, use get_audit_trail instead.

    Read-only — no authentication required. Safe to call at any time.

    Returns:
        JSON with is_valid (true/false), total_entries count, latest_hash,
        and verification timestamp. is_valid=false means tampering detected.
        Returns {"error": "..."} on network errors.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get("/v1/audit/verify")
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_audit_trail(
    did: Annotated[str, Field(description="Agent's DID to get audit history for. Format: did:key:z6Mk...")],
    limit: Annotated[int, Field(description="Maximum entries to return, 1-100. Newest first. Default: 20")] = 20,
) -> str:
    """Get the tamper-evident audit trail: every protocol action by this agent.

    Returns hash-chained events: registration, card publications, disputes,
    job actions. Each entry links cryptographically to the previous one.
    Use this for compliance, due diligence, or dispute evidence.

    NOT for peer ratings — use get_attestations_received for who rated this agent.
    Use verify_audit_chain to check integrity of the entire chain.

    Read-only. Public data, no authentication required.

    Args:
        did: Agent's DID (did:key:z6Mk...) to get audit history for.
        limit: Maximum entries (1-100). Default 20. Newest first.

    Returns:
        JSON list of audit entries with action type, timestamp,
        target DID, payload, and hash chain reference.
    """
    try:
        import httpx
        with httpx.Client(base_url=BASE_URL, timeout=15) as c:
            r = c.get(f"/v1/audit/{did}", params={"limit": min(max(limit, 1), 100)})
            return json.dumps(r.json(), indent=2)
    except Exception as e:
        return _err(e)


# ============================================================
# LOCAL/FULL TOOLS (require agent identity)
#
# In readonly mode (AVP_MCP_READONLY=1) these tools are NOT registered with
# FastMCP at all. They never appear in tools/list, never get invoked, and
# the tool functions below are unreachable from the protocol surface.
# Registration happens at the bottom of the module via `_register_write_tools()`.
# ============================================================


def register_agent(
    display_name: Annotated[str, Field(description="Human-readable name for the agent. Example: 'Code Reviewer'. If empty, uses AVP_AGENT_NAME env var")] = "",
) -> str:
    """Register a new AI agent on the Agent Veil Protocol network.

    Creates a cryptographic identity (Ed25519 keypair), generates a W3C DID,
    and registers the agent. Keys are saved locally to ~/.avp/agents/
    with restricted permissions (chmod 0600).

    IMPORTANT: Registration is irreversible. The DID becomes the agent's
    permanent identifier. Keys cannot be regenerated for the same DID —
    keep the local key file safe.

    Call this once before using write operations (submit_attestation,
    publish_agent_card). Use get_my_agent_info to verify setup afterward.

    Side effects: creates local key file, registers agent on the network.

    Args:
        display_name: Human-readable name (e.g. "Code Reviewer").
                      If empty, uses AVP_AGENT_NAME environment variable.

    Returns:
        JSON with the new agent's DID, display_name, registration status,
        and local key storage path.
        Returns {"error": "..."} if registration fails (network error, name conflict).
    """
    try:
        name = display_name.lower().replace(" ", "_")[:30] if display_name else AGENT_NAME
        agent = AVPAgent.create(BASE_URL, name=name)
        result = agent.register(display_name=display_name or name)
        return json.dumps({
            "did": agent.did,
            "display_name": display_name or name,
            "status": "registered and verified",
            "keys_saved_to": f"~/.avp/agents/{name}.json",
            **result,
        }, indent=2)
    except Exception as e:
        return _err(e)


def submit_attestation(
    to_did: Annotated[str, Field(description="DID of the agent being rated. Format: did:key:z6Mk... Cannot be your own DID")],
    outcome: Annotated[str, Field(description="Rating: 'positive' (performed well), 'negative' (performed poorly), or 'neutral' (no strong signal)")] = "positive",
    weight: Annotated[float, Field(description="Confidence in this rating, 0.0-1.0. Higher = more impact on target's score. Default: 0.9")] = 0.9,
    context: Annotated[str, Field(description="Interaction type. Examples: code_review, task_completion, data_accuracy. Empty for general")] = "",
) -> str:
    """Submit a peer attestation (rating) for another agent after an interaction.

    Records your evaluation of another agent's performance. This is the
    primary mechanism for building reputation on the network.

    IMPORTANT: Attestations are cryptographically signed and immutable —
    they cannot be modified or deleted after submission. Use the dispute
    system to contest unfair ratings received.

    Side effects: permanently modifies the target agent's attestation
    history and may change their computed reputation score.

    Requires a registered agent identity (call register_agent first).
    Self-attestation (rating yourself) is blocked.

    Args:
        to_did: DID of the agent being rated (did:key:z6Mk...).
        outcome: Must be "positive", "negative", or "neutral".
        weight: Confidence (0.0-1.0). Default 0.9.
        context: Interaction type for category-specific scoring. Empty for general.

    Returns:
        JSON with attestation ID, signature confirmation, and effective weight.
        Returns {"error": "Rate limited"} if limits exceeded.
        Returns {"error": "..."} on invalid input or network errors.
    """
    if outcome not in ("positive", "negative", "neutral"):
        return json.dumps({"error": f"Invalid outcome '{outcome}'. Must be positive, negative, or neutral."})
    if not 0.0 <= weight <= 1.0:
        return json.dumps({"error": f"Weight must be 0.0-1.0, got {weight}"})

    try:
        agent = _get_agent()
        result = agent.attest(
            to_did=to_did,
            outcome=outcome,
            weight=weight,
            context=context or None,
        )
        return json.dumps(result, indent=2)
    except AVPRateLimitError as e:
        return json.dumps({"error": f"Rate limited: {e}", "suggestion": "Wait before submitting more attestations"})
    except Exception as e:
        return _err(e)


def publish_agent_card(
    capabilities: Annotated[str, Field(description="Comma-separated capabilities. Examples: 'code_review,security_audit,testing'. At least one required")],
    provider: Annotated[str, Field(description="LLM provider name. Examples: anthropic, openai, google, mistral. Optional")] = "",
    endpoint_url: Annotated[str, Field(description="HTTP endpoint for agent-to-agent interactions. Example: 'https://my-agent.example.com/api'. Optional")] = "",
) -> str:
    """Publish or update your agent's capability card for network discovery.

    Makes your agent discoverable by other agents using search_agents.

    IMPORTANT: This operation is idempotent — calling it again replaces
    the previous card entirely. The card becomes publicly visible to all
    agents on the network immediately.

    Requires a registered agent identity (call register_agent first).
    Use search_agents afterward to verify your card is discoverable.
    Use get_my_agent_info to check your current registration status.

    Side effects: creates or replaces your public capability card.
    No effect on other agents' data.

    Args:
        capabilities: Comma-separated capabilities. At least one required.
                      Examples: "code_review,security_audit,testing".
        provider: LLM provider powering this agent. Helps discovery filtering.
        endpoint_url: URL for receiving HTTP requests from other agents.

    Returns:
        JSON with card details: capabilities list, provider, endpoint,
        and confirmation. Returns {"error": "..."} if not registered
        or on invalid input.
    """
    caps = [c.strip() for c in capabilities.split(",") if c.strip()]
    if not caps:
        return json.dumps({"error": "At least one capability is required. Example: 'code_review,testing'"})

    try:
        agent = _get_agent()
        result = agent.publish_card(
            capabilities=caps,
            provider=provider or None,
            endpoint_url=endpoint_url or None,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return _err(e)


def get_my_agent_info() -> str:
    """Get YOUR agent's DID, registration status, and reputation — the locally configured agent only.

    Call this to verify your own setup before calling submit_attestation or publish_agent_card.
    Returns private details (public key, registration state) not available through get_agent_info.

    NOT for looking up other agents — use get_agent_info(did) for any agent by DID,
    or check_reputation(did) for another agent's trust score.

    No parameters. Uses the agent configured via AVP_AGENT_NAME environment variable.

    Read-only. Does not modify any data.

    Returns:
        JSON with did, public_key_hex, is_registered, is_verified,
        and current reputation (or "not yet scored").
    """
    try:
        agent = _get_agent()
        info = {
            "did": agent.did,
            "public_key_hex": agent.public_key_hex,
            "is_registered": agent.is_registered,
            "is_verified": agent.is_verified,
        }
        # Try to get reputation
        try:
            rep = agent.get_reputation()
            info["reputation"] = rep
        except Exception:
            info["reputation"] = "not yet scored"
        return json.dumps(info, indent=2)
    except Exception as e:
        return _err(e)


# ============================================================
# ACTION-CONTROL TOOLS (require agent identity)
#
# These tools expose the AVP Runtime Gate / approval / receipt workflow as an
# explicit MCP toolbox. They do not proxy or intercept other MCP tool calls.
# They are registered only in local/full mode by `_register_write_tools()`.
# ============================================================

def runtime_evaluate_action(
    action: Annotated[str, Field(description="Action name to evaluate. Examples: deploy.release, infra.volume.delete, payment.transfer")],
    resource: Annotated[str, Field(description="Target resource identifier. Examples: service:checkout, volume:vol-123, account:vendor-7")],
    environment: Annotated[str, Field(description="Execution environment. Examples: development, staging, production")],
    delegation_receipt: Annotated[str, Field(description="DelegationReceipt JSON object string issued by the workflow owner/principal")],
    amount: Annotated[Optional[float], Field(description="Optional monetary amount for spend-sensitive actions. Omit when not applicable")] = None,
    currency: Annotated[str, Field(description="Optional ISO currency code for spend-sensitive actions. Example: USD")] = "",
) -> str:
    """Evaluate one proposed action with AVP Runtime Gate.

    Returns the Runtime Gate decision payload from AVP. The decision is expected
    to be one of ALLOW, WAITING_FOR_HUMAN_APPROVAL, or BLOCK. This tool only
    evaluates the action; it does not execute anything and does not intercept
    other MCP tool calls.
    """
    try:
        agent = _get_agent()
        receipt = _parse_json_object(delegation_receipt, "delegation_receipt")
        result = agent.runtime_evaluate(
            action=action,
            resource=resource,
            environment=environment,
            delegation_receipt=receipt,
            amount=amount,
            currency=currency or None,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return _err(e)


def controlled_action(
    action: Annotated[str, Field(description="Action name to evaluate and execute only if Runtime Gate allows it")],
    resource: Annotated[str, Field(description="Target resource identifier bound into the Runtime Gate decision")],
    environment: Annotated[str, Field(description="Execution environment. Examples: development, staging, production")],
    delegation_receipt: Annotated[str, Field(description="DelegationReceipt JSON object string issued by the workflow owner/principal")],
    params: Annotated[str, Field(description="Optional execution params as a JSON object string. Default: {}")] = "{}",
    amount: Annotated[Optional[float], Field(description="Optional monetary amount for spend-sensitive actions. Omit when not applicable")] = None,
    currency: Annotated[str, Field(description="Optional ISO currency code for spend-sensitive actions. Example: USD")] = "",
    approval_expires_in_seconds: Annotated[int, Field(description="Approval TTL in seconds when Runtime Gate returns WAITING_FOR_HUMAN_APPROVAL")] = 3600,
) -> str:
    """Run the high-level AVP controlled-action flow.

    Returns `ControlledActionOutcome.to_dict()` as a JSON string. Possible
    statuses are `executed`, `approval_required`, and `blocked`. Human approval
    is never auto-approved; after approval, call `execute_after_approval`.
    """
    try:
        agent = _get_agent()
        receipt = _parse_json_object(delegation_receipt, "delegation_receipt")
        parsed_params = _parse_json_object(params, "params", default={})
        outcome = agent.controlled_action(
            action=action,
            resource=resource,
            environment=environment,
            delegation_receipt=receipt,
            params=parsed_params,
            amount=amount,
            currency=currency or None,
            approval_expires_in_seconds=approval_expires_in_seconds,
        )
        return json.dumps(outcome.to_dict(), indent=2)
    except Exception as e:
        return _err(e)


def get_approval_request(
    approval_id: Annotated[str, Field(description="Human approval request id returned as approval.approval_id")],
) -> str:
    """Fetch a human approval request visible to the local agent identity."""
    try:
        agent = _get_agent()
        result = agent.get_approval(approval_id)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _err(e)


def approve_action(
    approval_id: Annotated[str, Field(description="Human approval request id returned as approval.approval_id")],
) -> str:
    """Approve a pending human approval request and return signed receipt JCS plus sha256."""
    try:
        agent = _get_agent()
        receipt_jcs = agent.approve(approval_id)
        return _receipt_jcs_response("approval_receipt_jcs", receipt_jcs)
    except Exception as e:
        return _err(e)


def deny_action(
    approval_id: Annotated[str, Field(description="Human approval request id returned as approval.approval_id")],
    reason: Annotated[str, Field(description="Optional denial reason recorded with the signed denial receipt")] = "",
) -> str:
    """Deny a pending human approval request and return signed receipt JCS plus sha256."""
    try:
        agent = _get_agent()
        receipt_jcs = agent.deny(approval_id, reason=reason or None)
        return _receipt_jcs_response("denial_receipt_jcs", receipt_jcs)
    except Exception as e:
        return _err(e)


def execute_after_approval(
    audit_id: Annotated[str, Field(description="Runtime Gate audit_id from the WAITING_FOR_HUMAN_APPROVAL decision")],
    approval_id: Annotated[str, Field(description="Approved human approval id. Use approval.approval_id, not approval.id")],
    action: Annotated[str, Field(description="Action name bound to the Runtime Gate decision")],
    resource: Annotated[str, Field(description="Resource identifier bound to the Runtime Gate decision")],
    environment: Annotated[str, Field(description="Execution environment bound to the Runtime Gate decision")],
    params: Annotated[str, Field(description="Optional execution params as a JSON object string. Default: {}")] = "{}",
) -> str:
    """Resume a controlled action after principal approval.

    The approval payload key is `approval_id`. This tool deliberately passes
    that key through to `AVPAgent.execute_after_approval(...)`.
    """
    try:
        agent = _get_agent()
        parsed_params = _parse_json_object(params, "params", default={})
        outcome = agent.execute_after_approval(
            audit_id=audit_id,
            approval_id=approval_id,
            action=action,
            resource=resource,
            environment=environment,
            params=parsed_params,
        )
        return json.dumps(outcome.to_dict(), indent=2)
    except Exception as e:
        return _err(e)


def get_decision_receipt(
    audit_id: Annotated[str, Field(description="Runtime Gate audit_id whose signed DecisionReceipt should be fetched")],
) -> str:
    """Fetch exact signed DecisionReceipt JCS text and its sha256 digest."""
    try:
        agent = _get_agent()
        receipt_jcs = agent.get_decision_receipt(audit_id)
        return _receipt_jcs_response("decision_receipt_jcs", receipt_jcs)
    except Exception as e:
        return _err(e)


def get_execution_receipt(
    receipt_id: Annotated[str, Field(description="Execution receipt id whose signed ExecutionReceipt should be fetched")],
) -> str:
    """Fetch exact signed ExecutionReceipt JCS text and its sha256 digest."""
    try:
        agent = _get_agent()
        receipt_jcs = agent.get_execution_receipt(receipt_id)
        return _receipt_jcs_response("execution_receipt_jcs", receipt_jcs)
    except Exception as e:
        return _err(e)


# ============================================================
# RESOURCES
# ============================================================

@mcp.resource("avp://protocol/info")
def protocol_info() -> str:
    """Information about AgentVeil action-control and advisory MCP tools."""
    return json.dumps({
        "name": "Agent Veil Protocol (AVP)",
        "description": "Explicit action-control MCP toolbox, advisory reputation, audit verification, and signed evidence for AI agent systems",
        "api": f"{BASE_URL}/docs",
        "explorer": f"{BASE_URL}/live",       # Deprecated alias; kept for compatibility.
        "live_network": f"{BASE_URL}/live",
        "sdk": "pip install agentveil",
        "mcp": "pip install 'agentveil[mcp]'",
        "github": "https://github.com/agentveil-protocol/avp-sdk",
        "boundary": "Explicit MCP toolbox; does not automatically proxy or intercept other MCP tool calls.",
        "features": [
            "W3C DID Identity (Ed25519)",
            "Runtime Gate action decisions",
            "Human approval routing",
            "Approved execution resume",
            "Signed DecisionReceipt and ExecutionReceipt fetch",
            "Agent profile and reputation inspection",
            "Advisory reputation checks",
            "Offline-verifiable credentials",
            "Agent discovery via capability cards",
            "Audit trail verification",
            "Signed interaction attestations",
        ],
    }, indent=2)


# ============================================================
# CONDITIONAL LOCAL/FULL TOOL REGISTRATION
# ============================================================

def _register_write_tools() -> None:
    """Register the 12 local/full tools with the FastMCP server.

    Called only when NOT in readonly mode. In readonly mode these local/full
    functions above remain plain Python callables but are not reachable via
    the MCP protocol — they do not appear in tools/list.
    """
    mcp.add_tool(register_agent)
    mcp.add_tool(submit_attestation)
    mcp.add_tool(publish_agent_card)
    mcp.add_tool(get_my_agent_info)
    mcp.add_tool(runtime_evaluate_action)
    mcp.add_tool(controlled_action)
    mcp.add_tool(get_approval_request)
    mcp.add_tool(approve_action)
    mcp.add_tool(deny_action)
    mcp.add_tool(execute_after_approval)
    mcp.add_tool(get_decision_receipt)
    mcp.add_tool(get_execution_receipt)


if not IS_READONLY:
    _register_write_tools()
    log.info("local/full tools registered")
else:
    log.info("readonly mode: local/full tools not registered")


# ============================================================
# HOSTED-MODE HTTP TRANSPORT: auth middleware + health endpoint
# ============================================================

def _build_http_app(token: str):
    """Build the ASGI app used by `agentveil-mcp --http`.

    Returns the FastMCP streamable-http ASGI app (a Starlette instance with
    its session-manager lifespan already wired), with two additions:
      - a GET /healthz route (unauthenticated) returning {"status":"ok"}
      - a bearer-token middleware enforcing Authorization: Bearer <token>
        on every path except /healthz

    We attach the health route and middleware to the MCP app directly rather
    than wrapping it in a parent Starlette. Wrapping breaks FastMCP's
    streamable-http session manager because its task group is initialized by
    the app's own lifespan, which ASGI does not propagate to mounted children
    by default.

    The MCP transport route is at `/mcp` (FastMCP default, see
    `mcp.settings.streamable_http_path`). When fronted by Caddy with
    `handle_path /mcp/*`, Caddy strips the `/mcp` prefix and forwards to
    this server; we therefore accept the transport at both `/` and `/mcp`.
    In practice Caddy's `reverse_proxy` (instead of `handle_path`) is the
    cleaner composition and is documented in the agentveil_mcp README for
    the hosted deployment.

    Fail-closed: if `token` is empty, this function is never called (see main()).
    """
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route

    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    class BearerAuthMiddleware(BaseHTTPMiddleware):
        def __init__(self, app, *, expected_token: str):
            super().__init__(app)
            self._expected_token = expected_token

        async def dispatch(self, request: Request, call_next):
            # Whitelist the health route — docker healthcheck must not need a token.
            if request.url.path == "/healthz":
                return await call_next(request)
            header = request.headers.get("authorization", "")
            expected = f"Bearer {self._expected_token}"
            # Constant-time compare to resist timing oracles.
            import hmac
            if not hmac.compare_digest(header, expected):
                return JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return await call_next(request)

    # FastMCP returns a fully-wired Starlette app with its own lifespan that
    # initializes the session manager task group. Reuse it as our base.
    app = mcp.streamable_http_app()

    # Prepend the health route so it takes precedence over any MCP routes.
    app.router.routes.insert(0, Route("/healthz", healthz, methods=["GET"]))

    # Attach the bearer middleware. Starlette builds the middleware stack
    # lazily on first request, so adding to user_middleware here is fine
    # provided we do it before the app has served a request.
    app.user_middleware.insert(0, Middleware(BearerAuthMiddleware, expected_token=token))
    app.middleware_stack = app.build_middleware_stack()

    return app


# ============================================================
# RESOURCES
# ============================================================

# NOTE: protocol_info() is defined above; kept here as a section marker for readers.


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AVP MCP Server")
    parser.add_argument("--http", action="store_true", help="Use HTTP transport instead of stdio")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    args = parser.parse_args()

    if args.http:
        token = os.environ.get("AVP_MCP_TOKEN", "").strip()
        if not token:
            log.error(
                "AVP_MCP_TOKEN is empty but --http requires it. Refusing to start. "
                "Set AVP_MCP_TOKEN in the environment (e.g. via /opt/avp/.env.mcp) "
                "or run without --http for stdio transport."
            )
            raise SystemExit(2)

        app = _build_http_app(token)

        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
