"""
Claude MCP Server for Agent Veil Protocol.

Runs as an MCP (Model Context Protocol) server that Claude Desktop/Code
can connect to. The canonical `agentveil-mcp` server exposes AVP
action-control, reputation, identity, attestation, and audit tools.

Usage:
    agentveil-mcp

Config for claude_desktop_config.json:
    {
      "mcpServers": {
        "agentveil": {
          "command": "agentveil-mcp",
          "env": {
            "AVP_BASE_URL": "https://agentveil.dev",
            "AVP_AGENT_NAME": "claude_agent"
          }
        }
      }
    }
"""

from __future__ import annotations

import json
import logging
import os
import sys

from agentveil.agent import AVPAgent

log = logging.getLogger("agentveil.tools.claude_mcp")

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError(
        "mcp is required for AVP Claude MCP server. "
        "Install with: pip install 'agentveil[mcp]'"
    )

# Configuration from environment
AVP_BASE_URL = os.environ.get("AVP_BASE_URL", "https://agentveil.dev")
AVP_AGENT_NAME = os.environ.get("AVP_AGENT_NAME", "claude_agent")

# Agent cache
_agent: AVPAgent | None = None


def _get_agent() -> AVPAgent:
    """Get or create a cached AVPAgent instance."""
    global _agent
    if _agent is None:
        try:
            _agent = AVPAgent.load(AVP_BASE_URL, name=AVP_AGENT_NAME)
        except Exception:
            _agent = AVPAgent.create(AVP_BASE_URL, name=AVP_AGENT_NAME)
            _agent.register()
    return _agent


# --- MCP Server ---

mcp = FastMCP("agentveil")


@mcp.tool()
async def check_avp_reputation(did: str) -> str:
    """Look up an agent's trust score, confidence, and attestation count on AVP.

    Use BEFORE delegating work to verify the agent is reputable.
    NOT for logging interactions — use log_avp_interaction instead.
    NOT for delegation decisions — use should_delegate_to_agent instead.

    Returns JSON with score (0.0-1.0), confidence (0.0-1.0),
    interpretation (untrusted/newcomer/basic/trusted/elite),
    and total_attestations count.

    No API key required. Read-only, no side effects.

    Args:
        did: Agent's decentralized identifier, e.g. 'did:key:z6Mk...'.
    """
    try:
        agent = _get_agent()
        rep = agent.get_reputation(did)
        return json.dumps({
            "did": did,
            "score": rep.get("score", 0.0),
            "confidence": rep.get("confidence", 0.0),
            "interpretation": rep.get("interpretation", "unknown"),
            "total_attestations": rep.get("total_attestations", 0),
        }, indent=2)
    except Exception as e:
        return f"Error checking reputation: {e}"


@mcp.tool()
async def should_delegate_to_agent(did: str, min_score: float = 0.5) -> str:
    """Get a yes/no delegation decision for an agent based on AVP reputation score and confidence.

    Use BEFORE handing off a task to another agent.
    NOT for just checking a score — use check_avp_reputation instead.

    Returns JSON with delegate (true/false), score, confidence,
    and a human-readable reason explaining the decision.
    Approves when score >= min_score AND confidence > 0.1.

    No API key required. Read-only, no side effects.

    Args:
        did: Agent's decentralized identifier, e.g. 'did:key:z6Mk...'.
        min_score: Minimum reputation score to approve (0.0-1.0, default 0.5). Higher values for sensitive tasks.
    """
    try:
        agent = _get_agent()
        rep = agent.get_reputation(did)
        score = rep.get("score", 0.0)
        confidence = rep.get("confidence", 0.0)
        interpretation = rep.get("interpretation", "unknown")

        should_delegate = score >= min_score and confidence > 0.1
        reason = (
            f"Score {score:.2f} >= {min_score:.2f} threshold, "
            f"confidence {confidence:.2f}, rated '{interpretation}'"
            if should_delegate
            else f"Score {score:.2f} < {min_score:.2f} threshold "
            f"or low confidence ({confidence:.2f})"
        )

        return json.dumps({
            "delegate": should_delegate,
            "did": did,
            "score": score,
            "confidence": confidence,
            "min_score": min_score,
            "reason": reason,
        }, indent=2)
    except Exception as e:
        return f"Error evaluating agent: {e}"


@mcp.tool()
async def log_avp_interaction(
    did: str, outcome: str = "positive", context: str = "claude_task"
) -> str:
    """Record a signed attestation about an agent you interacted with on AVP.

    Use AFTER completing a task with another agent to record the outcome.
    NOT for checking reputation — use check_avp_reputation instead.

    SIDE EFFECT: Creates an Ed25519-signed attestation stored on AVP.
    This permanently affects the target agent's reputation score.
    Positive attestations increase score, negative decrease it.

    Returns JSON with status, target DID, outcome, weight, and context.

    Requires agent registration (auto-created on first call).

    Args:
        did: Target agent's decentralized identifier, e.g. 'did:key:z6Mk...'.
        outcome: Result of the interaction: 'positive', 'negative', or 'neutral'.
        context: What the interaction was about, e.g. 'code_review', 'research', 'data_analysis'.
    """
    try:
        agent = _get_agent()
        result = agent.attest(
            to_did=did,
            outcome=outcome,
            weight=0.8,
            context=context,
        )
        return json.dumps({
            "status": "recorded",
            "to_did": did,
            "outcome": result.get("outcome", outcome),
            "weight": result.get("weight", 0.8),
            "context": context,
        }, indent=2)
    except Exception as e:
        return f"Error logging interaction: {e}"


@mcp.tool()
async def search_avp_agents(
    capability: str = "", provider: str = "", min_reputation: float = 0.0
) -> str:
    """Find agents registered on AVP, filtered by capability, provider, or minimum reputation.

    Use to discover available agents before delegating work.
    NOT for checking a specific agent's score — use check_avp_reputation instead.

    Returns JSON array of agents with DID, name, capabilities, provider,
    and reputation score. Currently indexes 8,000+ agents.

    No API key required. Read-only, no side effects.

    Args:
        capability: Filter by skill, e.g. 'code_review', 'research', 'data_analysis'. Empty string returns all.
        provider: Filter by LLM provider, e.g. 'anthropic', 'openai', 'google'. Empty string returns all.
        min_reputation: Only return agents with score >= this value (0.0-1.0, default 0.0).
    """
    try:
        agent = _get_agent()
        results = agent.search_agents(
            capability=capability or None,
            provider=provider or None,
            min_reputation=min_reputation or None,
        )
        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error searching agents: {e}"


def main():
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
