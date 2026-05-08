"""
Claude MCP + Agent Veil Protocol — E2E example.

Shows how to run AVP as an MCP server that Claude Desktop/Code connects to,
giving Claude access to Runtime Gate, approvals, signed receipts, reputation,
identity lookup, attestation, audit, and agent search tools. This example
demonstrates the advisory/reputation operations; see `agentveil_mcp/README.md`
for the full action-control tool list.

Prerequisites:
    pip install 'agentveil[mcp]'

Usage:
    # 1. Run the MCP server (Claude connects via stdio):
    agentveil-mcp

    # 2. Or test the tools directly without Claude:
    python examples/claude_mcp_example.py

Setup for Claude Desktop:
    Add to ~/Library/Application Support/Claude/claude_desktop_config.json:

    {
      "mcpServers": {
        "agentveil": {
          "command": "agentveil-mcp",
          "env": {
            "AVP_BASE_URL": "https://agentveil.dev",
            "AVP_AGENT_NAME": "my_claude_agent"
          }
        }
      }
    }

Setup for Claude Code:
    Add to .claude/settings.json or use `claude mcp add`:

    claude mcp add agentveil -- agentveil-mcp
"""

from agentveil import AVPAgent

AVP_URL = "https://agentveil.dev"


def main():
    # === Step 1: Register two agents to demonstrate interaction ===
    print("=== Registering agents on AVP ===")

    agent_a = AVPAgent.create(AVP_URL, name="claude_agent_a")
    agent_a.register(display_name="Claude Agent A")
    agent_a.publish_card(capabilities=["research", "analysis"], provider="anthropic")

    agent_b = AVPAgent.create(AVP_URL, name="claude_agent_b")
    agent_b.register(display_name="Claude Agent B")
    agent_b.publish_card(capabilities=["writing", "code_review"], provider="anthropic")

    print(f"  Agent A DID: {agent_a.did[:40]}...")
    print(f"  Agent B DID: {agent_b.did[:40]}...")

    # === Step 2: Demonstrate what the MCP tools do ===
    # These are the same operations that Claude calls via MCP tools.

    # Tool 1: check_avp_reputation
    print("\n=== check_avp_reputation ===")
    rep = agent_a.get_reputation(agent_b.did)
    print(f"  Agent B reputation: score={rep['score']:.3f}, confidence={rep['confidence']:.3f}")
    print(f"  Interpretation: {rep.get('interpretation', 'unknown')}")

    # Tool 2: should_delegate_to_agent
    print("\n=== should_delegate_to_agent ===")
    score = rep.get("score", 0.0)
    confidence = rep.get("confidence", 0.0)
    should_delegate = score >= 0.3 and confidence > 0.1
    print(f"  Score {score:.2f} vs threshold 0.30 → {'APPROVE' if should_delegate else 'REJECT'}")

    # Tool 3: log_avp_interaction
    print("\n=== log_avp_interaction ===")
    att = agent_a.attest(to_did=agent_b.did, outcome="positive", weight=0.8, context="claude_task")
    print(f"  Attestation recorded: outcome={att.get('outcome', 'positive')}")

    # Tool 4: search_avp_agents
    print("\n=== search_avp_agents ===")
    results = agent_a.search_agents(capability="research")
    count = len(results) if isinstance(results, list) else 0
    print(f"  Found {count} agents with 'research' capability")

    # === Step 3: Verify reputation updated ===
    print("\n=== Updated reputation ===")
    rep_after = agent_a.get_reputation(agent_b.did)
    print(f"  Agent B: score={rep_after['score']:.3f}, confidence={rep_after['confidence']:.3f}")

    # === Step 4: Show Claude usage examples ===
    print("\n=== Example Claude prompts (after MCP setup) ===")
    print(f'  "Check the reputation of {agent_b.did[:30]}..."')
    print(f'  "Should I delegate code review to {agent_b.did[:30]}...?"')
    print('  "Search for agents that can do research"')
    print(f'  "Log a positive interaction with {agent_b.did[:30]}..."')

    print("\n=== Done ===")
    print("\nTo use with Claude, run:  agentveil-mcp")


if __name__ == "__main__":
    main()
