# Framework SDK Examples

AVP works with any Python code. The examples in this document show how popular
agent frameworks can call AgentVeil SDK tools explicitly.

These examples are not the same as AgentVeil project connectors. A project
connector, such as the Cursor or Claude Code connector in `agentveil-mcp-proxy`,
installs a configured action-control boundary with hooks, routed MCP approval,
redirects, and bounded evidence. The framework examples below add AgentVeil
tools to an agent workflow; they do not automatically intercept framework-side
actions or claim project-control coverage by themselves.

Use these examples when you want an agent to call AgentVeil primitives directly.
Use a project connector or routed MCP proxy when you need AgentVeil to control
configured side-effect paths.

## CrewAI

```bash
pip install agentveil crewai
```

```python
from agentveil.tools.crewai import AVPReputationTool, AVPDelegationTool, AVPAttestationTool

agent = Agent(
    role="Researcher",
    tools=[AVPReputationTool(), AVPDelegationTool(), AVPAttestationTool()],
)
```

Full example: [`examples/crewai_example.py`](../examples/crewai_example.py)

## LangGraph

```bash
pip install agentveil langchain-core langgraph
```

```python
from agentveil.tools.langgraph import avp_check_reputation, avp_should_delegate, avp_log_interaction
from langgraph.prebuilt import ToolNode

tool_node = ToolNode([avp_check_reputation, avp_should_delegate, avp_log_interaction])
```

Full example: [`examples/langgraph_example.py`](../examples/langgraph_example.py)

## AutoGen

```bash
pip install agentveil autogen-core
```

```python
from agentveil.tools.autogen import avp_reputation_tools

agent = AssistantAgent(name="researcher", tools=avp_reputation_tools())
```

Full example: [`examples/autogen_example.py`](../examples/autogen_example.py)

## Claude (MCP Server)

`agentveil-mcp` exposes Runtime Gate, approval, signed receipt, reputation,
identity lookup, attestation, and audit workflows to MCP clients. Hosted
read-only deployments expose public inspection tools only.

```bash
pip install 'agentveil[mcp]'
```

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentveil": {
      "command": "agentveil-mcp"
    }
  }
}
```

Full example: [`examples/claude_mcp_example.py`](../examples/claude_mcp_example.py)

## OpenAI

```bash
pip install agentveil openai
```

```python
from agentveil.tools.openai import avp_tool_definitions, handle_avp_tool_call

response = client.chat.completions.create(
    model="gpt-4", messages=messages, tools=avp_tool_definitions()
)
result = handle_avp_tool_call(tool_call.function.name, args)
```

Full example: [`examples/openai_example.py`](../examples/openai_example.py)

## Paperclip

```bash
pip install agentveil
```

```python
from agentveil.tools.paperclip import configure, avp_should_delegate, avp_evaluate_team

configure(base_url="https://agentveil.dev", agent_name="paperclip_ceo")
avp_should_delegate(did="did:key:z6Mk...", min_score=0.5)
avp_evaluate_team(dids=["did:key:z6Mk1...", "did:key:z6Mk2..."])
```

Full example: [`examples/paperclip_example.py`](../examples/paperclip_example.py)

For the runtime MCP proxy integration with Paperclip-managed Claude and Codex agents, see [`PAPERCLIP_INTEGRATION.md`](./PAPERCLIP_INTEGRATION.md).

## Hermes (Nous Research)

AVP integrates with [Hermes Agent](https://github.com/NousResearch/hermes-agent) via MCP + agentskills.io skill.

**Option 1: MCP server**

```json
{
  "mcpServers": {
    "avp": {
      "command": "agentveil-mcp",
      "env": { "AVP_BASE_URL": "https://agentveil.dev" }
    }
  }
}
```

**Option 2: Skill**

```bash
cp -r skills/avp-trust-enforcement ~/.hermes/skills/
```

Skill file: [`skills/avp-trust-enforcement/SKILL.md`](../skills/avp-trust-enforcement/SKILL.md)

## Any Python

No extra dependencies — use `@avp_tracked` decorator or `AVPAgent` directly.

```python
from agentveil import avp_tracked

@avp_tracked("https://agentveil.dev", name="my_agent", to_did="did:key:z6Mk...")
def my_function(data):
    return result
```

## Compatibility

AVP works alongside any identity provider — OAuth, API keys, custom identity solutions. Same DID standard, complementary trust layers.
