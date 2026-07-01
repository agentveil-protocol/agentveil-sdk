"""Gemini CLI BeforeTool hook adapter for AgentVeil MCP Proxy.

Native Gemini mutators are denied before mutation with bounded redirect guidance;
AgentVeil-controlled MCP route calls pass through to the proxy approval boundary.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.classification import infer_action_family, infer_risk_class
from agentveil_mcp_proxy.claude_hook import (
    AGENTVEIL_CONTROLLED_MCP_SERVER,
    NATIVE_REDIRECT_INSTRUCTION,
    _bounded_input_ref,
    _classify_bash,
)
from agentveil_mcp_proxy.policy import (
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
)


GEMINI_SERVER_LABEL = "gemini_cli"
HOOK_EVENT_DEFAULT = "BeforeTool"
AGENTVEIL_CONTROLLED_MCP_SERVER_ALIASES = {
    AGENTVEIL_CONTROLLED_MCP_SERVER,
    AGENTVEIL_CONTROLLED_MCP_SERVER.replace("-", "_"),
}

_GEMINI_NATIVE_RISK: Mapping[str, RiskClass] = {
    "write_file": RiskClass.WRITE,
    "replace": RiskClass.WRITE,
    "read_file": RiskClass.READ,
    "read_many_files": RiskClass.READ,
    "list_directory": RiskClass.READ,
    "glob": RiskClass.READ,
    "grep_search": RiskClass.READ,
}


@dataclass(frozen=True)
class HookDecision:
    hook_action: str
    reason_code: str
    context: ToolCallContext
    evaluation: PolicyEvaluation


def _tool_name(payload: Mapping[str, Any]) -> str:
    for key in ("tool_name", "toolName", "tool", "name"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _tool_input(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("tool_input", "toolInput", "arguments", "input", "args"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _split_gemini_mcp_tool_name(tool_name: str) -> tuple[str, str] | None:
    """Return ``(server, tool_suffix)`` for ``mcp_<server>_<tool>`` or ``None``."""

    if not tool_name.startswith("mcp_"):
        return None
    rest = tool_name[4:]
    if not rest:
        return None
    for server in sorted(AGENTVEIL_CONTROLLED_MCP_SERVER_ALIASES, key=len, reverse=True):
        prefix = f"{server}_"
        if rest.startswith(prefix):
            return server, rest[len(prefix):]
    if "_" not in rest:
        return None
    server, tool_suffix = rest.split("_", 1)
    if not server or not tool_suffix:
        return None
    return server, tool_suffix


def classify_gemini_tool(tool_name: str, tool_input: Mapping[str, Any] | None = None) -> RiskClass:
    if tool_name == "run_shell_command":
        command = ""
        if isinstance(tool_input, Mapping):
            command = str(tool_input.get("command") or "")
        return _classify_bash(command)
    if tool_name in _GEMINI_NATIVE_RISK:
        return _GEMINI_NATIVE_RISK[tool_name]
    mcp_split = _split_gemini_mcp_tool_name(tool_name)
    if mcp_split is not None:
        _server, tool_suffix = mcp_split
        arguments = tool_input if isinstance(tool_input, Mapping) else None
        return infer_risk_class(
            action=tool_name,
            tool=tool_suffix,
            resource=None,
            arguments=arguments,
        )
    return RiskClass.UNKNOWN


def build_tool_call_context(payload: Mapping[str, Any]) -> ToolCallContext:
    tool_name = _tool_name(payload)
    tool_input = _tool_input(payload)
    risk = classify_gemini_tool(tool_name, tool_input)
    mcp_split = _split_gemini_mcp_tool_name(tool_name)
    if mcp_split is not None:
        server, tool_suffix = mcp_split
        action_family = infer_action_family(tool_suffix)
    else:
        server = GEMINI_SERVER_LABEL
        tool_suffix = tool_name or "unknown"
        action_family = infer_action_family(tool_suffix)
    return ToolCallContext(
        server=server,
        tool=tool_suffix,
        action=f"{server}.{tool_suffix}",
        risk_class=risk,
        action_family=action_family,
    )


def _is_agentveil_controlled_mcp_server(server: str) -> bool:
    return server in AGENTVEIL_CONTROLLED_MCP_SERVER_ALIASES


def default_proxy_config_for_hook() -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "gemini-hook",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "approval": {
            "approval_timeout_seconds": 300,
            "on_timeout": "deny",
            "ui_open_mode": "none",
        },
        "policy": {
            "id": "gemini_hook_default",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {
                    "id": "gemini-hook-read-allow",
                    "source": "builtin",
                    "decision": "allow",
                    "risk_class": "read",
                    "match": {"risk_class": ["read"]},
                },
                {
                    "id": "gemini-hook-write-approval",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "write",
                    "match": {"risk_class": ["write"]},
                },
                {
                    "id": "gemini-hook-prod-risk-approval",
                    "source": "builtin",
                    "decision": "approval",
                    # claim-check: allow policy risk enum value, not a production readiness claim.
                    "risk_class": "production",
                    "match": {"risk_class": ["production"]},  # claim-check: allow policy risk enum value.
                },
                {
                    "id": "gemini-hook-destructive-block",
                    "source": "builtin",
                    "decision": "block",
                    "risk_class": "destructive",
                    "match": {"risk_class": ["destructive"]},
                },
                {
                    "id": "gemini-hook-financial-block",
                    "source": "builtin",
                    "decision": "block",
                    "risk_class": "financial",
                    "match": {"risk_class": ["financial"]},
                },
            ],
        },
    })


def _reason_code(evaluation: PolicyEvaluation, hook_action: str) -> str:
    if hook_action == "allow":
        return "allowed"
    return "risky_blocked"


def decide(payload: Mapping[str, Any], engine: PolicyEngine) -> HookDecision:
    context = build_tool_call_context(payload)
    evaluation = engine.evaluate(context)
    if _is_agentveil_controlled_mcp_server(context.server):
        return HookDecision(
            hook_action="allow",
            reason_code="controlled_route_passthrough",
            context=context,
            evaluation=evaluation,
        )
    if evaluation.decision in (PolicyDecision.ALLOW, PolicyDecision.OBSERVE):
        hook_action = "allow"
    else:
        hook_action = "deny"
    return HookDecision(
        hook_action=hook_action,
        reason_code=_reason_code(evaluation, hook_action),
        context=context,
        evaluation=evaluation,
    )


def format_hook_output(decision: HookDecision) -> str | None:
    if decision.hook_action == "allow":
        return json.dumps({"decision": "allow"})
    reason = (
        f"agentveil: denied {decision.context.tool} "
        f"(risk_class={decision.evaluation.risk_class.value}, "
        f"policy_decision={decision.evaluation.decision.value}, "
        f"reason_code={decision.reason_code}); target_reached=false"
    )
    if decision.context.server == GEMINI_SERVER_LABEL:
        reason = f"{reason}. {NATIVE_REDIRECT_INSTRUCTION}"
    return json.dumps({"decision": "deny", "reason": reason})


def _bounded_cwd_ref(cwd: str) -> str:
    if not cwd:
        return "sha256:empty"
    digest = hashlib.sha256(cwd.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def build_evidence_record(
    payload: Mapping[str, Any],
    decision: HookDecision,
    *,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    timestamp = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    return {
        "ts": timestamp,
        "session_id": str(payload.get("session_id") or payload.get("sessionId") or ""),
        "cwd_digest": _bounded_cwd_ref(str(payload.get("cwd") or "")),
        "hook_event_name": str(
            payload.get("hook_event_name") or payload.get("hookEventName") or HOOK_EVENT_DEFAULT
        ),
        "tool_name": _tool_name(payload),
        "server": decision.context.server,
        "tool": decision.context.tool,
        "action_family": decision.context.action_family or "",
        "risk_class": decision.evaluation.risk_class.value,
        "policy_decision": decision.evaluation.decision.value,
        "hook_action": decision.hook_action,
        "reason_code": decision.reason_code,
        "policy_id": decision.evaluation.policy_id,
        "policy_rule_id": decision.evaluation.policy_rule_id,
        "matched_rule_ids": list(decision.evaluation.matched_rule_ids),
        "target_reached": False if decision.hook_action == "deny" else None,
        "input_ref": _bounded_input_ref(_tool_input(payload)),
    }


def write_evidence(record: Mapping[str, Any], evidence_path: Path) -> None:
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with evidence_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


def process_hook(
    payload: Mapping[str, Any],
    *,
    config: ProxyConfig | None = None,
    evidence_path: Path | None = None,
    out: Any = None,
) -> HookDecision:
    engine = PolicyEngine(config or default_proxy_config_for_hook())
    decision = decide(payload, engine)
    if evidence_path is not None:
        write_evidence(build_evidence_record(payload, decision), evidence_path)
    output = format_hook_output(decision)
    if output is not None:
        (out or sys.stdout).write(output + "\n")
    return decision


def main(argv: list[str] | None = None, *, stdin: Any = None, stdout: Any = None) -> int:
    parser = argparse.ArgumentParser(prog="agentveil-gemini-hook", add_help=True)
    parser.add_argument("--evidence-path", default=None)
    args = parser.parse_args(argv if argv is not None else [])
    in_stream = stdin if stdin is not None else sys.stdin
    try:
        payload = json.load(in_stream)
    except Exception as exc:  # noqa: BLE001 - external hook input
        sys.stderr.write(f"gemini_hook: invalid BeforeTool JSON: {exc}\n")
        return 1
    if not isinstance(payload, Mapping):
        sys.stderr.write("gemini_hook: BeforeTool payload must be a JSON object\n")
        return 1
    evidence_path = Path(args.evidence_path) if args.evidence_path else None
    process_hook(payload, evidence_path=evidence_path, out=stdout if stdout is not None else sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
