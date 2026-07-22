"""Cursor hook adapter for AgentVeil MCP Proxy (public one-command setup).

Maps Cursor ``preToolUse``, ``beforeShellExecution``, and ``beforeMCPExecution``
payloads onto the existing policy engine and returns Cursor-compatible decision
JSON. Evidence rows are privacy-bounded.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, MutableMapping

from agentveil_mcp_proxy.classification import infer_action_family, infer_risk_class
from agentveil_mcp_proxy.client_guidance import (
    NATIVE_CONTROLLED_MCP_REDIRECT_INSTRUCTION as NATIVE_REDIRECT_INSTRUCTION,
    NativeRedirectOrigin,
    format_native_redirect_agent_surface,
    maybe_register_native_redirect_for_hook_deny,
)
from agentveil_mcp_proxy.policy import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
)

CURSOR_SERVER_LABEL = "cursor"
AGENTVEIL_CONTROLLED_MCP_SERVER = "agentveil-mcp-proxy"
AGENTVEIL_MCP_SERVER_KEY = AGENTVEIL_CONTROLLED_MCP_SERVER

_MCP_READ_TOOLS = frozenset({
    "list_workspace",
    "read_file",
    "get_file_info",
    "instruction_surface_status",
})

_CURSOR_BUILTIN_RISK: Mapping[str, RiskClass] = {
    "Write": RiskClass.WRITE,
    "Edit": RiskClass.WRITE,
    "StrReplace": RiskClass.WRITE,
    "ApplyPatch": RiskClass.WRITE,
    "Delete": RiskClass.DESTRUCTIVE,
    "Shell": RiskClass.UNKNOWN,
    "Read": RiskClass.READ,
}

_SHELL_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "rm ",
    "rmdir ",
    "unlink ",
    "shred ",
    " -delete",
)

_SHELL_MUTATION_TOKENS: tuple[str, ...] = (
    " > ",
    " >> ",
    " tee ",
    "mv ",
    "cp ",
    "mkdir ",
    "touch ",
    "chmod ",
    "chown ",
    "curl -o",
    "wget -O",
    " -exec",
    " -i ",
    " -pi",
)

_BASH_READONLY_FIRST_TOKEN: frozenset[str] = frozenset({
    "pwd", "ls", "cat", "head", "tail", "grep", "find", "wc", "which",
    "whoami", "date", "echo", "true", "false",
})

_BASH_GIT_READONLY_SUBCOMMANDS: frozenset[str] = frozenset({"status", "diff"})

_SHELL_COMPOSITION_PATTERNS: tuple[str, ...] = (
    "$(", "`", "|", ";", "&", ">", "<(", "\n", "\r",
)


def is_mcp_tool_name(tool_name: str) -> bool:
    name = tool_name.strip()
    return name.upper().startswith("MCP:") or (":" in name and name.split(":", 1)[0].strip() == AGENTVEIL_MCP_SERVER_KEY)


def normalize_mcp_tool_name(tool_name: str) -> str:
    name = tool_name.strip()
    if name.upper().startswith("MCP:"):
        return name.split(":", 1)[1].strip()
    if ":" in name:
        _prefix, tool = name.split(":", 1)
        return tool.strip()
    return name


def normalize_hook_payload(
    payload: Mapping[str, Any],
    *,
    hook_event_hint: str | None = None,
) -> dict[str, Any]:
    normalized = dict(payload)
    if hook_event_hint:
        normalized["hook_event"] = hook_event_hint
    if "hook_event" not in normalized:
        if "command" in normalized:
            normalized["hook_event"] = "beforeShellExecution"
        elif "tool_input" in normalized and "tool_name" in normalized:
            tool_name = str(normalized.get("tool_name") or "")
            if tool_name in {"Shell", "Read", "Write", "Grep", "Delete", "StrReplace", "ApplyPatch", "Edit"}:
                normalized["hook_event"] = "preToolUse"
                normalized.setdefault("tool_class", tool_name)
            else:
                normalized["hook_event"] = "beforeMCPExecution"
                normalized.setdefault("tool_class", tool_name)
        elif "arguments" in normalized and "tool_name" in normalized:
            normalized["hook_event"] = "beforeMCPExecution"
            normalized.setdefault("tool_class", normalized["tool_name"])
    return normalized


def _has_shell_composition(command: str) -> bool:
    return any(pattern in command for pattern in _SHELL_COMPOSITION_PATTERNS)


def _classify_bash(command: str) -> RiskClass:
    lowered = command.lower().strip()
    if not lowered:
        return RiskClass.UNKNOWN
    if any(tok in lowered for tok in _SHELL_DESTRUCTIVE_TOKENS):
        return RiskClass.DESTRUCTIVE
    if any(tok in lowered for tok in _SHELL_MUTATION_TOKENS):
        return RiskClass.WRITE
    if _has_shell_composition(lowered):
        return RiskClass.UNKNOWN
    tokens = lowered.split()
    if not tokens:
        return RiskClass.UNKNOWN
    first = tokens[0]
    if first == "git":
        if len(tokens) >= 2 and tokens[1] in _BASH_GIT_READONLY_SUBCOMMANDS:
            return RiskClass.READ
        return RiskClass.UNKNOWN
    if first in _BASH_READONLY_FIRST_TOKEN:
        return RiskClass.READ
    return RiskClass.UNKNOWN


def classify_cursor_tool(
    tool_name: str,
    tool_input: Mapping[str, Any] | None = None,
    *,
    hook_event: str,
    command: str = "",
) -> RiskClass:
    if hook_event == "beforeShellExecution":
        return _classify_bash(command)
    if hook_event == "beforeMCPExecution" or is_mcp_tool_name(tool_name):
        normalized = normalize_mcp_tool_name(tool_name)
        if normalized in _MCP_READ_TOOLS:
            return RiskClass.READ
        arguments = tool_input if isinstance(tool_input, Mapping) else None
        return infer_risk_class(
            action=tool_name,
            tool=normalized,
            resource=None,
            arguments=arguments,
        )
    if tool_name in _CURSOR_BUILTIN_RISK:
        risk = _CURSOR_BUILTIN_RISK[tool_name]
        if tool_name == "Shell":
            cmd = ""
            if isinstance(tool_input, Mapping):
                cmd = str(tool_input.get("command") or "")
            return _classify_bash(cmd)
        return risk
    return RiskClass.UNKNOWN


def build_tool_call_context(payload: Mapping[str, Any]) -> ToolCallContext:
    hook_event = str(payload.get("hook_event") or "")
    tool_name = str(payload.get("tool_name") or payload.get("tool_class") or "")
    tool_input = payload.get("tool_input") or payload.get("arguments") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    command = str(payload.get("command") or tool_input.get("command") or "")

    risk = classify_cursor_tool(
        tool_name,
        tool_input,
        hook_event=hook_event,
        command=command,
    )
    if hook_event == "beforeMCPExecution" or is_mcp_tool_name(tool_name):
        tool_suffix = normalize_mcp_tool_name(tool_name)
        server = AGENTVEIL_CONTROLLED_MCP_SERVER
        action_family = infer_action_family(tool_suffix)
    else:
        server = CURSOR_SERVER_LABEL
        tool_suffix = tool_name or "unknown"
        action_family = infer_action_family(tool_suffix)

    return ToolCallContext(
        server=server,
        tool=tool_suffix,
        action=f"{server}.{tool_suffix}",
        risk_class=risk,
        action_family=action_family,
    )


def default_hook_policy() -> PolicyConfig:
    return PolicyConfig.from_dict({
        "id": "cursor_hook_default",
        "policy_schema_version": 1,
        "default_decision": "ask_backend",
        "default_risk_class": "unknown",
        "rules": [
            {"id": "cursor-read-allow", "source": "builtin", "decision": "allow",
             "risk_class": "read", "match": {"risk_class": ["read"]}},
            {"id": "cursor-write-approval", "source": "builtin", "decision": "approval",
             "risk_class": "write", "match": {"risk_class": ["write"]}},
            {"id": "cursor-destructive-block", "source": "builtin", "decision": "block",
             "risk_class": "destructive", "match": {"risk_class": ["destructive"]}},
        ],
    })


def default_proxy_config_for_hook() -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "cursor-hook",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "approval": {"approval_timeout_seconds": 300, "on_timeout": "deny", "ui_open_mode": "none"},
        "policy": {
            "id": "cursor_hook_default",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {"id": "cursor-read-allow", "source": "builtin", "decision": "allow",
                 "risk_class": "read", "match": {"risk_class": ["read"]}},
                {"id": "cursor-write-approval", "source": "builtin", "decision": "approval",
                 "risk_class": "write", "match": {"risk_class": ["write"]}},
                {"id": "cursor-destructive-block", "source": "builtin", "decision": "block",
                 "risk_class": "destructive", "match": {"risk_class": ["destructive"]}},
            ],
        },
    })


@dataclass(frozen=True)
class HookDecision:
    hook_action: str
    reason_code: str
    context: ToolCallContext
    evaluation: PolicyEvaluation


_FAIL_CLOSED = frozenset({
    PolicyDecision.BLOCK,
    PolicyDecision.APPROVAL,
    PolicyDecision.ASK_BACKEND,
})


def _load_workspace_mcp_servers(workspace: Path) -> dict[str, Any]:
    path = workspace / ".cursor" / "mcp.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    return servers if isinstance(servers, dict) else {}


def _is_agentveil_mcp_routed(payload: Mapping[str, Any], workspace: Path) -> bool:
    servers = _load_workspace_mcp_servers(workspace)
    agentveil_keys = {
        key for key, entry in servers.items()
        if key == AGENTVEIL_MCP_SERVER_KEY or "agentveil" in json.dumps(entry).lower()
    }
    if not agentveil_keys:
        return False
    raw_tool = str(payload.get("tool_name") or payload.get("tool_class") or "")
    if ":" in raw_tool and not raw_tool.upper().startswith("MCP:"):
        prefix = raw_tool.split(":", 1)[0].strip()
        return prefix in agentveil_keys
    if len(servers) == 1 and next(iter(servers)) in agentveil_keys:
        return True
    return False


def decide(payload: Mapping[str, Any], engine: PolicyEngine, *, workspace: Path) -> HookDecision:
    context = build_tool_call_context(payload)
    evaluation = engine.evaluate(context)
    hook_event = str(payload.get("hook_event") or "")

    if hook_event == "beforeMCPExecution" or is_mcp_tool_name(str(payload.get("tool_name") or payload.get("tool_class") or "")):
        tool = normalize_mcp_tool_name(context.tool)
        if tool in _MCP_READ_TOOLS:
            return HookDecision("allow", "mcp_read_allow", context, evaluation)
        if _is_agentveil_mcp_routed(payload, workspace):
            return HookDecision("allow", "controlled_route_passthrough", context, evaluation)

    if context.server == AGENTVEIL_CONTROLLED_MCP_SERVER:
        return HookDecision("allow", "controlled_route_passthrough", context, evaluation)

    if evaluation.decision in (PolicyDecision.ALLOW, PolicyDecision.OBSERVE):
        return HookDecision("allow", "allowed", context, evaluation)
    if evaluation.decision in _FAIL_CLOSED:
        return HookDecision("deny", "risky_blocked", context, evaluation)
    return HookDecision("deny", "risky_blocked", context, evaluation)


def format_cursor_hook_response(
    decision: HookDecision,
    *,
    redirect_origin: NativeRedirectOrigin | None = None,
) -> dict[str, Any]:
    if decision.hook_action == "allow":
        return {"permission": "allow"}
    agent_message = NATIVE_REDIRECT_INSTRUCTION
    if decision.context.server != CURSOR_SERVER_LABEL:
        agent_message = (
            f"agentveil: denied {decision.context.tool} "
            f"(reason_code={decision.reason_code}). "
            f"{NATIVE_REDIRECT_INSTRUCTION}"
        )
    response: dict[str, Any] = {
        "permission": "deny",
        "user_message": "AgentVeil denied this native action before it ran.",
        "agent_message": format_native_redirect_agent_surface(agent_message, redirect_origin),
    }
    return response


def _bounded_input_ref(tool_input: Any) -> dict[str, Any]:
    if not isinstance(tool_input, Mapping):
        keys: list[str] = []
        canonical = json.dumps({"_non_dict": True}, separators=(",", ":"))
    else:
        keys = sorted(str(k) for k in tool_input.keys())
        canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"input_hash": f"sha256:{digest[:16]}", "input_keys": keys}


def build_evidence_record(
    payload: Mapping[str, Any],
    decision: HookDecision,
    *,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    timestamp = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    tool_input = payload.get("tool_input") or payload.get("arguments")
    return {
        "ts": timestamp,
        "hook_event": str(payload.get("hook_event") or ""),
        "tool_name": str(payload.get("tool_name") or payload.get("tool_class") or ""),
        "server": decision.context.server,
        "tool": decision.context.tool,
        "risk_class": decision.evaluation.risk_class.value,
        "policy_decision": decision.evaluation.decision.value,
        "hook_action": decision.hook_action,
        "reason_code": decision.reason_code,
        "target_reached": False if decision.hook_action == "deny" else None,
        "input_ref": _bounded_input_ref(tool_input),
    }


def write_evidence(record: Mapping[str, Any], evidence_path: Path) -> None:
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with evidence_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


def process_hook(
    payload: Mapping[str, Any],
    *,
    workspace: Path,
    config: ProxyConfig | None = None,
    evidence_path: Path | None = None,
    home: Path | None = None,
    out: Any = None,
) -> HookDecision:
    config = config or default_proxy_config_for_hook()
    engine = PolicyEngine(config)
    decision = decide(payload, engine, workspace=workspace)
    if evidence_path is not None:
        write_evidence(build_evidence_record(payload, decision), evidence_path)
    tool_input = payload.get("tool_input") or payload.get("arguments") or {}
    redirect_origin = maybe_register_native_redirect_for_hook_deny(
        hook_action=decision.hook_action,
        native_server=decision.context.server,
        native_tool=decision.context.tool,
        action_family=decision.context.action_family or "",
        risk_class=decision.evaluation.risk_class.value,
        tool_input=tool_input if isinstance(tool_input, Mapping) else {},
        home=home,
    )
    response = format_cursor_hook_response(decision, redirect_origin=redirect_origin)
    if out is None:
        out = sys.stdout
    out.write(json.dumps(response) + "\n")
    return decision


def main(argv: list[str] | None = None, *, stdin: Any = None, stdout: Any = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="agentveil-cursor-hook", add_help=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--home", default=None)
    parser.add_argument("--evidence-path", default=None)
    parser.add_argument("--hook-event", default=None)
    args = parser.parse_args(argv if argv is not None else [])

    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    try:
        payload = json.load(in_stream)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cursor_hooks: invalid hook JSON: {exc}\n")
        return 1
    if not isinstance(payload, Mapping):
        sys.stderr.write("cursor_hooks: hook payload must be a JSON object\n")
        return 1

    hook_event = args.hook_event or payload.get("hook_event")
    normalized = normalize_hook_payload(payload, hook_event_hint=str(hook_event) if hook_event else None)
    workspace = Path(args.workspace).resolve()
    evidence_path = Path(args.evidence_path) if args.evidence_path else None
    home = Path(args.home).resolve() if args.home else None
    process_hook(
        normalized,
        workspace=workspace,
        evidence_path=evidence_path,
        home=home,
        out=out_stream,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
