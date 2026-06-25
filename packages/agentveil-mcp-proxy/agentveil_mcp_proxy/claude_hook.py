"""Claude Code PreToolUse hook adapter for AgentVeil MCP Proxy.

Productizes the P10D.11-C/C2 probe surface into a reusable module that maps
Claude Code `PreToolUse` hook payloads onto the existing AgentVeil policy
engine, returns Claude-compatible decision JSON, and writes bounded JSONL
evidence records.

Scope for S1:
- Decision plumbing only (deny/allow); no approval round-trip.
- No installer / `.claude/settings.json` writer; no CLI subcommand wiring.
- Reuses ``PolicyEngine`` / ``ToolCallContext`` / ``RiskClass`` /
  ``PolicyDecision`` from ``agentveil_mcp_proxy.policy``. There is no parallel
  decision engine here.
- Evidence rows are privacy-bounded: ``tool_input`` is reduced to a SHA-256
  digest of its JCS-canonicalized form plus a sorted list of its top-level
  key names. Raw prompt, file content, shell command bodies, tokens, and tool
  output are not copied into the evidence record.

Conservative fallback contract (spec clarification #2):
- Tool names that map to ``RiskClass.UNKNOWN`` are routed through the built-in
  policy's ``default_decision`` which is ``ASK_BACKEND``. With no backend
  available in S1, ``ASK_BACKEND`` maps to deny. This
  keeps unknown mutation-shaped tools from silently allowing.
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
from agentveil_mcp_proxy.policy import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
)


CLAUDE_SERVER_LABEL = "claude_code"
HOOK_EVENT_DEFAULT = "PreToolUse"

# MCP server name written by `agentveil-mcp-proxy connect <client>`. Tool calls
# routed to this server (``mcp__agentveil-mcp-proxy__*``) are the AgentVeil
# controlled route: they already pass through the proxy's own approval boundary.
# The PreToolUse hook must NOT double-block them — otherwise the redirect that
# tells the agent to "use the controlled MCP tool" dead-ends on the hook itself.
AGENTVEIL_CONTROLLED_MCP_SERVER = "agentveil-mcp-proxy"

# Generic agent-facing redirect appended to NATIVE-tool deny reasons (S2
# corrective). This is static instruction text only: no approval round-trip
# (S3), no auto-transformation of Write into an MCP call, and no private
# playbook content. It tells the agent to re-route the same intent through a
# controlled AgentVeil MCP tool when one is available.
# claim-check: allow "blocked" is literal hook-deny user-facing text; tested in
# tests/test_mcp_proxy_claude_hook.py native redirect assertions.
NATIVE_REDIRECT_INSTRUCTION = (
    "Direct native tool use was blocked before mutation. "  # claim-check: allow literal hook-deny text tested below.
    "Use an AgentVeil controlled MCP tool for the same operation when available, "
    "preserving the same path, content, and intent. "
    "If approval is required, ask the user to approve and then retry the controlled tool call."
)


# Claude Code built-in tool names and their natural risk class. Bash is
# special-cased at runtime because its input determines mutation vs read.
_CLAUDE_BUILTIN_RISK: Mapping[str, RiskClass] = {
    "Write": RiskClass.WRITE,
    "Edit": RiskClass.WRITE,
    "MultiEdit": RiskClass.WRITE,
    "NotebookEdit": RiskClass.WRITE,
    "Read": RiskClass.READ,
    "LS": RiskClass.READ,
    "Glob": RiskClass.READ,
    "Grep": RiskClass.READ,
    "WebSearch": RiskClass.READ,
    "WebFetch": RiskClass.READ,
}

# Shell classifier uses a deny fallback: default-deny with a small allowlist of
# unambiguously read-only commands. Denylist heuristics catch obvious
# mutation shapes for telemetry (WRITE/DESTRUCTIVE risk_class), but ANYTHING
# not on the allowlist falls through to UNKNOWN -> ASK_BACKEND -> deny.
#
# Rationale: arbitrary interpreters (python3 -c, node -e, perl -e) and
# arbitrary subprocesses can write to the filesystem without matching any
# specific token pattern. Token-based denylists fail open on these; an
# allowlist of read-only commands denies unknown commands. The corrective fix for
# P10D.14 S1 reverses the original token-denylist design.

_SHELL_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "rm ",
    "rmdir ",
    "unlink ",
    "shred ",
    "wipe ",
    " -delete",  # `find ... -delete`
)

_SHELL_MUTATION_TOKENS: tuple[str, ...] = (
    " > ",
    " >> ",
    " >|",
    " tee ",
    "mv ",
    "cp ",
    "mkdir ",
    "touch ",
    "chmod ",
    "chown ",
    " ln ",
    "curl -o",
    "wget -O",
    " dd ",
    " -exec",   # `find -exec`, `xargs -I {} -exec`
    " -i ",     # `sed -i`, `perl -i`
    " -pi",     # `perl -pi`
)

# Single-token executables that are unambiguously read-only when invoked
# without mutation operators (caught above by destructive/mutation tokens).
_BASH_READONLY_FIRST_TOKEN: frozenset[str] = frozenset({
    "pwd",
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "wc",
    "which",
    "whoami",
    "date",
    "echo",
    "true",
    "false",
})

# Git subcommands that are read-only. Anything else (checkout, reset, clean,
# push, pull, commit, add, merge, rebase, ...) falls through to UNKNOWN.
_BASH_GIT_READONLY_SUBCOMMANDS: frozenset[str] = frozenset({
    "status",
    "diff",
})

# Shell composition / metacharacters. Presence of ANY of these means the
# command is not a simple single read-only invocation: it can command-
# substitute, pipe, chain, background, or redirect into a mutation while the
# first token still looks read-only (e.g. ``echo $(python3 -c "...")``).
#
# Corrective-2 finding: a first-token allowlist is insufficient; an attacker
# can hide a write inside a substitution/pipe/chain. Any composition token =>
# deny fallback (UNKNOWN -> deny), regardless of the first token.
_SHELL_COMPOSITION_PATTERNS: tuple[str, ...] = (
    "$(",   # command substitution
    "`",    # backtick command substitution
    "|",    # pipe (also covers ||)
    ";",    # command separator
    "&",    # background and && chaining
    ">",    # any output redirect (>, >>, >|, >( )
    "<(",   # process substitution (executes the inner command)
    "\n",   # embedded newline => multiple commands
    "\r",
)


def _has_shell_composition(command: str) -> bool:
    """Return True if the command contains shell composition metacharacters."""
    return any(pattern in command for pattern in _SHELL_COMPOSITION_PATTERNS)


def _classify_bash(command: str) -> RiskClass:
    """Classify a Bash command. Unknown by default.

    Order of evaluation:
    1. Destructive tokens (rm, rmdir, find -delete) -> DESTRUCTIVE.
    2. Mutation tokens (redirects with spaces, sed -i, find -exec, ...) -> WRITE.
    3. Shell composition metacharacters ($(), backtick, |, ;, &, >, <(, newline)
       -> UNKNOWN. A composed command is not simple enough to allowlist.
    4. First-token allowlist (ls, cat, grep, ...) on a simple command -> READ.
    5. `git <subcommand>` with subcommand in the read-only subset -> READ.
    6. Anything else -> UNKNOWN (the policy then routes to ASK_BACKEND, which
       the hook maps to deny in S1).

    Composition (step 3) is checked BEFORE the allowlist (steps 4-5) so a
    read-looking first token does not carry a hidden mutation through.
    """
    lowered = command.lower().strip()
    if not lowered:
        return RiskClass.UNKNOWN

    if any(tok in lowered for tok in _SHELL_DESTRUCTIVE_TOKENS):
        return RiskClass.DESTRUCTIVE
    if any(tok in lowered for tok in _SHELL_MUTATION_TOKENS):
        return RiskClass.WRITE

    # Composition guard: nothing past this point may reach the READ allowlist
    # unless it is a single, simple command.
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


def _split_mcp_tool_name(tool_name: str) -> tuple[str, str] | None:
    """Return ``(server, tool_suffix)`` for ``mcp__server__tool`` or ``None``."""
    if not tool_name.startswith("mcp__"):
        return None
    parts = tool_name.split("__", 2)
    if len(parts) < 3 or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def classify_claude_tool(
    tool_name: str,
    tool_input: Mapping[str, Any] | None = None,
) -> RiskClass:
    """Classify a Claude tool call into a ``RiskClass``.

    The classifier maps tool metadata into the engine's risk vocabulary. It
    does NOT make the deny/allow decision; that responsibility belongs to the
    policy engine (spec clarification: no parallel decision engine here).
    """

    if tool_name in _CLAUDE_BUILTIN_RISK:
        return _CLAUDE_BUILTIN_RISK[tool_name]
    if tool_name == "Bash":
        command = ""
        if isinstance(tool_input, Mapping):
            command = str(tool_input.get("command") or "")
        return _classify_bash(command)
    mcp_split = _split_mcp_tool_name(tool_name)
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
    """Build a ``ToolCallContext`` from a Claude PreToolUse payload."""
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}

    risk = classify_claude_tool(tool_name, tool_input)

    mcp_split = _split_mcp_tool_name(tool_name)
    if mcp_split is not None:
        server, tool_suffix = mcp_split
        action_family = infer_action_family(tool_suffix)
    else:
        server = CLAUDE_SERVER_LABEL
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
    """Built-in protect-mode policy for S1.

    Rules are minimal and risk-class driven:
    - read           -> allow
    - write          -> approval (treated as deny in S1; no approval surface)
    - production     -> approval  # claim-check: allow "production" is RiskClass vocabulary.
    - destructive    -> block
    - financial      -> block

    Anything else (UNKNOWN) falls through to ``default_decision=ASK_BACKEND``
    which the hook maps to deny in S1 (spec clarification #2).
    """
    return PolicyConfig.from_dict({
        "id": "claude_hook_s1_default",
        "policy_schema_version": 1,
        "default_decision": "ask_backend",
        "default_risk_class": "unknown",
        "rules": [
            {
                "id": "claude-hook-read-allow",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {"risk_class": ["read"]},
            },
            {
                "id": "claude-hook-write-approval",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "write",
                "match": {"risk_class": ["write"]},
            },
            {
                "id": "claude-hook-prod-risk-approval",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "production",  # claim-check: allow "production" is RiskClass vocabulary.
                "match": {"risk_class": ["production"]},  # claim-check: allow "production" is RiskClass vocabulary.
            },
            {
                "id": "claude-hook-destructive-block",
                "source": "builtin",
                "decision": "block",
                "risk_class": "destructive",
                "match": {"risk_class": ["destructive"]},
            },
            {
                "id": "claude-hook-financial-block",
                "source": "builtin",
                "decision": "block",
                "risk_class": "financial",
                "match": {"risk_class": ["financial"]},
            },
        ],
    })


def default_proxy_config_for_hook() -> ProxyConfig:
    """Minimal ProxyConfig wrapping the hook default policy."""
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "claude-hook",
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
            "id": "claude_hook_s1_default",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {
                    "id": "claude-hook-read-allow",
                    "source": "builtin",
                    "decision": "allow",
                    "risk_class": "read",
                    "match": {"risk_class": ["read"]},
                },
                {
                    "id": "claude-hook-write-approval",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "write",
                    "match": {"risk_class": ["write"]},
                },
                {
                    "id": "claude-hook-prod-risk-approval",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "production",  # claim-check: allow "production" is RiskClass vocabulary.
                    "match": {"risk_class": ["production"]},  # claim-check: allow "production" is RiskClass vocabulary.
                },
                {
                    "id": "claude-hook-destructive-block",
                    "source": "builtin",
                    "decision": "block",
                    "risk_class": "destructive",
                    "match": {"risk_class": ["destructive"]},
                },
                {
                    "id": "claude-hook-financial-block",
                    "source": "builtin",
                    "decision": "block",
                    "risk_class": "financial",
                    "match": {"risk_class": ["financial"]},
                },
            ],
        },
    })


@dataclass(frozen=True)
class HookDecision:
    """Result of one PreToolUse evaluation."""

    hook_action: str  # "allow" or "deny"
    reason_code: str
    context: ToolCallContext
    evaluation: PolicyEvaluation


_FAIL_CLOSED_DECISIONS = frozenset({
    PolicyDecision.BLOCK,
    PolicyDecision.APPROVAL,
    PolicyDecision.ASK_BACKEND,
})


def _reason_code(evaluation: PolicyEvaluation, hook_action: str) -> str:
    if hook_action == "deny":
        if evaluation.decision is PolicyDecision.BLOCK:
            return "risky_blocked"
        if evaluation.decision is PolicyDecision.APPROVAL:
            # S1 has no approval surface; approval-required becomes deny.
            return "risky_blocked"
        if evaluation.decision is PolicyDecision.ASK_BACKEND:
            # Conservative fallback when no backend exists.
            return "risky_blocked"
        return "risky_blocked"
    return "allowed"


def decide(payload: Mapping[str, Any], engine: PolicyEngine) -> HookDecision:
    """Evaluate one PreToolUse payload and return the hook decision."""
    context = build_tool_call_context(payload)
    evaluation = engine.evaluate(context)

    # Controlled-route pass-through: calls to the AgentVeil proxy's own MCP
    # tools self-govern at the proxy's approval boundary. The hook allows them
    # through (instead of denying write-shaped MCP tools on this controlled route) so the redirect
    # to "use the controlled MCP tool" is reachable. The proxy, not the hook,
    # then applies approval/redirect/evidence to these calls.
    if context.server == AGENTVEIL_CONTROLLED_MCP_SERVER:
        return HookDecision(
            hook_action="allow",
            reason_code="controlled_route_passthrough",
            context=context,
            evaluation=evaluation,
        )

    if evaluation.decision in (PolicyDecision.ALLOW, PolicyDecision.OBSERVE):
        hook_action = "allow"
    elif evaluation.decision in _FAIL_CLOSED_DECISIONS:
        hook_action = "deny"
    else:
        # Defensive: any decision we don't recognize fails closed.
        hook_action = "deny"
    return HookDecision(
        hook_action=hook_action,
        reason_code=_reason_code(evaluation, hook_action),
        context=context,
        evaluation=evaluation,
    )


def format_hook_output(decision: HookDecision) -> str | None:
    """Format Claude-compatible PreToolUse JSON, or ``None`` to allow silently.

    For native Claude tools (Write/Edit/MultiEdit/NotebookEdit/Bash), the deny
    reason carries a generic redirect instruction so the message is actionable
    for the agent, not just "denied". MCP tool denies keep the bounded base
    reason (the redirect-to-MCP instruction does not apply to an MCP call).
    """
    if decision.hook_action == "allow":
        return None
    reason = (
        f"agentveil: denied {decision.context.tool} "
        f"(risk_class={decision.evaluation.risk_class.value}, "
        f"policy_decision={decision.evaluation.decision.value}, "
        f"reason_code={decision.reason_code}); target_reached=false"
    )
    if decision.context.server == CLAUDE_SERVER_LABEL:
        reason = f"{reason}. {NATIVE_REDIRECT_INSTRUCTION}"
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT_DEFAULT,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def _bounded_input_ref(tool_input: Any) -> dict[str, Any]:
    """Privacy-bounded reference: SHA-256 prefix of canonical input + key names.

    The full raw tool_input is not returned from this function; only the hash prefix
    and the sorted list of top-level keys are returned. This is the explicit
    contract that test_evidence_bounded asserts via sentinel value injection.
    """
    if not isinstance(tool_input, Mapping):
        keys: list[str] = []
        canonical = json.dumps({"_non_dict": True}, separators=(",", ":"))
    else:
        keys = sorted(str(k) for k in tool_input.keys())
        canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "input_hash": f"sha256:{digest[:16]}",
        "input_keys": keys,
    }


def _bounded_cwd_ref(cwd: str) -> str:
    """Privacy-bounded reference for the workspace cwd.

    Raw cwd is a customer workspace path and must not appear verbatim in
    evidence (corrective finding: P10D.14 S1 review). Returns a SHA-256
    digest prefix so audit trails can still compare same-cwd sessions
    without leaking the path.
    """
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
    """Build a bounded JSONL evidence record.

    Privacy contract (corrective S1 review, sentinel-tested):
    - No raw ``tool_input`` values copied (only ``input_hash`` + ``input_keys``).
    - No raw prompt, file content, shell command body, tokens, or tool output.
    - No raw workspace ``cwd``; recorded as ``cwd_digest`` (SHA-256 prefix).
    - ``tool_name``, ``session_id``, and derived fields (server/tool/risk_class)
      are recorded as standard policy metadata.
    """
    timestamp = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    tool_input = payload.get("tool_input")
    record: dict[str, Any] = {
        "ts": timestamp,
        "session_id": str(payload.get("session_id") or ""),
        "cwd_digest": _bounded_cwd_ref(str(payload.get("cwd") or "")),
        "hook_event_name": str(payload.get("hook_event_name") or HOOK_EVENT_DEFAULT),
        "tool_name": str(payload.get("tool_name") or ""),
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
        "input_ref": _bounded_input_ref(tool_input),
    }
    return record


def write_evidence(record: Mapping[str, Any], evidence_path: Path) -> None:
    """Append one bounded record as a JSONL line."""
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
    """Process one PreToolUse payload end-to-end.

    Returns the ``HookDecision`` so callers (and tests) can inspect the
    structured outcome. Side effects:
    - Appends a bounded evidence record to ``evidence_path`` when provided.
    - Writes Claude-compatible deny JSON to ``out`` when the decision is deny.
    """
    config = config or default_proxy_config_for_hook()
    engine = PolicyEngine(config)
    decision = decide(payload, engine)
    if evidence_path is not None:
        record = build_evidence_record(payload, decision)
        write_evidence(record, evidence_path)
    output = format_hook_output(decision)
    if output is not None:
        if out is None:
            out = sys.stdout
        out.write(output + "\n")
    return decision


def main(argv: list[str] | None = None, *, stdin: Any = None, stdout: Any = None) -> int:
    """Hook runtime entrypoint, invoked by Claude Code as the PreToolUse command.

    Reads a PreToolUse payload from stdin, processes it, writes the
    hookSpecificOutput JSON (or nothing for allow) to stdout, and returns 0.

    Evidence path resolution order:
    1. ``--evidence-path <path>`` argument (set by the installed hook command).
    2. ``AGENTVEIL_HOOK_EVIDENCE_PATH`` environment variable.
    3. None (no evidence written).

    The ``--evidence-path`` argument is preferred because it is cross-platform
    (no shell ``VAR=x cmd`` prefix needed) and is what S2's installer writes
    into the project ``.claude/settings.json`` hook command.
    """
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="agentveil-claude-hook", add_help=True)
    parser.add_argument("--evidence-path", default=None)
    args = parser.parse_args(argv if argv is not None else [])

    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    try:
        payload = json.load(in_stream)
    except Exception as exc:  # noqa: BLE001 - external input
        sys.stderr.write(f"claude_hook: invalid PreToolUse JSON: {exc}\n")
        return 1
    if not isinstance(payload, Mapping):
        sys.stderr.write("claude_hook: PreToolUse payload must be a JSON object\n")
        return 1

    evidence_arg = args.evidence_path or os.environ.get("AGENTVEIL_HOOK_EVIDENCE_PATH")
    evidence_path = Path(evidence_arg) if evidence_arg else None
    process_hook(payload, evidence_path=evidence_path, out=out_stream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


__all__ = [
    "AGENTVEIL_CONTROLLED_MCP_SERVER",
    "CLAUDE_SERVER_LABEL",
    "HOOK_EVENT_DEFAULT",
    "NATIVE_REDIRECT_INSTRUCTION",
    "HookDecision",
    "build_evidence_record",
    "build_tool_call_context",
    "classify_claude_tool",
    "decide",
    "default_hook_policy",
    "default_proxy_config_for_hook",
    "format_hook_output",
    "main",
    "process_hook",
    "write_evidence",
]
