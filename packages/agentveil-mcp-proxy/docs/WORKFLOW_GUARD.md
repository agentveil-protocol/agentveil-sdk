# Workflow Guard (T1 classifier)

T1 adds a **local, metadata-only** shell command classifier for agent action
workflow guard work. It does not execute commands, wrap shells, enforce policy,
write evidence, or integrate with Runtime Gate, Approval Center, or MCP Proxy
approval semantics.

## Action envelope

`WorkflowGuardClassifier.classify()` returns a `WorkflowActionEnvelope` with:

- `role` and `adapter` (caller-provided context)
- `command_family` (git, ssh, package manager, deploy, etc.)
- `action_type` (local read, local test, file mutation, git push, …)
- `disposition` (`allow`, `approval_candidate`, `block_candidate`)
- `redacted_target_label` (category label, not a raw path)
- `target_hash` and `payload_hash` (SHA-256 prefixed digests)
- `risk_hints` (short hint tokens)

Raw shell text is **not** stored on the envelope by default. Path-like and
remote targets are canonicalized to placeholders before hashing.

## Parsing model

- Deterministic tokenization via `shlex` (no subprocess, no shell expansion).
- Simple pipe splitting for multi-segment commands; the highest-risk segment wins.
- Secret-path detection aligns with MCP Proxy secret-path segment/filename rules.
- Secret **basenames in cwd** (for example `.pypirc`, `id_rsa`) are detected even
  without `/`, `./`, `~`, or absolute prefixes.
- `env` and `printenv` are **credential-surface** commands (block candidate), not
  local read/allow, because they can dump raw environment secrets.

## Bypass warning

**Raw shell remains a bypass** unless commands are routed through a wrapper or
restricted runtime that invokes this classifier (or a successor enforcement
layer) before execution. T1 classifies only; it does not block, approve, or log
to the evidence database.

## Non-goals (T1)

- No command execution or subprocess-based parsing.
- No prompts/chats inspection.
- No changes to existing approval, policy, evidence, or Runtime Gate behavior.
