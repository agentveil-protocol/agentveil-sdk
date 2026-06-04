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

## T2 role policy and redirect playbooks

`WorkflowGuardPolicyEvaluator` in `workflow_guard_policy.py` maps a T1
`WorkflowActionEnvelope` plus a `WorkflowPolicyContext` to a
`WorkflowPolicyResult`:

- **Role profiles:** `reviewer`, `implementer`, `ops`, `release`
- **Decisions:** `allow`, `approval_required`, `block`, `block_and_redirect`
- **Redirects:** `RedirectPlaybook` with compact, copy-ready `workflow_text`

Policy input is metadata/hash-first only (envelope fields and optional markers
such as `implementation_scope_allowed`, `release_approval_marker`,
`ops_infra_approved`). It does not store raw shell, prompts, secrets, file
contents, or command output.

### Role summary

| Profile | Local read/test | File mutation | Remote / push / release |
| --- | --- | --- | --- |
| reviewer | allow | redirect unless scoped | block_and_redirect |
| implementer | allow | allow | approval_required |
| ops | allow | redirect | allow infra class only when `ops_infra_approved` |
| release | allow | — | publish needs marker or approval |

T2 does not execute commands, wrap shells, or integrate with CLI, evidence,
Runtime Gate, or Approval Center. Ops **allow** is policy metadata only.

T1 `block_candidate` dispositions (for example pipeline-exec, injection, or empty
commands) map to `approval_required` or `block_and_redirect` with the dangerous-
action playbook, not a dead-end plain `block`.

## Bypass warning (T2)

Policy evaluation does not close the T1 bypass: unwrapped shell still runs
unless a future enforcement layer applies classifier + policy before execution.
