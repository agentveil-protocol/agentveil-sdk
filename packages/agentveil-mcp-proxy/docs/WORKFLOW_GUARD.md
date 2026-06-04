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

## T3 controlled runner and metadata event log

`WorkflowGuardRunner` in `workflow_guard_runner.py` wires the **controlled
wrapped-command path**:

1. T1 `WorkflowGuardClassifier.classify()`
2. T2 `WorkflowGuardPolicyEvaluator.evaluate()`
3. Injected `WorkflowCommandExecutor` runs **only** when decision is `allow`
4. Compact decision text (default) or full playbook/task text (`RunnerOutputMode.PLAYBOOK`)
5. Append one metadata-only JSONL event per run via `append_workflow_guard_event()`

### Library API (T3)

```python
runner = WorkflowGuardRunner()
result = runner.run(
    "git status --short --branch",
    context=WorkflowPolicyContext(role_profile=RoleProfile.REVIEWER),
    executor=my_executor,
    output_mode=RunnerOutputMode.COMPACT,
    event_sink="/tmp/workflow_guard_events.jsonl",
)
print(result.compact_message)
```

Default compact output:

```text
Decision: allow
Rule: reviewer_local_allow
Executed: true
```

Redirected runs add `Next: <playbook_id>` and do not execute.

### JSONL event fields

`timestamp`, `role_profile`, `command_family`, `action_type`, `disposition`,
`decision`, `policy_rule_id`, `target_hash`, `payload_hash`,
`redirect_playbook_id`, `executed`, and `executor_result_status` (allow path
only). Events omit raw shell, secrets, full paths, prompts, and executor output.

`executor_result_status` is normalized via `normalize_executor_status()` to a
small allowlisted label (`ok`, `failed`, `timeout`, `rejected`, `cancelled`, or
`unknown`). Hostile executor-provided status strings are normalized before event
write.

### Not Runtime Isolation

T3 is a **library runner** for wrapped commands. It is not CLI-registered yet,
not a kernel/sandbox, and not Approval Center or Runtime Gate integration.
**Raw shell outside the wrapper remains a bypass.**

### Intended future CLI shape (not implemented in T3)

```text
agentveil-mcp-proxy workflow-guard run --role reviewer -- <command...>
```

Future CLI would call `WorkflowGuardRunner` with a real executor adapter; T3
only defines the library contract and test `RecordingExecutor`.

## T4 controlled CLI, doctor, and smoke

`workflow_guard_cli.py` registers a top-level `workflow-guard` command on
`agentveil-mcp-proxy` with three subcommands:

```text
agentveil-mcp-proxy workflow-guard run --role reviewer [--execute] [--playbook] [--event-log PATH] -- <command...>
agentveil-mcp-proxy workflow-guard doctor [--home PATH] [--event-log PATH] [--json]
agentveil-mcp-proxy workflow-guard smoke [--home PATH] [--event-log PATH] [--json]
```

`scripts/workflow_guard_smoke.py` is a standalone entrypoint that calls the same
smoke scenarios (metadata-only, no real shell unless an external wrapper passes
`--execute` on `run`).

### Controlled run (default dry-run)

1. T1 classify → T2 policy
2. Print compact `Decision` / `Rule` / `Executed` / optional `Next` lines
3. Optionally append one metadata-only JSONL event when `--event-log` is set

Without `--execute`, policy may return `allow` but the CLI does **not** shell
out (`Executed: false`). With `--execute`, policy `allow` runs the command through
an injected subprocess executor inside `workflow_guard_cli.py` only.

Shell argv after `--` is rebuilt with `shlex.join()` (not plain `" ".join()`),
so arguments containing spaces round-trip into classification and subprocess
execution.

`workflow-guard smoke` and `scripts/workflow_guard_smoke.py` include a CLI
product-path check: `workflow-guard run --execute` with relative `touch` targets
checks that allowed paths reach a marker file, denied paths do not, and JSONL
events stay metadata-only.

With `--json`, nested product-path `run` output is suppressed so stdout is a single
parseable JSON document (no leading `Decision:` lines).

### Doctor

Validates T1/T2/T3 imports, role profiles, event-log writability, and a dry-run
allow path with metadata-only events.

### Smoke

Runs a built-in scenario matrix (reviewer allow/redirect, implementer test allow
with `RecordingExecutor`, secret surface, block candidate) and checks JSONL
event count plus privacy constraints.

### Bypass warning (T4)

CLI registration does **not** isolate the host shell. Commands started outside
`agentveil-mcp-proxy workflow-guard run` remain a bypass. T4 is the controlled
wrapped-command path, not a sandbox or Approval Center integration.
