# Downstream EOF Approval Retirement

## User impact

If a downstream MCP process closes stdout while an action waits for approval,
the pending approval is now retired instead of remaining actionable forever.
The stale action cannot be approved or forwarded after the route dies.

## Root cause

The stdout reader could observe EOF before `Popen.poll()` exposed the child exit
code. That branch marked the downstream unavailable but did not retire
generation-bound approvals. A waiting action could therefore remain pending
without another routed call to trigger process-exit latching.

## Correction

Unexpected stdout EOF now retires generation-bound approvals on the first
transport-closure observation, including the EOF-before-poll ordering. Repeated
EOF observation is idempotent. Expected EOF during proxy shutdown does not
change approval state.

## Compatibility

- The downstream error remains `downstream closed stdout`.
- Reconnect generation and fallback behavior are unchanged.
- No approval decision, evidence schema, public API, package, or workflow
  contract changes.

## Verification

- Deterministic EOF-before-poll regression.
- Idempotent repeated EOF proof.
- Expected-stop negative.
- Full route reconnect recovery suite, including stale-card `410`, zero old
  mutation, and exactly one mutation in the recovered generation.
