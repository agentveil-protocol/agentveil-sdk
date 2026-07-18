# CI Policy

This repository uses tiered CI so day-to-day agent work stays fast while release quality remains unchanged.

## Gates

- Fast gate: runs on normal branch pushes. It uses Ubuntu and the primary Python version, and must run the full regular pytest suite.
- Compatibility gate: runs on pull requests to `main`, manual dispatch, and release tags. It uses the full supported OS/Python matrix.
- Publish gate: package publication is allowed only after the compatibility gate has passed for the release candidate or tag.
- MCP Proxy release acceptance: for releases that change MCP Proxy setup,
  passthrough, approval UX, evidence, or Runtime Gate behavior, run
  `packages/agentveil-mcp-proxy/scripts/mcp_proxy_release_acceptance.py`
  against the release candidate wheel
  before tagging or publishing. See
  [`MCP_PROXY_RELEASE_ACCEPTANCE.md`](../packages/agentveil-mcp-proxy/docs/MCP_PROXY_RELEASE_ACCEPTANCE.md).

## Agent Rules

- Run the relevant local tests before pushing code changes.
- Do not treat the fast gate as release verification.
- Do not use `[skip ci]` for code, packaging, security, or behavior changes.
- Before reporting a change as done, state which local commands and which CI gates actually ran.
- Before tagging or publishing a release, verify that the compatibility gate passed.
- Before tagging or publishing an MCP Proxy release, verify that the MCP Proxy
  release acceptance runner passed, or state explicitly why that gate was
  skipped.

## Runtime Budgets And Hang Handling

- Focused suites should finish within 3 minutes. The full local public SDK gate
  has a 25-minute target budget.
- Release compatibility jobs use a hard 35-minute timeout. A timeout or a
  test step with no meaningful progress for 10 minutes is a CI `HOLD`; do not
  start a duplicate workflow while the original run is active.
- The SDK suite and MCP Proxy suite run once each with explicit test paths.
  Pytest reports the 50 slowest tests and emits a faulthandler thread dump after
  120 seconds so a stalled process has actionable diagnostics.
- Tests that launch an MCP Proxy or managed Approval Center subprocess must
  explicitly disable real browser and OS approval delivery in the child
  process. Parent-process monkeypatches are not subprocess isolation.
- Process tests must use bounded waits and clean up the child proxy and managed
  Approval Center even when an assertion fails.
- Before creating a recovery tag, run the publish workflow manually against the
  corrective branch or commit. Manual dispatch is compatibility-only; the
  publish job is restricted to tag refs.
- If a tag-triggered workflow exceeds its budget, first determine whether the
  publish job ran. Do not move or recreate the tag, rerun the same uncorrected
  workflow, or publish manually. Record `HOLD` and require explicit operator
  approval for cancellation and recovery.
