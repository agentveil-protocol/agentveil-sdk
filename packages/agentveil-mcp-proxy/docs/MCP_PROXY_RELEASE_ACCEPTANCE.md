# MCP Proxy Release Acceptance

This is the release-gate procedure for serious MCP Proxy changes, especially
changes touching CLI setup, passthrough behavior, approval UX, evidence, or
Runtime Gate integration. It is intentionally separate from the regular pytest
suite because it builds a wheel, installs it into a clean virtualenv, and talks
to the configured backend.

For the **onboarding stage** (smoke, `client-config print`, deny path, privacy scan, Approval
Center API when pending), use
[`MCP_PROXY_ONBOARDING_STAGE_GATE.md`](MCP_PROXY_ONBOARDING_STAGE_GATE.md).

Run this before tagging or publishing an MCP Proxy release:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_release_acceptance.py
```

Use an already-built wheel:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_release_acceptance.py \
  --wheel packages/agentveil-mcp-proxy/dist/agentveil_mcp_proxy-0.7.23-py3-none-any.whl
```

Keep artifacts for debugging:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_release_acceptance.py --keep-tmp
```

Fresh Ubuntu prerequisite:

```bash
sudo apt-get update
sudo apt-get install -y python3.12-venv python3-pip
```

## What It Verifies

The runner performs the public customer path from the installed wheel, not from
the source tree. It checks install, setup, backend registration when enabled,
MCP stdio startup, safe routed calls, one approval-required mutation, approval
retry, evidence export, and verification.

## Release Rule

For MCP Proxy releases, this procedure is a release gate. Do not publish a
release that changes MCP Proxy setup, passthrough, approval, evidence, or
Runtime Gate behavior unless this runner passes against the release candidate
wheel, or the release notes explicitly call out why the gate was skipped.

`--skip-backend` exists only for local debugging. A public MCP Proxy release
gate must not use it, because it does not verify `register` or
`doctor --check-backend`.

## Current Proof Boundary

This runner verifies local approval UX and local evidence proof export. It does
not require a backend-signed human approval receipt, because the current MCP
Proxy local approval surface does not produce that artifact. If a future release
adds backend Human Control receipts to this flow, extend this runner to require
the signed receipt count and field binding.
