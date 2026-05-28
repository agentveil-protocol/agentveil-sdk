# CI Policy

This repository uses tiered CI so day-to-day agent work stays fast while release quality remains unchanged.

## Gates

- Fast gate: runs on normal branch pushes. It uses Ubuntu and the primary Python version, and must run the full regular pytest suite.
- Compatibility gate: runs on pull requests to `main`, manual dispatch, and release tags. It uses the full supported OS/Python matrix.
- Publish gate: package publication is allowed only after the compatibility gate has passed for the release candidate or tag.
- MCP Proxy release acceptance: for releases that change MCP Proxy setup,
  passthrough, approval UX, evidence, or Runtime Gate behavior, run
  `scripts/mcp_proxy_release_acceptance.py` against the release candidate wheel
  before tagging or publishing. See
  [`MCP_PROXY_RELEASE_ACCEPTANCE.md`](MCP_PROXY_RELEASE_ACCEPTANCE.md).

## Agent Rules

- Run the relevant local tests before pushing code changes.
- Do not treat the fast gate as release verification.
- Do not use `[skip ci]` for code, packaging, security, or behavior changes.
- Before reporting a change as done, state which local commands and which CI gates actually ran.
- Before tagging or publishing a release, verify that the compatibility gate passed.
- Before tagging or publishing an MCP Proxy release, verify that the MCP Proxy
  release acceptance runner passed, or state explicitly why that gate was
  skipped.
