# AUD-2 R-B public release candidate (unreleased)

Status: dirty release-candidate source only. Not published, tagged, or merged.

Date: 2026-08-04
Branch: `codex/public-team-aud2-rb-bridge-release-v1`
Base: `924197dce6788a4eef0e67c5b3b5b0ad09b9f0a8`

## Reserved candidate versions (unreleased)

| Distribution | Version | Contents |
|---|---|---|
| `agentveil` | **0.7.23** | queryless AVP-Sig v2 opt-in (`force_v2=True`) |
| `agentveil-mcp-proxy` | **0.7.38** | generic installed-provider bridge + explicit `cryptography>=42.0.0` dependency closure |

MCP Proxy dependency floor: `agentveil>=0.7.23,<0.8`.

These versions are metadata reservations only. No PyPI publish, tag, or release
claim until the separate final public gate and operator approval.

## Stacked public ancestry

```text
origin/main
  └── a7615dd  generic installed-provider bridge
        └── 924197d  queryless AVP-Sig v2
              └── R-B release-candidate edits
```

Private RA2, Console dirty worktree, and R-C/R-D/R-E remain out of scope.

## Contract ownership

Single machine-readable handoff v1 owner:

`agentveil_mcp_proxy/contracts/installed_provider_activation_handoff_v1.json`

Runtime constants, tests, and docs must match this artifact. The test fixture
under `tests/fixtures/` is a parity check only, not a second owner.

## Dependency closure

After ordinary pip install of both built wheels in a clean Python 3.12
environment:

- `pynacl>=1.5.0` resolves via `agentveil`;
- `cryptography>=42.0.0` resolves via `agentveil-mcp-proxy`;
- module origins belong to the install environment, not the worktree;
- a product-neutral vendored hook may import both through the real activation
  flow;
- missing `cryptography` fails closed with no new active state.

Proof: `tests/test_mcp_proxy_paid_dependency_closure.py`.

## Explicit non-goals (this slice)

- commit, push, PR, merge, tag, publish, deploy;
- `public_sdk_pr_gate.sh` (reserved for final reviewed tip);
- runtime edits to `paid_install.py`, `paid_provider.py`, or `auth.py`;
- Console Slice 8, T7, R-C, R-D, R-E, or private implementation;
- claiming AUD-2 closed, Checkpoint B PASS, or package availability.

## Verification (developer)

Focused pytest (worktree `PYTHONPATH=.:packages/agentveil-mcp-proxy`):

```bash
pytest -q -rs \
  tests/test_auth.py tests/test_mcp_packaging.py \
  packages/agentveil-mcp-proxy/tests/test_proxy_packaging.py \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_paid_install.py \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_paid_activation_bridge.py \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_installed_provider_activation_handoff.py \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_paid_dependency_closure.py
```

Plus changed-file Ruff, JSON parse, `git diff --check`, slice worktree guard,
and a temporary staged commit-gate probe followed by exact-file unstage.
