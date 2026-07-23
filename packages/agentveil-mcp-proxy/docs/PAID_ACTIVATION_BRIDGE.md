# Paid activation bridge (public MCP Proxy)

Status: public sender/durable-state bridge for private Runtime Gate zero-config
discovery. Boundary: public `agentveil-mcp-proxy` only. No private policy
packs, Approval Center UI, or hosted accounting internals.

## User path

```bash
agentveil-mcp-proxy paid activate --license-key-stdin
```

Optional later:

```bash
agentveil-mcp-proxy paid status
agentveil-mcp-proxy paid deactivate
```

No manual `provider_id`, `package_name`, `package_version`, artifact id,
entitlement JSON paste, or `private=true` is required for the normal path.

## Backend resolution (zero-config)

| `AVP_PAID_API_BASE_URL` | Behavior |
|-------------------------|----------|
| unset | Packaged default `https://agentveil.dev` |
| `""` (explicit blank) | Offline / no network (tests + local fallback) |
| non-empty URL | That base URL |

Successful activation through the backend writes both durable files below.
Unavailable/failed activation returns non-zero (or explicit unavailable
output) and omits `active` claims and paid-active-looking `install.json`.

## Durable files

Under `{AVP_HOME:-~/.avp}/paid/`:

| File | Role |
|------|------|
| `activation.json` | Bounded activation status (`active` / missing / expired / revoked / …) |
| `install.json` | Bounded installed provider bridge (`provider_id=private_v1`, package name/version) |

Private Runtime Gate B1/B2/B3 reads these filenames/shapes for zero-config
enablement. Both are `active` for paid enablement; otherwise Core fallback.

Cross-repo contract artifact (public + private consume this shape):

`tests/fixtures/paid_activation_public_contract.json`

Public tests validate outputs against that fixture. Private repo gates should
consume the same artifact; public tests do not import private code.

## Privacy

Persisted files and CLI output omit:

- raw license keys
- entitlement / install tokens
- backend URLs or presigned URLs
- artifact internals / host absolute paths
- private rule graphs

Malformed or unreadable on-disk JSON maps to Core fallback (bounded CLI /
status result, no Python traceback, no host path leak).

## Core fallback compatibility

| Durable state | Expected enablement |
|---|---|
| active + compatible Builder install | paid enabled (`private_v1`) |
| expired / revoked / disabled | Core fallback |
| missing activation or install | Core fallback |
| malformed JSON | Core fallback |
| package name/version mismatch | Core fallback at private selection |

Public `paid status` keeps terminal inactive activation statuses
(`expired` / `revoked` / `disabled` / `invalid` / `error`) back to `active`
when `install.json` is still active.
