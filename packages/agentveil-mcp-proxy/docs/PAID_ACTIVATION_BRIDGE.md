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

## Durable files

Under `{AVP_HOME:-~/.avp}/paid/`:

| File | Role |
|------|------|
| `activation.json` | Bounded activation status (`active` / missing / expired / revoked / …) |
| `install.json` | Bounded installed provider bridge (`provider_id=private_v1`, package name/version) |

Private Runtime Gate B1/B2/B3 reads these filenames/shapes for zero-config
enablement. Both must be `active` for paid enablement; otherwise Core fallback.

## Backend resolution (safer default)

When `AVP_PAID_API_BASE_URL` is unset or blank, the CLI does **not** open a
network backend. Activate then persists public-fallback / provider-absent
state. A packaged default host (`https://agentveil.dev`) is deferred until
Product Guard accepts live endpoint proof.

For local/integration proof, set `AVP_PAID_API_BASE_URL` or inject an
in-process backend client (tests).

## Privacy

Persisted files and CLI output must not include:

- raw license keys
- entitlement / install tokens
- backend URLs or presigned URLs
- artifact internals / host absolute paths
- private rule graphs

## Core fallback compatibility

| Durable state | Expected private outcome |
|---|---|
| active + compatible Builder install | paid enabled (`private_v1`) |
| expired / revoked / disabled | Core fallback |
| missing activation or install | Core fallback |
| malformed JSON | Core fallback |
| package name/version mismatch | Core fallback at private selection |

Public `paid status` must not promote terminal inactive activation statuses
(`expired` / `revoked` / `disabled` / `invalid` / `error`) back to `active`
just because `install.json` is still active.
