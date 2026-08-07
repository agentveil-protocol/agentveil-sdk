# Installed-provider activation handoff (public MCP Proxy)

Status: product-neutral exact-installed-wheel activation hook for paid
activation. Boundary: public `agentveil-mcp-proxy` only. No Team semantics,
Approval Center changes, or durable public schema expansion.

## When it runs

The hosted paid backend may return `provider_handoff_required: true` on
activation validation. When true, and only after the existing backend flow has
validated the credential, issued entitlement, passed install safety, authorized <!-- claim-check: allow bounded prerequisite sequence verified by focused negative tests. -->
the artifact, verified hash/size/name/version/archive safety, and extracted the <!-- claim-check: allow bounded artifact checks verified by focused adversarial tests. -->
exact authorized wheel into `{AVP_HOME}/paid/vendor/`, the public layer:

1. discovers one compatible hook from that wheel's vendored `.dist-info` only;
2. invokes it once with a bounded in-memory request;
3. validates the bounded response;
4. only then writes `install.json` and allows `activation.json` to become
   `active`.

When `provider_handoff_required` is absent or `false`, the legacy Builder path
is unchanged and the hook is never discovered, imported, or invoked. <!-- claim-check: allow legacy false-path boundary verified by regression tests. -->

## Hook packaging contract

| Field | Value |
|-------|-------|
| Protocol | `installed_provider_activation_handoff` |
| Contract version | `1` |
| Entry-point group | `agentveil_mcp_proxy.installed_provider_activation_handoffs` |
| Entry-point name | `v1` |
| Target shape | `package.module:callable` |

The hook callable receives an
`InstalledProviderActivationHandoffRequest` with only:

- contract version
- raw activation credential (secret, in-memory only)
- stable non-reversible activation reference derived from the credential
- server-returned plan family (metadata only)
- exact verified package name and version
- exact provider id from the authorized artifact flow
- resolved AVP home for private state placement

The hook response is closed-by-default and may include only:

- contract version
- completion status (`active` or `error`)
- public fallback availability
- safe summary <!-- claim-check: allow bounded response-field vocabulary, not a universal safety claim. -->
- bounded error code

## Privacy

The public layer must not persist, log, echo, or return the raw activation
credential. Secret-bearing request objects redact the credential in `repr` and
`str`. Errors must not contain credential fragments, backend URLs, presigned
URLs, or private module names.

## Canonical contract artifact

Installed package data (single public owner):

`agentveil_mcp_proxy/contracts/installed_provider_activation_handoff_v1.json`

The artifact locks request/response key sets, nullable `plan_family` semantics,
credential/home bounds, status semantics, error codes, limits, and deny-only
privacy scan metadata (`privacy.deny_only_metadata=true`).

Test fixture (must match canonical exactly):

`tests/fixtures/paid_installed_provider_activation_handoff_contract.json`

Public tests validate the full claim-bearing contract object and adversarial
mutations against the installed canonical artifact.

## Failure behavior

Missing, multiple, malformed, incompatible, or wrong-distribution hooks fail
closed with bounded error codes and write no new active public state. A failed
replacement attempt must not destroy a previously valid activation/install pair.

Package update alone does not invoke a hook; only explicit activation with the
server-required signal may do so.
