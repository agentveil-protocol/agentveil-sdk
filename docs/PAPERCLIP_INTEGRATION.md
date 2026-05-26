# AgentVeil for Paperclip — Operator Guide

This guide describes how to use AgentVeil with Paperclip as of the
AgentVeil SDK source version that includes the Paperclip helper
commands described below. Older published `agentveil` releases may not
yet contain those helpers; check the `agentveil-paperclip` console
script availability after installation. The guide is written for
operators who already run Paperclip and who want to add runtime
controls around MCP-routed tool calls. It is not a substitute for
either project's primary documentation.

---

## Overview

Paperclip orchestrates agent work — companies, tasks, approvals, budgets,
governance, and the heartbeat loop that drives agent runtimes such as
Claude Code and Codex. AgentVeil contributes a runtime control layer that
sits on the MCP-stdio transport between an agent runtime and its
downstream tools.

Positioning: **Paperclip manages agent work. AgentVeil helps control and
prove risky actions.**

The two products meet at one seam. When an agent runtime that supports
MCP-stdio is configured to launch AgentVeil as the wrapper for a
downstream MCP server, AgentVeil observes every tool call that traverses
that MCP boundary and applies its runtime decision and evidence policies
before the call reaches the downstream server. The integration uses each
runtime's documented MCP configuration mechanism; no special partnership
or upstream support is implied or required.

The companion `paperclip-plugin-avp` is a separate, Paperclip-facing
plugin that contributes advisory reputation and delegation signals into
Paperclip workflows. It does not embed the runtime gate; that gate lives
in the external AgentVeil proxy. This guide treats those two surfaces as
distinct.

---

## Integration Boundary

There are three pieces and they do different jobs:

- **Paperclip** — orchestrates the agent. Owns task assignment, heartbeat
  scheduling, budget tracking, approvals, audit log, and rollback. These
  capabilities continue to live in Paperclip and are not displaced by
  this integration.
- **AgentVeil proxy** — sits on the MCP-stdio path between an agent
  runtime and a downstream MCP server. Applies runtime decisions and
  records evidence for the MCP-routed calls it sees. This is the runtime
  control surface and it lives in the external AgentVeil package, not
  inside the Paperclip plugin.
- **`paperclip-plugin-avp`** — a Paperclip plugin that contributes
  advisory signals into Paperclip workflows. Useful for delegation
  decisions and reputation reads inside Paperclip-native flows. It is
  advisory; it does not enforce runtime controls.

Coverage applies only to **MCP-routed downstream tools**. Tool calls that
do not traverse the MCP boundary are outside this integration's scope —
see the next section for the explicit list.

---

## What Is Covered Today

- **Local Claude runtime path** with the corresponding Paperclip adapter:
  validated internally end-to-end against a real adapter invocation and
  a representative downstream MCP server.
- **Local Codex runtime path** with the corresponding Paperclip adapter:
  validated internally end-to-end with valid runtime credentials and a
  supported model, against a representative downstream MCP server.
- **`paperclip-plugin-avp`** advisory surface inside Paperclip workflows.
- The AgentVeil proxy as the MCP wrapper for any downstream MCP server
  the operator chooses to gate.

Internal validation here means: the integration was exercised end-to-end
in a local environment, the downstream MCP server received the expected
tool call through the AgentVeil proxy, and the agent runtime received
the response. It does not mean a cloud-sandbox provider has been
validated live; see "What Is Not Covered Today" below.

---

## What Is Not Covered Today

The integration does not, and this guide does not claim that it does:

- Intercept built-in tools provided directly by an agent runtime
  (file edit, shell, search, and similar in-runtime tools that do not
  traverse MCP). Operators who need controls over those tool surfaces
  should use the runtime's own permission mechanism, Paperclip's
  approval gates, or sandbox-level controls.
- Cover Paperclip adapters that do not speak MCP-stdio (HTTP webhook
  agents, shell-process adapters, the OpenClaw gateway, and similar).
- Gate every Paperclip action automatically. Paperclip's own
  governance, budgets, and approval workflow remain the source of truth
  for non-MCP action paths.
- Live-provider proof on a specific cloud sandbox runtime. A documented
  setup pattern exists for cloud sandboxes (see below), but a publicly-
  claimed live end-to-end proof on any specific cloud provider is a
  next-milestone item, not a current claim.
- Coverage of Cloudflare-bridge sandbox environments.
- Replacement of Paperclip's governance, approvals, budgets, audit log,
  or rollback. Those continue to live in Paperclip.

---

## Local Setup Shape (High Level)

For a local Paperclip deployment that already runs Claude or Codex:

1. Install the AgentVeil package in the same environment that will run
   the agent. The package ships the AgentVeil proxy as a published
   console entry point; consult AgentVeil's own documentation for the
   exact installation step.
2. Initialize and validate the proxy using its own bootstrap commands.
   Configure the proxy to wrap the downstream MCP server you want to
   gate.
3. Configure the agent runtime's MCP layer to launch AgentVeil as the
   MCP wrapper instead of pointing directly at the downstream server.
   Both Claude Code and Codex provide their own MCP configuration
   mechanisms; the AgentVeil documentation references the public
   configuration entry points each runtime expects.
4. Keep every secret used by the runtime, the proxy, or the downstream
   server in operator-managed secret storage. Do not commit secrets into
   workspace files or repository-checked configuration.

Operational note: cold start of the proxy plus the downstream server
takes a few seconds the first time per heartbeat. If your agent prompt
or task template is short-lived enough to race that window, include
language in the prompt that tolerates a brief retry while the MCP layer
finishes coming up. This is a generic MCP-stdio behavior, not specific
to AgentVeil.

### Read-only local helpers

The AgentVeil SDK source includes two read-only helper commands for
sanity-checking your local environment before you wire anything up by
hand. Use an `agentveil` package release that includes these helpers,
or install from an updated source tree that contains them; the
currently published PyPI release may not yet ship them. The two
commands are:

- `agentveil paperclip doctor` reports whether the AgentVeil proxy,
  the local Claude runtime, and the local Codex runtime are
  discoverable on this machine, and whether their MCP configuration
  files are present at the documented locations. It reports paths
  only — it never reads the contents of any configuration or
  credential file.
- `agentveil paperclip init --dry-run` previews the setup steps that
  would need to happen for each integration surface (proxy, local
  Claude, local Codex, sandbox / remote, Paperclip plugin). Each
  step is described as a "would" action and explicitly marked as
  requiring manual review. Running `init` without `--dry-run` is
  refused; the helper does not implement a mutating init flow today.

Both commands are strictly read-only. Neither writes to Claude,
Codex, or Paperclip configuration files; neither creates any proxy
state; neither calls the AgentVeil backend or any agent runtime.
Their output uses path-level disclosure only — never file contents,
secrets, or proxy policy internals.

Both commands report sandbox / remote as **not verified by this
local doctor or dry-run**. That boundary is intentional: the helpers
inspect the local machine only. Sandbox-side coverage continues to
require the AgentVeil proxy to be installed inside the sandbox
runtime environment, as described in the next section.

---

## Sandbox / Remote Setup Shape (High Level)

For Paperclip configurations that route agent execution through a cloud
sandbox or a remote SSH host:

- **Sandbox image must include the AgentVeil proxy.** Publish a custom
  sandbox image that has the AgentVeil package installed and the proxy
  reachable on the runtime's standard binary path. Point your sandbox
  provider configuration at that image. This is the recommended path
  because it keeps proxy installation out of the per-heartbeat critical
  path.
- **MCP configuration travels with the workspace and the runtime home.**
  Paperclip's existing workspace and runtime-asset synchronization is
  what carries your MCP configuration into the sandbox; no additional
  Paperclip work is required for the carry itself. The single new
  operator-side requirement is that the proxy binary is reachable
  inside the sandbox.
- **SSH remote targets require operator pre-provisioning.** Install
  both the agent runtime and the AgentVeil proxy on the SSH host
  before pointing Paperclip at it. The same workspace and runtime
  carry mechanics then apply.
- **Live single-provider proof is a next milestone, not a current
  claim.** This guide describes the setup pattern; it does not assert
  that any specific cloud sandbox provider has been validated live
  end-to-end.
- **Cloudflare-bridge sandboxes are not covered by this version of the
  guide.** Their bridge runtime model is outside the documented
  custom-image path; an operator on Cloudflare-bridge should expect a
  separate coverage track.

---

## Evidence and Identity

The integration produces signed evidence for the MCP-routed tool calls
it observes. Where that evidence lives depends on where the proxy runs:

- **Local and SSH paths:** the proxy stores evidence in operator-
  managed storage on the host. Retention is a property of that
  storage and persists across heartbeats by default.
- **Sandbox paths:** the proxy stores evidence inside the sandbox
  filesystem. Sandbox filesystems are commonly ephemeral. This guide
  does **not** claim durable sandbox-side evidence by default.
  Operators who need durable retention from a sandbox run must design
  it: options include selecting a sandbox provider with persistent
  storage, or operating the proxy with a retention strategy that
  forwards evidence out of the ephemeral lifetime. Any such design
  belongs in the operator's own deployment documentation.

Identity continuity follows the same shape. The proxy uses a stable
operator-managed identity by default in local and SSH paths. In
sandbox paths the identity may be ephemeral per sandbox lifetime
unless the operator chooses a secret-handling design that injects a
stable identity at runtime. This guide does not prescribe one; treat
the choice as a deployment decision specific to the operator's
sandbox provider and secret-handling tools.

---

## Operational Checklist

Before running an agent against the integration:

- The agent runtime is configured to launch AgentVeil as the MCP
  wrapper for the downstream MCP server you want to gate.
- The agent runtime's MCP layer recognises the AgentVeil wrapper at
  startup and successfully completes its standard MCP handshake.
- A representative MCP-routed tool call from the agent reaches the
  downstream MCP server through AgentVeil. (Use an instrumented or
  test-only downstream server during onboarding to confirm
  visibility.)
- Built-in agent-runtime tools are handled by a separate control
  surface — the runtime's own permission system, Paperclip's
  approvals, or sandbox-level controls — appropriate to your risk
  model.
- Your evidence-retention choice is explicit and consistent with any
  external retention claim you intend to make.
- Your identity-continuity choice is explicit and consistent with any
  reputation-continuity expectations downstream.
- If you are running in a cloud sandbox, the sandbox image you point
  the provider at includes the AgentVeil proxy and the proxy is on
  the runtime's standard binary path.

---

## Claim Boundaries

**Allowed:**

- "The integration controls MCP-routed downstream tool calls."
- "Local Claude and local Codex paths have been validated internally."
- "The runtime control surface lives in the external AgentVeil proxy."
- "`paperclip-plugin-avp` contributes advisory signals into Paperclip
  workflows."
- "A documented setup pattern exists for cloud sandbox providers; a
  live single-provider proof is a planned next step."
- "SSH remote targets require operator pre-provisioning of both the
  agent runtime and the AgentVeil proxy."
- "Built-in agent-runtime tools require separate controls."

**Not allowed in operator-facing copy:**

- Any phrasing that implies AgentVeil intercepts built-in agent-runtime
  tools.
- Any phrasing that implies the Paperclip plugin embeds runtime
  enforcement.
- Any phrasing that frames this integration as a substitute for
  Paperclip's own governance, approvals, budgets, retention, or
  rollback. Those continue to live in Paperclip.
- Any phrasing that implies a specific cloud sandbox provider has
  been validated live end-to-end (until that proof exists).
- Any phrasing that implies Cloudflare-bridge environments are
  covered (until that coverage exists).
- Any phrasing that implies durable sandbox-side evidence by default.
- Any phrasing that implies endorsement by any agent-runtime vendor or
  sandbox provider.

---

## Next Proof Milestones

The following items are explicitly out of scope for this version of the
guide and will be addressed as separate work:

- A live single-cloud-sandbox-provider end-to-end proof, on a custom
  image that has the AgentVeil proxy pre-installed.
- A verification track that establishes durable evidence retention
  beyond local and SSH storage.
- A design for stable sandbox identity that fits the operator's
  secret-handling tools.
- An optional Paperclip-side evidence-reader surface that lets
  Paperclip workflows consume AgentVeil signals without changing the
  runtime enforcement point.

Each of those is independent of the integration as it stands today;
none of them is required for the local and SSH paths to work.
