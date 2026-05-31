# MCP Proxy Operations

## Downstream Lifecycle

The MCP proxy starts each configured downstream MCP server as a child process and
applies platform-specific cleanup controls:

| Platform | Ungraceful Proxy Termination Behavior |
| --- | --- |
| Linux | The downstream child receives `SIGTERM` through `prctl(PR_SET_PDEATHSIG)` if the proxy process exits before normal cleanup. The downstream also runs in its own process group for graceful shutdown. |
| Windows | The downstream process is assigned to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the kernel terminates the job when the proxy process exits. |
| macOS | Graceful proxy shutdown terminates the downstream process group. If the proxy is force-killed, downstream may remain running; run the proxy under `launchd` or another supervisor when ungraceful-termination cleanup is required. |

## Downstream Response Timeout

The proxy waits up to `downstream.response_timeout_seconds` for a forwarded
JSON-RPC request to receive a matching downstream response. The default is 30
seconds.

Example:

```json
{
  "downstream": {
    "name": "github-mcp",
    "command": "github-mcp-server",
    "args": [],
    "response_timeout_seconds": 30
  }
}
```

On timeout, the proxy returns a sanitized JSON-RPC error to the client and keeps
the downstream process running so later requests can continue.

## Downstream Response Size And Framing

The proxy accepts downstream JSON-RPC responses as UTF-8 JSON objects on stdout,
including pretty-printed objects that span multiple lines. Each downstream
message is bounded to 1 MiB. If a downstream response exceeds that limit or is
not a JSON object, the proxy returns a sanitized downstream-unavailable error to
the client and does not include response content in logs or client output.

## Local Evidence Storage

Approval flows use a local SQLite evidence database at
`~/.avp/mcp-proxy/evidence.sqlite`. The database file is created with `0600`
permissions and uses SQLite WAL mode so pending approvals survive a proxy
restart.

The store contains approval state and privacy-preserving metadata only: request
IDs, session/client labels, server/tool names, action and risk classes, resource
hashes, payload hashes, policy context hashes, receipt hashes, approval token
hashes, timestamps, and sanitized result/error classes. It must never contain raw
MCP arguments, prompts, outputs, tokens, source code, secrets, or private logs.

Pending approval records are written before an approval prompt can authorize
downstream execution. On startup, stale pending records are marked expired; the
store never auto-approves a request during recovery.

Evidence schema version 2 adds a local hash chain. Each request record stores
`prev_event_hash`; `record_hash` is computed over the canonical JCS form of the
record fields excluding `prev_event_hash` and `record_hash` themselves. Chain
nodes are per request ID. Approval transitions update the existing request
record and the store reconstructs following chain pointers inside the same
transaction.

To export an offline verification bundle:

```bash
agentveil-mcp-proxy export-evidence /secure/path/evidence-bundle.json \
  --since 2026-05-01T00:00:00Z
agentveil-mcp-proxy verify /secure/path/evidence-bundle.json
agentveil-mcp-proxy verify /secure/path/evidence-bundle.json --output json
```

The export bundle is written with `0600` permissions and includes schema
version, export time, proxy DID, trusted signer DID set, chain root hash,
privacy-preserving records, and any signed receipts that can be fetched
opportunistically. Receipt JCS strings are stored byte-exact so offline
verification can validate backend signatures. If receipt fetch fails during
export, the bundle remains valid and reports the unverified receipt count.

`verify` performs offline checks only: record hashes, chain linkage, signed
receipt signatures against pinned trusted signer DIDs, and signed-field binding
between records and DecisionReceipts when those receipts are present. It checks
payload hash, client risk class, and client policy context hash. It does not
call the AVP backend.

Auditors should pass their own pinned signer DID set:

```bash
agentveil-mcp-proxy verify /secure/path/evidence-bundle.json \
  --trusted-signer-did did:key:z6Mk...
```

`verify` runs in strict, proof-grade mode: it trusts ONLY the signer DID(s) you
pin with `--trusted-signer-did` and never the signer list embedded in the
bundle. A receipt-bearing bundle therefore fails closed (non-zero exit,
`status: invalid`) unless you pass `--trusted-signer-did`, and a referenced
signed receipt that is missing from the bundle is a hard failure, not a warning.
That is what stops a malicious bundle from vouching for itself with an
attacker-controlled signer DID and a matching attacker-signed receipt.

For day-to-day operator visibility, use the privacy-safe event views:

```bash
agentveil-mcp-proxy events list --limit 20
agentveil-mcp-proxy events list --json
agentveil-mcp-proxy events tail
agentveil-mcp-proxy events tail --follow
agentveil-mcp-proxy evidence-summary
```

`events list` / `events tail` show timestamp, downstream server, tool, risk
class, evidence status, policy rule, receipt presence, and evidence record ID.
They do not print raw MCP arguments, prompts, outputs, tokens, source code,
secrets, payload hashes, or result hashes. `evidence-summary` prints aggregate
counts by status and receipt presence.

To prune old terminal records and rebuild the local chain:

```bash
agentveil-mcp-proxy events vacuum --max-age-days 90
agentveil-mcp-proxy events vacuum --before 2026-05-01T00:00:00Z
```

Vacuum removes only terminal states (`executed`, `denied`, `expired`,
`invalidated`, `error`, `blocked`) older than the cutoff. Pending and approved
records are preserved regardless of age. The legacy `events --vacuum` form is
still accepted.

### Signed Approval Grants

When the proxy identity is configured with a signing key and the approval record
has a bounded expiry, approved local decisions are recorded with a signed approval
grant (schema `proxy_approval_grant/1`) when minting succeeds. It is stored next to
the approval record and verified during `verify`. The grant is signed by the
**local proxy identity key** — the proxy's own DID, printed by `init` and recorded
in the bundle's `proxy_identity_did` field — using the proxy's shipped Data
Integrity signing primitive.

**What a verified grant proves.** The pinned proxy identity recorded an
`APPROVED` local approval decision bound to one specific action: request ID,
downstream server, tool, action/risk class, resource hash, policy ID and rule,
policy context hash, approval scope, the deciding-actor label, and an explicit
expiry. `verify` cross-checks each of those fields against the approval record,
so a valid grant cannot be transplanted onto a different call.

**What a grant does NOT prove.** A grant is a *local* attestation only. By
itself it does not establish backend authorization, a real human's identity,
that the downstream tool call executed, or that the call was acceptable under policy. The
`decided_by` label may be `local-user`, `headless-policy`, or `scope-cache-hit`;
it is not an authenticated human identity. Execution outcome is separate
evidence recorded on the record: whether the approved call ran, errored, or was rejected downstream, plus a result hash.

**Trust model.** Grant trust is external-pinning only. `verify` accepts a grant
only when its signer DID is in the `--trusted-signer-did` set you pin out of
band, and it requires the grant's embedded `agent_did` to equal that signer.
Neither the bundle's own `trusted_signer_dids` field nor any signer hint inside a
grant is ever an accepted trust anchor, so a re-signed bundle cannot vouch for
its own grants. Add the proxy's DID to the same `--trusted-signer-did` set you
use for backend receipt signers; the bundle's `proxy_identity_did` is a value to
confirm out of band, not a trust source.

**Scope binding.** Grant binding follows the approval scope:

- `exact` binds `payload_hash`, the approved call's exact payload.
- `similar_5m` binds `resource_hash` and omits `payload_hash`, covering similar
  calls on the same resource for a short window.
- Either scope carries a **mandatory** `expires_at`, matched against the record's
  exact-approval expiry or its 5-minute scope expiry. A grant requires an
  explicit expiry.

**Strict vs legacy verification.** `verify`, and the library default, run
strict, proof-grade verification: every record that recorded a local `APPROVED`
decision must carry a grant that verifies and matches the record — including
records that were approved and then ran, were rejected downstream, or errored. A missing
grant, or a present grant with no external signer pin, is a hard failure
(`status: invalid`). Records that were denied, expired, or are still pending, and
Runtime Gate / backend-only records that mint no local grant, are exempt. Legacy
/ non-strict verification is a library-only path
(`verify_evidence_bundle(..., strict=False)` or `verify_evidence_bundle_legacy`;
there is no CLI flag) that downgrades those two failures to warnings.

**Backward compatibility.** Signed grants were added on top of an existing
evidence store, so bundles exported before grants shipped — and any record
approved by a proxy that had no grant signing key, no bounded approval expiry, or
a grant-mint failure — carry locally approved records with no grant. Strict
`verify` fails closed on them; inspect
such pre-grant bundles with legacy / non-strict library verification, which
reports each missing grant as a warning. Those records remain valid chain
evidence but do not provide signed approval-grant assurance for the approval decision itself.

## Local Approval Surface

Approval-required tool calls are routed to a loopback approval server bound to
`127.0.0.1` on an ephemeral port. The approval URL contains a per-process token,
and approve/deny POSTs require that path token, an HTTP-only HMAC cookie, and a
per-request CSRF token. The token rotates on every proxy restart and only its
hash is written to local evidence.

Approval pages set `Referrer-Policy: no-referrer`, no-store cache headers,
frame-denial headers, and a restrictive Content Security Policy on every
response. The UI displays privacy-filtered action/resource metadata and never
shows raw MCP arguments, prompts, outputs, tokens, source code, secrets, or
private logs.

The proxy writes the pending approval record before it renders the approval page
or sends notifications. Approval, denial, and timeout decisions are written back
to local evidence before the proxy acts on them.

For MCP stdio clients, approval-required calls fail fast instead of holding the
tool call open until a human acts. The JSON-RPC error uses code `-32011` and
includes `status: "approval_required"`, `record_id`, `record_status`, and
`approval_url`. Open the URL to approve or deny; if approved, retry the tool
call so the new request can use the recorded approval grant.

## Multi-IDE Deployment

For developers running multiple LLM IDE clients, the canonical pattern is one
MCP proxy per IDE.

Each `agentveil-mcp-proxy run` invocation creates an independent process with:

- A distinct approval server port, bound to `127.0.0.1` on a random unused port
- An independent evidence database, scoped by `--home` or `AVP_HOME`
- An independent Runtime Gate session, identity, and control grant
- Independent circuit breaker state

This process-level isolation avoids shared approval state between proxy
instances on the same host. Each IDE's MCP server configuration should point at
its own proxy command.

Example: two IDEs on one machine

```bash
AVP_HOME="$HOME/.avp-claude" agentveil-mcp-proxy run
AVP_HOME="$HOME/.avp-cursor" agentveil-mcp-proxy run
```

Each proxy has its own home tree containing its identity, control grant, and
`evidence.sqlite`. Decisions in one proxy do not authorize or deny requests in
the other.

For centralized policy enforcement across multiple developers, enforce policy
in the AVP backend rather than multiplexing multiple IDE clients through one
local proxy process.

## Headless Approval Mode

For CI or scheduled jobs, run with deny-by-default headless behavior:

```bash
agentveil-mcp-proxy run --headless --auto-deny
agentveil-mcp-proxy run --headless --headless-policy /etc/avp/mcp-headless-policy.json
```

Headless policy files use JSON and are schema-versioned:

```json
{
  "headless_policy_schema_version": 1,
  "pre_approvals": [
    {
      "server": "github",
      "tool": "create_issue",
      "resource_hash": "sha256:...",
      "environment": "mcp_proxy",
      "risk_class": "write",
      "max_payload_hash": "sha256:...",
      "expires_at": "2026-06-01T00:00:00Z"
    }
  ]
}
```

Missing matches deny by default. `destructive`, `production`, and `financial`
pre-approvals require a resource selector (`resource_hash` or `resource`). They
also require an exact `max_payload_hash` unless the policy explicitly sets
`allow_narrow_match: true`. Store headless policy files with owner-only
permissions (`0600` or `0400`) before starting the proxy.

### Policy Rule Override Semantics

When you author a user policy rule with `intentional_override: true`, the local
policy engine treats your override as an explicit decision to bypass built-in
policy pack rules for the contexts that match your rule.

Selection algorithm (`policy.py:_select_rule`):

1. If any matching user rule has `intentional_override: true`:
   - Built-in rules are ignored for this context.
   - Among matching user rules, override and non-override, the highest-rank
     decision wins. Stricter user-authored decisions are not silently bypassed.
2. Otherwise, the highest-rank matching rule wins across user and built-in
   rules.

Operational implication:

A single user rule with `intentional_override: true` matching a context where a
built-in policy pack normally provides protection causes that built-in
protection to be ignored. This is by design: operators use
`intentional_override` to relax built-in defaults that conflict with their
environment. It is still a security boundary footgun. There is no
"intentional_override only narrows selection to this rule" mode; the override
applies to the entire matching context.

Example footgun:

If you load the `filesystem` built-in pack, which blocks `delete_*`, `purge_*`,
`wipe_*`, and similar tools through the `filesystem-delete` rule, and add a user
rule matching `server: ["filesystem"]` with `intentional_override: true` and
`decision: "allow"`, then all filesystem destructive actions become allowed
regardless of the built-in rule's block intent.

Recommended pattern:

Narrow override rules as tightly as possible by tool name pattern, not by server
alone. Use `match.tool` patterns that name only the specific operation you want
to permit, such as `tool: ["delete_logs_*"]` for log-rotation tooling, so the
built-in blanket destructive protection remains in effect for unnamed tools.

## Proxy Identity Storage

`agentveil-mcp-proxy init` encrypts the local proxy identity by default. In an
interactive shell it prompts for a passphrase and confirmation. In automated
setup, provide the passphrase with one of:

```bash
agentveil-mcp-proxy init --passphrase-file /run/secrets/avp-proxy-passphrase
AVP_PROXY_PASSPHRASE='...' agentveil-mcp-proxy init
```

`doctor`, `run`, and `reissue-grant` use the same passphrase sources. Plaintext
storage is available only through the explicit `--plaintext` opt-out on `init`;
the command prints a warning because the private key is then protected only by
local file permissions.

### Security Trade-Offs By Passphrase Source

The four passphrase sources do not have equivalent security properties on POSIX
systems:

- **`--passphrase`** - appears in the process command line, visible via
  `ps eww` to any user on the same host, and may be written to shell history.
  Use only for one-off interactive operations, never in scripts or CI.

- **`AVP_PROXY_PASSPHRASE` env var** - visible to other processes running under
  the same UID via `/proc/<pid>/environ` on Linux, and briefly via `ps eww`
  during the proxy startup window. It is acceptable for short-lived `init`
  operations in trusted single-user environments, but it is not recommended for
  long-running automated setups.

- **`--passphrase-file`** - the most secure automated method. The file contents
  are not visible in process listings or environment dumps. The MCP proxy
  enforces owner-only POSIX permissions (`0o600` or `0o400`) on the passphrase
  file before reading it; mispermissioned files are rejected.

- **TTY prompt** - the most secure interactive method: no command line, no
  environment, and no file artifact. Use this for first-time `init` on developer
  workstations.

For CI/CD, container, and systemd-style automated deployments, prefer
`--passphrase-file` pointing at a mount provided by a secret manager, such as
`/run/secrets/avp-proxy-passphrase` on Docker Swarm or
`/var/run/secrets/...` on Kubernetes.

Encrypted identity storage uses an Argon2id key derivation function with
moderate operation and memory limits. Each CLI invocation that opens the
identity derives the key again, which commonly adds about three seconds of
startup latency depending on host hardware. The derived key is never cached on
disk, and v0.1 intentionally does not keep an in-process decrypted-key cache
between commands. Scripts can set `AVP_PROXY_PASSPHRASE` once per shell session
to avoid repeated passphrase prompts, but each command still pays the derivation
cost. For production automation, run `agentveil-mcp-proxy run` as a persistent
process or service instead of repeatedly chaining short-lived `doctor && run`
invocations. The explicit `--plaintext` opt-out avoids the KDF cost by storing
the private key unencrypted on disk.

### Migrate Existing Plaintext Identity

Do not use `agentveil-mcp-proxy init --force` to migrate an existing plaintext
identity. `init --force` creates a new DID, which changes the proxy identity
used for AVP reputation, receipts, and local control grants.

To preserve the existing DID, stop the proxy and re-wrap the current identity
file with a passphrase:

```bash
export AVP_HOME="${AVP_HOME:-$HOME/.avp}"
export PASSPHRASE_FILE="/run/secrets/avp-proxy-passphrase"
cp -p "$AVP_HOME/agents/agentveil-mcp-proxy.json" \
  "$AVP_HOME/agents/agentveil-mcp-proxy.json.plaintext-backup-$(date +%Y%m%d%H%M%S)"

python3 - <<'PY'
import json
import os
from pathlib import Path

from agentveil.agent import AVPAgent
from agentveil_mcp_proxy.identity import encrypted_identity_payload

home = Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
config_path = home / "mcp-proxy" / "config.json"
config = json.loads(config_path.read_text(encoding="utf-8"))
agent_name = config["avp"]["agent_name"]
base_url = config["avp"]["base_url"]
identity_path = home / "agents" / f"{agent_name}.json"
identity = json.loads(identity_path.read_text(encoding="utf-8"))

if identity.get("encrypted") is True:
    raise SystemExit("identity is already encrypted")
private_key_hex = identity.get("private_key_hex")
if not isinstance(private_key_hex, str) or not private_key_hex:
    raise SystemExit("plaintext private_key_hex is missing")

passphrase_path = Path(os.environ["PASSPHRASE_FILE"])
passphrase = passphrase_path.read_text(encoding="utf-8").strip()
if not passphrase:
    raise SystemExit("passphrase file is empty")

agent = AVPAgent(base_url, bytes.fromhex(private_key_hex), name=agent_name)
if agent.did != identity.get("did"):
    raise SystemExit("identity DID mismatch; refusing to rewrite")

encrypted = encrypted_identity_payload(agent, passphrase)
encrypted["registered"] = bool(identity.get("registered", False))
encrypted["verified"] = bool(identity.get("verified", False))

tmp_path = identity_path.with_name(f".{identity_path.name}.tmp")
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
with os.fdopen(os.open(tmp_path, flags, 0o600), "w", encoding="utf-8") as fh:
    json.dump(encrypted, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp_path, identity_path)
os.chmod(identity_path, 0o600)
print(f"migrated identity {agent.did} at {identity_path}")
PY

agentveil-mcp-proxy doctor --passphrase-file "$PASSPHRASE_FILE"
```

Keep the backup only long enough to verify the proxy can run with the encrypted
identity. Store or destroy the backup according to your local key-handling
policy; it contains the plaintext private key.

## Control Grant Lifecycle

The local control grant defaults to a 30-day TTL. `doctor` warns when the grant
expires within 7 days and fails when it has already expired.

To rotate the grant:

```bash
agentveil-mcp-proxy reissue-grant --passphrase-file /run/secrets/avp-proxy-passphrase
```

The command refuses to replace a still-valid grant with more than 24 hours
remaining unless `--force` is passed. For scheduled checks, `--auto` prints a
single structured status line.
