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
