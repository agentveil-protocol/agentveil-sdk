# Registration & Verification

Registration turns a local AgentVeil identity into a backend-known agent DID.
Verification proves that the holder of the local Ed25519 private key controls
that DID. A local key alone is not enough for production Runtime Gate or signed
API flows; the backend must know and verify the DID first.

## Lifecycle

```text
created locally
  -> register(...)
registered with backend
  -> proof-of-work + challenge signature
verified DID
  -> optional onboarding/card pipeline
ready for integration_preflight() and controlled_action(...)
```

State meanings:

| State | Meaning |
|---|---|
| Created | Local Ed25519 key and `did:key` exist. Nothing has been submitted to the backend yet. |
| Registered | Backend has accepted the DID registration request. |
| Verified | Backend has verified key ownership through challenge signing and proof-of-work. |
| Onboarded | Optional capability-card/onboarding pipeline has completed. This is separate from DID verification. |

`agent.is_registered` and `agent.is_verified` are local cached booleans. They
are set after `register(...)` succeeds and saved with the agent file. Before a
controlled action, prefer `agent.integration_preflight()` because it checks the
live API, registration state, verification state, agent status, and a safe
signed request.

## Register

```python
def register(
    self,
    display_name: str | None = None,
    capabilities: list[str] | None = None,
    endpoint_url: str | None = None,
    provider: str | None = None,
) -> dict
```

Parameters:

| Parameter | Meaning |
|---|---|
| `display_name` | Human-readable name shown in agent metadata. Defaults to the local agent name. |
| `capabilities` | Optional capability labels. Supplying these can start the onboarding pipeline after verification. |
| `endpoint_url` | Optional URL where this agent can be reached. |
| `provider` | Optional LLM/provider label such as `anthropic` or `openai`. |

`register(...)` performs three steps in one call:

1. POST the public key and optional card metadata.
2. Solve the registration proof-of-work challenge.
3. Sign the server challenge and verify key ownership.

On success, it returns the registration response with an added
`onboarding_pending` boolean, marks the local agent as registered and verified,
and saves the agent file. It no longer waits for onboarding completion. Current
SDK versions do not accept a passphrase argument on `register(...)`; call
`agent.save(passphrase=...)` after registration if the production key should be
stored encrypted.

Expected failures use SDK exception types:

| Exception | Common cause |
|---|---|
| `AVPValidationError` | Duplicate/conflicting DID, invalid input, or backend validation failure. |
| `AVPAuthError` | Signed follow-up request is forbidden or invalid. |
| `AVPRateLimitError` | Registration or trust-gate rate limit. Inspect `retry_after`. |
| `AVPServerError` | Backend dependency/configuration issue or malformed server response. |
| `httpx.RequestError` | Network, DNS, TLS, or timeout failure before a response is returned. |

See [Error Handling](ERRORS.md) for the full SDK exception hierarchy, HTTP
status mapping, and recovery patterns.

## Onboarding

Registration/verification and onboarding are different.

`register(...)` verifies DID ownership and returns immediately after the
verification step. If `capabilities` are supplied, the backend may start an
onboarding/card pipeline in the background.

Use:

```python
challenge_result = agent.auto_answer_onboarding_challenge(max_wait=30.0)
status = agent.wait_for_onboarding(timeout=60.0, poll_interval=2.0)
```

`auto_answer_onboarding_challenge(...)` is explicit opt-in. It polls for a
challenge, submits a stock SDK answer when a challenge is available, and returns
the challenge result or `None` if no challenge is available.

`wait_for_onboarding(...)` blocks until `completed`, `failed`, or
`not_started`, then returns the final status dictionary. Only `completed` means
success. `not_started` means there is no onboarding session to wait for.

## Common Patterns

| Pattern | Flow | Notes |
|---|---|---|
| First-time setup | `AVPAgent.create(...)` -> `register(...)` -> `integration_preflight()` | Use this for a new production DID. |
| Reload existing agent | `AVPAgent.load(..., passphrase=...)` -> `integration_preflight()` | Use the same name and passphrase that saved the key. |
| Re-registration after key rotation | `old_agent.migrate(new_agent)` -> use `new_agent` | Migration is for DID succession; do not keep using the old DID after success. |
| Headless / CI setup | `register(..., capabilities=[...])` -> optional `auto_answer_onboarding_challenge(...)` | Avoid interactive prompts. Keep passphrases in your secret manager. |

## Passphrase Security

By default, SDK agent files live under:

```text
~/.avp/agents/{name}.json
```

Use a passphrase when storing production keys:

```python
agent = AVPAgent.create("https://agentveil.dev", name="release-agent", save=False)
agent.register(display_name="Release Agent")
agent.save(passphrase=os.environ["AVP_AGENT_PASSPHRASE"])
```

If saved with a passphrase, `AVPAgent.load(...)` requires the same passphrase.
Without a passphrase, the local private key is stored as plaintext hex with
owner-only file permissions. There is no passphrase recovery in the SDK. Keep
the passphrase in your credential manager or CI secret store. If the passphrase
and private-key backup are both lost, create a new DID and use `migrate(...)`
only if the old key is still available to sign the migration.

Never commit `~/.avp/agents/*.json`, raw private keys, passphrases, or CI
secrets to a repository.

## Error Cases And Recovery

| Case | What you see | Recovery |
|---|---|---|
| Network failure during registration | `httpx.RequestError` before an SDK response exists | Check `base_url`, DNS/TLS, proxy settings, and retry once connectivity is stable. |
| Proof-of-work is slow | `register(...)` spends time solving PoW | Treat this as normal anti-abuse work. If it never completes, inspect CPU limits and retry. |
| Backend returns malformed registration data | `AVPServerError` mentioning a missing `challenge`, `pow_challenge`, or `pow_difficulty` | Stop and inspect backend health/configuration. |
| Duplicate DID or conflicting state | `AVPValidationError` with `Conflict: ...` | Load the existing saved agent if this DID is yours; otherwise create a fresh identity. |
| Onboarding challenge unavailable | `auto_answer_onboarding_challenge(...)` returns `None` or `wait_for_onboarding(...)` returns `not_started` | Continue with DID verification checks, or publish capabilities/card data to start onboarding. |
| Challenge expired or rejected | Challenge answer result shows failure, or status becomes `failed` | Re-run onboarding or register a new capability card depending on backend guidance. |
| Mismatched local key and DID | `integration_preflight()` reports `signature_invalid` | Load the correct saved key or restore from a known private-key backup. |

## Next Steps

After registration is ready:

1. Run `agent.integration_preflight()`.
2. Obtain or issue a DelegationReceipt for the intended action scope.
3. Call `controlled_action(...)`.
4. Export and verify Proof Packets with [Proof Packet Guide](PROOF_PACKET.md).

See [Customer Integration](CUSTOMER_INTEGRATION.md) for the controlled-action
path and [DelegationReceipt Guide](DELEGATION_RECEIPT.md) for delegation
issuance and verification.
