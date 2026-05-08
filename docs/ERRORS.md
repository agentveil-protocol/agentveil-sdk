# Error Handling

AgentVeil SDK methods raise typed exceptions for API responses and local
validation failures. Network failures and some offline verifier failures use
their native exception types so applications can handle transport, SDK, and
proof errors separately.

## Hierarchy

```text
Exception
├── httpx.RequestError
├── agentveil.delegation.DelegationInvalid
├── agentveil.proof.ProofVerificationError
└── AVPError
    ├── AVPAuthError
    ├── AVPNotFoundError
    ├── AVPRateLimitError
    ├── AVPValidationError
    └── AVPServerError
```

`AVPError` has these attributes:

| Attribute | Meaning |
|---|---|
| `message` | Human-readable SDK message. Also available through `str(exc)`. |
| `status_code` | HTTP status when the error came from an HTTP response. Defaults to `0` for local SDK errors. |
| `detail` | Backend detail text when available. |

`AVPRateLimitError` also exposes `retry_after`, in seconds.

## Exception Reference

| Exception | Triggers | Attributes | Common cause | Recovery pattern |
|---|---|---|---|---|
| `AVPValidationError` | Local validation failure, `400`, or `409` | `message`, `status_code`, `detail` | Bad input, invalid outcome/weight, malformed request, conflict state | Fix input or state before retrying. Do not blind-retry. |
| `AVPAuthError` | `401` or `403` | `message`, `status_code`, `detail` | Missing/invalid signature, stale timestamp, nonce replay, unverified/suspended/revoked DID | Reload the correct key, register/verify the DID, check clock skew, or stop if the DID is revoked. |
| `AVPNotFoundError` | `404` | `message`, `status_code`, `detail` | Missing object, foreign private object, or intentionally hidden resource | Verify the identifier and caller DID. Treat private-resource 404s as non-disclosure. |
| `AVPRateLimitError` | `429` | `message`, `retry_after`, `status_code` | Trust Gate, registration, or global API rate limit | Wait at least `retry_after` seconds and retry with backoff. |
| `AVPServerError` | `5xx` or malformed successful response | `message`, `status_code`, `detail` | Backend dependency unavailable, signing config missing, non-JSON response where JSON was required | Retry cautiously with backoff. Escalate if persistent. |
| `AVPError` | Any other SDK-mapped response | `message`, `status_code`, `detail` | Unexpected status code or SDK-level failure | Log status/detail and fail safely. |
| `httpx.RequestError` | Request could not reach the API | Native `httpx` fields | DNS, TLS, proxy, timeout, connection refused | Check `base_url`, network, TLS, and retry only after transport is healthy. |
| `DelegationInvalid` | Offline DelegationReceipt verification failure | `reason` | Expired receipt, invalid signature, wrong issuer, unsupported scope | Obtain a fresh valid DelegationReceipt from the principal. |
| `ProofVerificationError` | Offline proof artifact verification failure | Reason via `str(exc)` | Invalid signature, untrusted signer DID, malformed packet, or receipt hash mismatch | Treat as failed evidence verification and re-export from trusted source artifacts. |

## HTTP Mapping

SDK HTTP helpers map responses as follows:

| HTTP status | SDK exception |
|---|---|
| `400` | `AVPValidationError` |
| `401` | `AVPAuthError` |
| `403` | `AVPAuthError` |
| `404` | `AVPNotFoundError` |
| `409` | `AVPValidationError` |
| `429` | `AVPRateLimitError` |
| `5xx` | `AVPServerError` |
| Other non-success | `AVPError` |

`integration_preflight()` is intentionally different: it returns an
`IntegrationPreflightReport` with `ready`, `status`, and `next_action` instead
of raising for common readiness states.

## Common Scenarios

| Scenario | Likely signal | Recovery |
|---|---|---|
| Network failure during `register(...)` | `httpx.RequestError` | Check network/TLS/base URL. Retry after transport is stable. |
| Duplicate DID registration | `AVPValidationError` with `Conflict: ...` | Load the existing saved agent if it is yours, or create a fresh DID. |
| Rate limit during `attest_batch(...)` | `AVPRateLimitError`, `retry_after` | Sleep at least `retry_after`, then retry with jitter/backoff. |
| Malformed DelegationReceipt in `runtime_evaluate(...)` | `AVPValidationError` | Verify the receipt offline first and correct input before retrying. |
| Backend unavailable during `controlled_action(...)` | `AVPServerError` | Do not execute the action directly. Retry later or fail closed. |
| Approval not ready or expired | `AVPValidationError` with a conflict-style message | Surface the state to the principal and create or wait for a valid approval. |
| Invalid DelegationReceipt offline | `DelegationInvalid` | Ask the principal for a fresh receipt with the intended scope and validity window. |

## Recovery Snippets

Rate limit:

```python
try:
    agent.attest_batch(items)
except AVPRateLimitError as exc:
    time.sleep(exc.retry_after)
    # Retry once with jitter/backoff in production.
```

Validation:

```python
try:
    agent.runtime_evaluate(...)
except AVPValidationError as exc:
    print(exc.message)
    # Fix malformed input or unsafe state before retrying.
```

Backend unavailable:

```python
try:
    outcome = agent.controlled_action(...)
except AVPServerError as exc:
    print(exc.message)
    # Fail closed: do not run the action outside the control path.
```

Network:

```python
try:
    agent.register(display_name="worker")
except httpx.RequestError as exc:
    print(exc)
    # Check base_url, TLS, proxy, and retry when connectivity is healthy.
```

Generic SDK handling:

```python
try:
    result = agent.get_reputation()
except AVPError as exc:
    print(exc.status_code, exc.message)
```

## Known Coverage Notes

Most HTTP-backed SDK calls route non-success API responses through typed SDK
exceptions. A few local Python errors can still happen before an HTTP response
exists, such as malformed local dictionaries passed into helper methods. Treat
those as programming errors and validate inputs before calling the SDK.

## Related Guides

- [Customer Integration](CUSTOMER_INTEGRATION.md) for controlled-action error states and proof retention.
- [Proof Packet Guide](PROOF_PACKET.md) for `ProofVerificationError` handling.
- [Registration & Verification](REGISTRATION.md) for setup and verification recovery.
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md) for offline delegation validation failures.
