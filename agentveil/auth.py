"""
AVP authentication helpers.
Builds signed Authorization headers for API requests.
"""

import hashlib
import secrets
import time
from urllib.parse import quote, urlencode

from nacl.signing import SigningKey


def canonicalize_query_params(params: dict | list[tuple[str, object]] | None = None) -> str:
    """Canonicalize query params for AVP-Sig v2.

    Sorts key/value pairs, preserves repeated keys, and encodes spaces as %20
    instead of '+'.
    """
    if not params:
        return ""
    pairs = []
    if isinstance(params, dict):
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((str(key), str(item)) for item in value)
            else:
                pairs.append((str(key), str(value)))
    else:
        pairs = [(str(k), str(v)) for k, v in params]
    pairs.sort(key=lambda item: (item[0], item[1]))
    return urlencode(pairs, doseq=True, quote_via=quote, safe="")


def build_auth_header(
    private_key: bytes,
    did: str,
    method: str,
    path: str,
    body: bytes = b"",
    params: dict | list[tuple[str, object]] | None = None,
    *,
    force_v2: bool = False,
) -> dict[str, str]:
    """
    Build AVP-Sig Authorization header.

    Signs: {method}:{path}:{timestamp}:{nonce}:{body_sha256}
    Returns dict with Authorization header ready for httpx.

    Args:
        private_key: Ed25519 private key (32 bytes)
        did: Agent's DID (did:key:z6Mk...)
        method: HTTP method (GET, POST, etc.)
        path: URL path (/v1/attestations)
        body: Request body bytes
        params: Optional query params. When provided, signs AVP-Sig v2 with
            canonical query binding.
        force_v2: When True, sign AVP-Sig v2 even when the canonical query is
            empty. Non-boolean values are rejected before signing.
    """
    if not isinstance(force_v2, bool):
        raise TypeError("force_v2 must be a bool")

    ts = int(time.time())
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body).hexdigest()

    canonical_query = canonicalize_query_params(params)
    sig_version = "2" if canonical_query or force_v2 else "1"
    if sig_version == "2":
        message = f"v2:{method}:{path}:{canonical_query}:{ts}:{nonce}:{body_hash}"
    else:
        message = f"{method}:{path}:{ts}:{nonce}:{body_hash}"
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message.encode())
    sig_hex = signed.signature.hex()

    version_part = 'v="2",' if sig_version == "2" else ""
    return {
        "Authorization": f'AVP-Sig {version_part}did="{did}",ts="{ts}",nonce="{nonce}",sig="{sig_hex}"',
        "Content-Type": "application/json",
    }
