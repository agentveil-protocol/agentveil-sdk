"""Shared did:key Ed25519 encoder.

Holds ``_public_key_to_did`` so that ``delegation`` and ``data_integrity`` can
both use it without an import cycle. ``data_integrity`` previously imported this
function from ``delegation``; a later change that lets ``delegation`` call into
``data_integrity`` would otherwise close that loop. This module depends only on
``base58`` and imports no other ``agentveil`` module, so importing it cannot
create a cycle.

This is a pure relocation: the function body is unchanged from its prior home in
``delegation``. The decode-side ``_did_to_public_key`` is deliberately NOT
centralized here, because ``delegation`` and ``data_integrity`` raise different
error types (``DelegationInvalid`` vs ``DataIntegrityError``) with different
messages and different base58-error handling; merging them would change
observable behavior and would pull those error classes into this leaf module.
"""

from __future__ import annotations

import base58

ED25519_MULTICODEC = b"\xed\x01"


def _public_key_to_did(public_key: bytes) -> str:
    """Encode a 32-byte Ed25519 public key as a did:key string."""
    multicodec_key = ED25519_MULTICODEC + public_key
    encoded = base58.b58encode(multicodec_key).decode()
    return f"did:key:z{encoded}"


__all__ = ["ED25519_MULTICODEC", "_public_key_to_did"]
