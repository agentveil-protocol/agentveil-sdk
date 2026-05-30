"""Local MCP proxy identity serialization helpers."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from agentveil.agent import AVPAgent


PASSPHRASE_ENV = "AVP_PROXY_PASSPHRASE"
PLAINTEXT_WARNING = (
    "WARNING: --plaintext stores the MCP proxy private key unencrypted on disk. "
    "Use encrypted storage unless an external secret manager protects this host."
)


class IdentityError(RuntimeError):
    """Base class for sanitized local identity failures."""


class IdentityPassphraseRequired(IdentityError):
    """Raised when an encrypted identity cannot be loaded without a passphrase."""


class IdentityDecryptError(IdentityError):
    """Raised when an encrypted identity cannot be decrypted."""


class IdentityInvalidError(IdentityError):
    """Raised when an identity file is malformed."""


def plaintext_identity_payload(agent: AVPAgent) -> dict[str, Any]:
    """Return the explicit plaintext identity file payload."""

    return {
        "name": agent._name,
        "did": agent.did,
        "public_key_hex": agent.public_key_hex,
        "registered": agent.is_registered,
        "verified": agent.is_verified,
        "base_url": agent._base_url,
        "private_key_hex": agent.private_key_hex,
        "encrypted": False,
    }


def encrypted_identity_payload(agent: AVPAgent, passphrase: str) -> dict[str, Any]:
    """Return an encrypted identity payload matching AVPAgent.save semantics."""

    if not passphrase:
        raise IdentityPassphraseRequired("encrypted identity passphrase required")

    from nacl.pwhash import argon2id
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random

    salt = nacl_random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        passphrase.encode(),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )
    box = SecretBox(key)
    encrypted = box.encrypt(bytes.fromhex(agent.private_key_hex)).hex()
    return {
        "name": agent._name,
        "did": agent.did,
        "public_key_hex": agent.public_key_hex,
        "registered": agent.is_registered,
        "verified": agent.is_verified,
        "base_url": agent._base_url,
        "private_key_encrypted": encrypted,
        "encrypted_blob": encrypted,
        "encryption_salt": salt.hex(),
        "encrypted": True,
    }


def load_agent_from_identity(
    identity: Mapping[str, Any],
    *,
    base_url: str,
    agent_name: str,
    passphrase: str | None = None,
    agent_cls: Callable[..., Any] = AVPAgent,
    timeout: float | None = None,
) -> Any:
    """Load an AVP agent from a local proxy identity payload."""

    private_key = _private_key_from_identity(identity, passphrase=passphrase)
    kwargs: dict[str, Any] = {"name": agent_name}
    if timeout is not None:
        kwargs["timeout"] = timeout
    try:
        agent = agent_cls(base_url, private_key, **kwargs)
    except TypeError:
        kwargs.pop("timeout", None)
        agent = agent_cls(base_url, private_key, **kwargs)

    if hasattr(agent, "_is_registered"):
        agent._is_registered = bool(identity.get("registered", False))
    if hasattr(agent, "_is_verified"):
        agent._is_verified = bool(identity.get("verified", False))
    if hasattr(agent, "_saved_to_disk"):
        agent._saved_to_disk = True
    return agent


def _private_key_from_identity(identity: Mapping[str, Any], *, passphrase: str | None) -> bytes:
    encrypted = identity.get("encrypted")
    if encrypted is True:
        return _decrypt_private_key(identity, passphrase=passphrase)
    if encrypted is False:
        private_key_hex = identity.get("private_key_hex")
        if not isinstance(private_key_hex, str) or not private_key_hex:
            raise IdentityInvalidError("proxy identity private key unavailable")
        try:
            return bytes.fromhex(private_key_hex)
        except ValueError as exc:
            raise IdentityInvalidError("proxy identity private key invalid") from exc
    raise IdentityInvalidError("proxy identity encryption state invalid")


def _decrypt_private_key(identity: Mapping[str, Any], *, passphrase: str | None) -> bytes:
    if not passphrase:
        raise IdentityPassphraseRequired("encrypted identity passphrase required")

    from nacl.pwhash import argon2id
    from nacl.secret import SecretBox

    encrypted_hex = identity.get("private_key_encrypted") or identity.get("encrypted_blob")
    salt_hex = identity.get("encryption_salt")
    if not isinstance(encrypted_hex, str) or not isinstance(salt_hex, str):
        raise IdentityInvalidError("encrypted identity payload invalid")
    try:
        salt = bytes.fromhex(salt_hex)
        encrypted = bytes.fromhex(encrypted_hex)
    except ValueError as exc:
        raise IdentityInvalidError("encrypted identity payload invalid") from exc
    try:
        key = argon2id.kdf(
            SecretBox.KEY_SIZE,
            passphrase.encode(),
            salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )
        return bytes(SecretBox(key).decrypt(encrypted))
    except Exception as exc:
        raise IdentityDecryptError("encrypted identity could not be decrypted") from exc


__all__ = [
    "IdentityDecryptError",
    "IdentityError",
    "IdentityInvalidError",
    "IdentityPassphraseRequired",
    "PASSPHRASE_ENV",
    "PLAINTEXT_WARNING",
    "encrypted_identity_payload",
    "load_agent_from_identity",
    "plaintext_identity_payload",
]
