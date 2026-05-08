"""
AVPAgent — main SDK class for interacting with Agent Veil Protocol.

Handles key management, authentication, registration, attestations,
and reputation queries.

Usage:
    agent = AVPAgent.create("https://avp.example.com", name="MyAgent")
    agent.register()

    agent.attest("did:key:z6Mk...", outcome="positive", weight=0.8)
    rep = agent.get_reputation("did:key:z6Mk...")
"""

import json
import os
import logging
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Optional

import httpx
from nacl.signing import SigningKey, VerifyKey

from agentveil.auth import build_auth_header
from agentveil.pow import solve_pow
from agentveil.results import ControlledActionOutcome, IntegrationPreflightReport, ProofPacket
from agentveil.exceptions import (
    AVPError,
    AVPAuthError,
    AVPNotFoundError,
    AVPRateLimitError,
    AVPValidationError,
    AVPServerError,
)

log = logging.getLogger("agentveil")

# Default storage for agent keys
AGENTS_DIR = os.path.expanduser("~/.avp/agents")

# Multicodec prefix for Ed25519 public key
ED25519_MULTICODEC = bytes([0xED, 0x01])
SUCCESS_STATUS_CODES = {200, 201}


def _public_key_to_did(public_key: bytes) -> str:
    """Convert Ed25519 public key to did:key."""
    import base58
    multicodec_key = ED25519_MULTICODEC + public_key
    encoded = base58.b58encode(multicodec_key).decode("ascii")
    return f"did:key:z{encoded}"


def _parse_retry_after(response: httpx.Response) -> int:
    headers = getattr(response, "headers", {}) or {}
    raw = headers.get("Retry-After", "60") if hasattr(headers, "get") else "60"
    if not isinstance(raw, (str, int)):
        return 60
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 60


def _response_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("detail", response.text))
    except Exception:
        pass
    return response.text


class AVPAgent:
    """
    AI agent identity on Agent Veil Protocol.

    Manages Ed25519 keys, signs requests, and provides methods
    for all AVP operations: registration, attestation, and reputation.
    """

    def __init__(
        self,
        base_url: str,
        private_key: bytes,
        name: str = "agent",
        timeout: float = 15.0,
        rate_limit_retries: int = 1,
        rate_limit_retry_buffer: float = 1.0,
    ):
        """
        Initialize agent with existing private key.
        Use AVPAgent.create() or AVPAgent.load() instead of calling directly.
        """
        self._base_url = base_url.rstrip("/")
        self._private_key = private_key
        self._name = name
        self._timeout = timeout
        self._rate_limit_retries = max(0, rate_limit_retries)
        self._rate_limit_retry_buffer = max(0.0, rate_limit_retry_buffer)

        # Warn if using unencrypted HTTP for non-localhost connections
        if self._base_url.startswith("http://") and "localhost" not in self._base_url and "127.0.0.1" not in self._base_url:
            log.warning(
                "Using HTTP without TLS. Signatures and keys may be intercepted. "
                "Use https:// in production."
            )

        # Derive public key and DID
        signing_key = SigningKey(private_key)
        self._public_key = bytes(signing_key.verify_key)
        self._did = _public_key_to_did(self._public_key)
        self._is_registered = False
        self._is_verified = False
        self._saved_to_disk = False

    # === Factory methods ===

    @classmethod
    def create(cls, base_url: str = "", name: str = "agent", save: bool = True, mock: bool = False) -> "AVPAgent":
        """
        Create a new agent with fresh Ed25519 keys.

        Args:
            base_url: AVP server URL (e.g. "https://agentveil.dev"). Not needed if mock=True.
            name: Agent name (used for local key storage)
            save: Save keys to ~/.avp/agents/{name}.json
            mock: If True, return a mock agent that works without a server
        """
        if mock:
            from agentveil.mock import AVPMockAgent
            return AVPMockAgent.create(name=name)

        if not base_url:
            raise ValueError("base_url is required (or use mock=True for offline mode)")

        signing_key = SigningKey.generate()
        private_key = bytes(signing_key)
        agent = cls(base_url, private_key, name=name)
        if save:
            agent.save()
        else:
            log.warning(
                f"Agent {agent.did[:30]}... created with save=False. "
                f"Private key exists only in memory — if the process crashes before "
                f"register() or save(), this agent is lost. Use agent.private_key_hex "
                f"to back up, or agent.save() to persist."
            )
        log.info(f"Created new agent: {agent.did[:40]}...")
        return agent

    @classmethod
    def load(cls, base_url: str, name: str = "agent", passphrase: Optional[str] = None) -> "AVPAgent":
        """
        Load agent from saved keys.

        Args:
            base_url: AVP server URL
            name: Agent name (matches saved file)
            passphrase: Required if the saved file was encrypted with a passphrase

        Raises:
            FileNotFoundError: If no saved agent with this name
            ValueError: If file is encrypted but no passphrase provided
        """
        path = os.path.join(AGENTS_DIR, f"{name}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"No saved agent '{name}' at {path}")

        with open(path) as f:
            data = json.load(f)

        if data.get("encrypted"):
            if not passphrase:
                raise ValueError(
                    f"Agent '{name}' is encrypted. Provide passphrase to load."
                )
            from nacl.pwhash import argon2id
            from nacl.secret import SecretBox

            salt = bytes.fromhex(data["encryption_salt"])
            key = argon2id.kdf(
                SecretBox.KEY_SIZE,
                passphrase.encode(),
                salt,
                opslimit=argon2id.OPSLIMIT_MODERATE,
                memlimit=argon2id.MEMLIMIT_MODERATE,
            )
            box = SecretBox(key)
            encrypted = bytes.fromhex(data["private_key_encrypted"])
            private_key = bytes(box.decrypt(encrypted))
        else:
            private_key = bytes.fromhex(data["private_key_hex"])

        agent = cls(base_url, private_key, name=name)
        agent._is_registered = data.get("registered", False)
        agent._is_verified = data.get("verified", False)
        agent._saved_to_disk = True
        log.info(f"Loaded agent: {agent.did[:40]}...")
        return agent

    @classmethod
    def from_private_key(cls, base_url: str, private_key_hex: str, name: str = "agent") -> "AVPAgent":
        """Create agent from hex-encoded private key."""
        return cls(base_url, bytes.fromhex(private_key_hex), name=name)

    # === Properties ===

    @property
    def did(self) -> str:
        """Agent's DID (did:key:z6Mk...)."""
        return self._did

    @property
    def public_key_hex(self) -> str:
        """Agent's public key as hex string."""
        return self._public_key.hex()

    @property
    def private_key_hex(self) -> str:
        """Agent's private key as hex string. Use to back up key for later recovery via from_private_key()."""
        return self._private_key.hex()

    @property
    def is_registered(self) -> bool:
        return self._is_registered

    @property
    def is_verified(self) -> bool:
        return self._is_verified

    # === Key management ===

    def save(self, passphrase: Optional[str] = None) -> str:
        """
        Save agent keys to disk. Returns file path.

        Args:
            passphrase: If provided, encrypts the private key using NaCl SecretBox
                        with a key derived from the passphrase via scrypt.
                        If None, private key is stored as plaintext hex (0o600 permissions).
        """
        os.makedirs(AGENTS_DIR, exist_ok=True)
        path = os.path.join(AGENTS_DIR, f"{self._name}.json")

        data = {
            "name": self._name,
            "did": self._did,
            "public_key_hex": self._public_key.hex(),
            "registered": self._is_registered,
            "verified": self._is_verified,
            "base_url": self._base_url,
        }

        if passphrase:
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
            encrypted = box.encrypt(self._private_key)
            data["private_key_encrypted"] = encrypted.hex()
            data["encryption_salt"] = salt.hex()
            data["encrypted"] = True
        else:
            data["private_key_hex"] = self._private_key.hex()
            data["encrypted"] = False
            log.warning(
                "Saving private key unencrypted. Use save(passphrase='...') for encrypted storage."
            )

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(path, 0o600)  # Owner read/write only
        self._saved_to_disk = True
        return path

    # === HTTP helpers ===

    def _auth_headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        params: Optional[dict] = None,
    ) -> dict:
        """Build authenticated headers for a request."""
        return build_auth_header(
            self._private_key,
            self._did,
            method,
            path,
            body,
            params=params,
        )

    def _handle_response(self, response: httpx.Response) -> dict:
        """Parse response and raise appropriate exceptions."""
        if response.status_code in SUCCESS_STATUS_CODES:
            try:
                return response.json()
            except (json.JSONDecodeError, ValueError):
                raise AVPServerError(
                    f"Server returned non-JSON response (status {response.status_code}): "
                    f"{response.text[:200]}",
                    response.status_code, response.text[:200],
                )

        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text

        if response.status_code == 401:
            raise AVPAuthError(f"Authentication failed: {detail}", 401, detail)
        elif response.status_code == 403:
            raise AVPAuthError(f"Forbidden: {detail}", 403, detail)
        elif response.status_code == 404:
            raise AVPNotFoundError(f"Not found: {detail}", 404, detail)
        elif response.status_code == 409:
            raise AVPValidationError(f"Conflict: {detail}", 409, detail)
        elif response.status_code == 429:
            retry_after = _parse_retry_after(response)
            raise AVPRateLimitError(f"Rate limited: {detail}", retry_after=retry_after)
        elif response.status_code == 400:
            raise AVPValidationError(f"Validation error: {detail}", 400, detail)
        elif response.status_code >= 500:
            raise AVPServerError(f"Server error: {detail}", response.status_code, detail)
        else:
            raise AVPError(f"Unexpected error ({response.status_code}): {detail}", response.status_code, detail)

    def _handle_raw_json_response(self, response: httpx.Response) -> str:
        """Return an exact JSON response body after normal status/error handling.

        Execution and human-approval receipt endpoints return signed JCS JSON
        where the exact response bytes are the proof artifact. This helper
        validates that the body is JSON but returns ``response.text`` unchanged.
        """
        if response.status_code in SUCCESS_STATUS_CODES:
            try:
                response.json()
            except (json.JSONDecodeError, ValueError):
                raise AVPServerError(
                    f"Server returned non-JSON response (status {response.status_code}): "
                    f"{response.text[:200]}",
                    response.status_code, response.text[:200],
                )
            return response.text
        self._handle_response(response)
        raise AVPServerError("unreachable response handling state")

    def _request_with_rate_limit_retry(self, send_request) -> httpx.Response:
        attempts = 0
        while True:
            response = send_request()
            if response.status_code != 429 or attempts >= self._rate_limit_retries:
                return response

            retry_after = _parse_retry_after(response)
            sleep_for = max(0, retry_after) + self._rate_limit_retry_buffer
            log.warning("AVP API rate-limited request; retrying in %.1fs", sleep_for)
            time.sleep(sleep_for)
            attempts += 1

    def _get_public_json(self, path: str, params: Optional[dict] = None) -> dict:
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = self._request_with_rate_limit_retry(lambda: c.get(path, params=params))
            return self._handle_response(r)

    def _post_json(
        self,
        path: str,
        body_data: dict,
        params: Optional[dict] = None,
    ) -> dict:
        body = json.dumps(body_data).encode()
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            def send_request():
                headers = self._auth_headers("POST", path, body, params=params)
                return c.post(path, content=body, params=params, headers=headers)

            r = self._request_with_rate_limit_retry(send_request)
            return self._handle_response(r)

    def _post_raw_json(
        self,
        path: str,
        body_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> str:
        body = b"" if body_data is None else json.dumps(body_data).encode()
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            def send_request():
                headers = self._auth_headers("POST", path, body, params=params)
                return c.post(path, content=body, params=params, headers=headers)

            r = self._request_with_rate_limit_retry(send_request)
            return self._handle_raw_json_response(r)

    def _get_json(self, path: str, params: Optional[dict] = None) -> dict:
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            def send_request():
                headers = self._auth_headers("GET", path, params=params)
                return c.get(path, params=params, headers=headers)

            r = self._request_with_rate_limit_retry(send_request)
            return self._handle_response(r)

    def _get_raw_json(self, path: str, params: Optional[dict] = None) -> str:
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            def send_request():
                headers = self._auth_headers("GET", path, params=params)
                return c.get(path, params=params, headers=headers)

            r = self._request_with_rate_limit_retry(send_request)
            return self._handle_raw_json_response(r)

    def integration_preflight(self) -> IntegrationPreflightReport:
        """Check integration readiness without mutating backend state.

        The preflight uses a public health check, public agent lookup, and one
        signed auth-only read (`GET /v1/remediation/cases`) with no query
        parameters. It does not call Runtime Gate and does not approve or
        execute actions.
        """

        def report(
            ready: bool,
            status: str,
            next_action: str,
            *,
            api_reachable: bool = False,
            registered: Optional[bool] = None,
            verified: Optional[bool] = None,
            agent_status: Optional[str] = None,
            successor_did: Optional[str] = None,
            signed_request_ok: bool = False,
            status_code: Optional[int] = None,
            detail: Optional[str] = None,
            retry_after: Optional[int] = None,
        ) -> IntegrationPreflightReport:
            return IntegrationPreflightReport(
                ready=ready,
                status=status,  # type: ignore[arg-type]
                next_action=next_action,
                did=self._did,
                base_url=self._base_url,
                api_reachable=api_reachable,
                registered=registered,
                verified=verified,
                agent_status=agent_status,
                successor_did=successor_did,
                signed_request_ok=signed_request_ok,
                status_code=status_code,
                detail=detail,
                retry_after=retry_after,
            )

        registered: Optional[bool] = None
        verified: Optional[bool] = None
        agent_status: Optional[str] = None
        successor_did: Optional[str] = None

        try:
            with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
                health = c.get("/v1/health")
                if health.status_code >= 500:
                    return report(
                        False,
                        "backend_or_config_unavailable",
                        "Check AVP API health and backend configuration before retrying.",
                        api_reachable=True,
                        status_code=health.status_code,
                        detail=_response_detail(health),
                    )
                if health.status_code not in SUCCESS_STATUS_CODES:
                    return report(
                        False,
                        "unexpected_response",
                        "Check base_url and AVP API health endpoint.",
                        api_reachable=True,
                        status_code=health.status_code,
                        detail=_response_detail(health),
                    )
                try:
                    health_data = health.json()
                except Exception:
                    health_data = {}
                if isinstance(health_data, dict) and health_data.get("status") == "degraded":
                    return report(
                        False,
                        "api_degraded",
                        "AVP API is reachable but degraded; wait for backend health to recover.",
                        api_reachable=True,
                        status_code=health.status_code,
                        detail=str(health_data),
                    )

                agent_lookup = c.get(f"/v1/agents/{self._did}")
                if agent_lookup.status_code in SUCCESS_STATUS_CODES:
                    try:
                        data = agent_lookup.json()
                    except Exception:
                        return report(
                            False,
                            "unexpected_response",
                            "Agent lookup returned malformed JSON; check AVP API response handling before proceeding.",
                            api_reachable=True,
                            status_code=agent_lookup.status_code,
                            detail=agent_lookup.text[:200],
                        )
                    registered = True
                    verified = bool(data.get("is_verified"))
                    agent_status = data.get("status")
                    successor_raw = data.get("successor_did")
                    if isinstance(successor_raw, str) and successor_raw:
                        successor_did = successor_raw
                    normalized_status = (
                        agent_status.lower()
                        if isinstance(agent_status, str)
                        else ""
                    )
                    if normalized_status == "suspended":
                        return report(
                            False,
                            "agent_suspended",
                            "This agent DID is suspended; stop using it until it is restored by an authorized operator.",
                            api_reachable=True,
                            registered=True,
                            verified=verified,
                            agent_status=agent_status,
                            status_code=agent_lookup.status_code,
                        )
                    if normalized_status == "revoked":
                        return report(
                            False,
                            "agent_revoked",
                            "This agent DID is revoked; stop using it permanently and use a different verified DID.",
                            api_reachable=True,
                            registered=True,
                            verified=verified,
                            agent_status=agent_status,
                            status_code=agent_lookup.status_code,
                        )
                    if normalized_status == "succeeded":
                        if successor_did is not None:
                            return report(
                                False,
                                "agent_migrated",
                                "This agent DID has migrated; use the successor DID for future signed requests.",
                                api_reachable=True,
                                registered=True,
                                verified=verified,
                                agent_status=agent_status,
                                successor_did=successor_did,
                                status_code=agent_lookup.status_code,
                            )
                elif agent_lookup.status_code == 404:
                    registered = False
                    verified = False
                elif agent_lookup.status_code >= 500:
                    return report(
                        False,
                        "backend_or_config_unavailable",
                        "Check AVP API health and backend configuration before retrying.",
                        api_reachable=True,
                        status_code=agent_lookup.status_code,
                        detail=_response_detail(agent_lookup),
                    )

                signed_path = "/v1/remediation/cases"
                signed = c.get(
                    signed_path,
                    headers=self._auth_headers("GET", signed_path),
                )
        except httpx.RequestError as exc:
            return report(
                False,
                "api_unreachable",
                "Check base_url, network connectivity, and TLS configuration.",
                detail=str(exc),
            )

        if signed.status_code in SUCCESS_STATUS_CODES:
            if registered is False:
                return report(
                    False,
                    "unregistered",
                    "Register and verify this DID before the first controlled action.",
                    api_reachable=True,
                    registered=False,
                    verified=False,
                    signed_request_ok=True,
                    status_code=signed.status_code,
                )
            if verified is False:
                return report(
                    False,
                    "unverified_or_forbidden",
                    "Verify the agent DID before the first controlled action.",
                    api_reachable=True,
                    registered=registered,
                    verified=False,
                    agent_status=agent_status,
                    signed_request_ok=True,
                    status_code=signed.status_code,
                )
            return report(
                True,
                "ready",
                "Ready for controlled_action(...).",
                api_reachable=True,
                registered=True if registered is None else registered,
                verified=True if verified is None else verified,
                agent_status=agent_status,
                signed_request_ok=True,
                status_code=signed.status_code,
            )

        detail = _response_detail(signed)
        if signed.status_code == 401:
            if registered is False:
                status = "unregistered"
                next_action = "Register and verify this DID before the first controlled action."
            elif "Nonce already used" in detail:
                status = "nonce_replay"
                next_action = "Retry with a fresh request; do not reuse signed headers or nonces."
            else:
                status = "signature_invalid"
                next_action = "Check that the local key matches the registered DID, then verify clock skew and signature handling."
            return report(
                False,
                status,
                next_action,
                api_reachable=True,
                registered=registered,
                verified=verified,
                agent_status=agent_status,
                successor_did=successor_did,
                status_code=401,
                detail=detail,
            )
        if signed.status_code == 403:
            status = "unverified_or_forbidden"
            next_action = "Verify the agent DID and check whether it is allowed for this read path."
            if "Agent suspended" in detail:
                status = "agent_suspended"
                next_action = "This agent DID is suspended; stop using it until it is restored by an authorized operator."
            elif "Agent revoked" in detail:
                status = "agent_revoked"
                next_action = "This agent DID is revoked; stop using it permanently and use a different verified DID."
            elif "migrated" in detail or "successor_did" in detail:
                status = "agent_migrated"
                next_action = "This agent DID has migrated; use the successor DID for future signed requests."
                try:
                    body = signed.json()
                except Exception:
                    body = {}
                found_successor = body.get("successor_did") if isinstance(body, dict) else None
                if isinstance(found_successor, str) and found_successor:
                    successor_did = found_successor
            elif "Agent not verified" in detail:
                next_action = "Verify the agent DID before the first controlled action."
            return report(
                False,
                status,
                next_action,
                api_reachable=True,
                registered=registered,
                verified=verified,
                agent_status=agent_status,
                successor_did=successor_did,
                status_code=403,
                detail=detail,
            )
        if signed.status_code == 429:
            retry_after = _parse_retry_after(signed)
            return report(
                False,
                "rate_limited",
                f"Wait {retry_after} seconds before retrying; avoid aggressive polling.",
                api_reachable=True,
                registered=registered,
                verified=verified,
                agent_status=agent_status,
                successor_did=successor_did,
                status_code=429,
                detail=detail,
                retry_after=retry_after,
            )
        if signed.status_code >= 500:
            return report(
                False,
                "backend_or_config_unavailable",
                "AVP backend or proof-signing configuration is unavailable; do not retry aggressively.",
                api_reachable=True,
                registered=registered,
                verified=verified,
                agent_status=agent_status,
                successor_did=successor_did,
                status_code=signed.status_code,
                detail=detail,
            )
        return report(
            False,
            "unexpected_response",
            "Inspect status_code and detail before proceeding.",
            api_reachable=True,
            registered=registered,
            verified=verified,
            agent_status=agent_status,
            successor_did=successor_did,
            status_code=signed.status_code,
            detail=detail,
        )

    # === Registration ===

    def register(
        self,
        display_name: Optional[str] = None,
        capabilities: Optional[list[str]] = None,
        endpoint_url: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> dict:
        """
        Register agent on AVP and verify key ownership.
        Does register + PoW + verify in one call and returns as soon as
        verification succeeds.

        SDK v0.6.0: this call NO LONGER blocks on onboarding completion.
        If capabilities are provided, the agent card is auto-created and the
        server starts the onboarding pipeline in the background. Use
        `agent.get_onboarding_status()` to poll, `agent.wait_for_onboarding()`
        to block until terminal state, or
        `agent.auto_answer_onboarding_challenge()` to have the SDK reply to
        the challenge automatically (previous pre-v0.6.0 implicit behavior).

        Args:
            display_name: Optional human-readable name
            capabilities: Agent capabilities (e.g. ["code_review", "testing"])
            endpoint_url: URL where this agent can be reached
            provider: LLM provider (e.g. "anthropic", "openai")

        Returns:
            dict with 'did', 'agnet_address', and 'onboarding_pending' (bool)
        """
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            # Step 1: Register (with optional card data)
            body = {
                "public_key_hex": self.public_key_hex,
                "display_name": display_name or self._name,
            }
            if capabilities:
                body["capabilities"] = capabilities
            if endpoint_url:
                body["endpoint_url"] = endpoint_url
            if provider:
                body["provider"] = provider

            r = c.post("/v1/agents/register", json=body)
            data = self._handle_response(r)

            # Validate required fields from registration response
            for field in ("challenge", "pow_challenge", "pow_difficulty"):
                if field not in data:
                    raise AVPServerError(
                        f"Registration response missing required field '{field}'",
                        200, str(data),
                    )
            challenge = data["challenge"]

            # Step 2: Solve Proof-of-Work puzzle
            pow_challenge = data["pow_challenge"]
            pow_difficulty = data["pow_difficulty"]
            log.info(f"Solving PoW (difficulty={pow_difficulty} bits)...")
            pow_nonce = solve_pow(pow_challenge, pow_difficulty)
            log.info(f"PoW solved: nonce={pow_nonce}")

            # Step 3: Sign challenge and verify
            signing_key = SigningKey(self._private_key)
            signed = signing_key.sign(challenge.encode())
            sig_hex = signed.signature.hex()

            r = c.post("/v1/agents/verify", json={
                "did": self._did,
                "challenge": challenge,
                "signature_hex": sig_hex,
                "pow_nonce": pow_nonce,
            })
            verify_data = self._handle_response(r)

        self._is_registered = True
        self._is_verified = True
        self.save()

        # SDK v0.6.0: register() NO LONGER blocks on onboarding completion.
        # Server runs onboarding in the background after /verify.
        # Clients that want LLM-assisted challenge auto-answer must call
        # auto_answer_onboarding_challenge() explicitly.
        # Clients that want to block until onboarding finishes must call
        # wait_for_onboarding() explicitly.
        onboarding_started = verify_data.get("onboarding_started", False)
        onboarding_pending = verify_data.get("onboarding_pending", onboarding_started)
        next_step = verify_data.get("next_step", "")

        if onboarding_pending:
            log.info(
                f"Registered and verified. Onboarding running in background for "
                f"{self._did[:40]}...  Poll onboarding_status() or call "
                f"wait_for_onboarding() to observe completion."
            )
        else:
            log.info(
                f"Registered and verified. Onboarding NOT started "
                f"(no capabilities provided). Call publish_card(...) to trigger. "
                f"Server hint: {next_step}"
            )

        # Expose the pending flag to callers inspecting the return value.
        data["onboarding_pending"] = onboarding_pending
        return data

    def auto_answer_onboarding_challenge(self, max_wait: float = 30.0) -> Optional[dict]:
        """
        Opt-in helper: poll for the onboarding challenge and auto-submit a stock answer.

        Previously wired into register() implicitly — as of SDK v0.6.0 this
        is an explicit, opt-in call. Safe to ignore for integrators that
        answer the challenge themselves.

        Best-effort, non-fatal: returns challenge result dict on success,
        or None if no challenge is available / an error occurred.
        Challenge generation involves an LLM call and may take 5-15s.
        """
        return self._auto_handle_onboarding_challenge(max_wait=max_wait)

    def wait_for_onboarding(
        self, timeout: float = 60.0, poll_interval: float = 2.0
    ) -> dict:
        """
        Opt-in helper: block until onboarding reaches a terminal state.

        Polls GET /v1/onboarding/{did} until status is one of
        'completed', 'failed', or 'not_started', or until the timeout is hit.

        Returns the final onboarding status dict. Raises TimeoutError if
        no terminal state is reached before the timeout.

        IMPORTANT: `not_started` is treated as a terminal state here because
        it means no session row exists, so there is nothing to wait for —
        NOT because onboarding succeeded. Callers MUST inspect the returned
        `status` explicitly. Only `"completed"` is a success outcome;
        `"failed"` and `"not_started"` each need their own handling.
        """
        import time as _time

        deadline = _time.monotonic() + timeout
        last: dict = {}
        terminal = {"completed", "failed", "not_started"}
        while _time.monotonic() < deadline:
            try:
                last = self.get_onboarding_status()
            except Exception as e:
                log.debug(f"wait_for_onboarding: status fetch failed ({e}); retrying")
                _time.sleep(poll_interval)
                continue
            if (last.get("status") or "").lower() in terminal:
                return last
            _time.sleep(poll_interval)
        raise TimeoutError(
            f"Onboarding did not reach a terminal state within {timeout}s. "
            f"Last status: {last.get('status')!r}"
        )

    def _auto_handle_onboarding_challenge(self, max_wait: float = 30.0) -> Optional[dict]:
        """
        Deprecated internal alias (SDK v0.6.0). Prefer
        auto_answer_onboarding_challenge().

        Poll for an onboarding challenge and auto-submit an answer.
        Best-effort, non-fatal: if anything fails, registration still succeeds.
        Challenge generation involves LLM call and may take 5-15s after Stage 1.
        """
        import time
        import asyncio

        def _sleep(seconds: float) -> None:
            """Sleep without blocking event loop if one is running."""
            try:
                loop = asyncio.get_running_loop()
                # We're inside an event loop — don't block it
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    loop.run_in_executor(pool, time.sleep, seconds)
            except RuntimeError:
                # No event loop — safe to block
                time.sleep(seconds)

        # Initial delay: Stage 1 runs fast but LLM challenge generation takes 5-10s
        _sleep(3.0)

        deadline = time.monotonic() + max_wait

        try:
            challenge = None
            while time.monotonic() < deadline:
                challenge = self.get_onboarding_challenge()
                if challenge and challenge.get("status") == "awaiting_response":
                    break
                _sleep(2.0)

            if not challenge or challenge.get("status") != "awaiting_response":
                log.debug("Auto-challenge: no active challenge found, skipping")
                return None

            challenge_id = challenge.get("challenge_id", "")
            challenge_text = challenge.get("challenge_text", "")

            if not challenge_id or not challenge_text:
                return None

            answer = (
                f"Responding to challenge: {challenge_text[:200]}\n\n"
                f"I am an AI agent with capabilities in this domain. "
                f"This is an automated response from the AVP SDK register() flow. "
                f"My capabilities are registered in my agent card."
            )

            result = self.submit_challenge_answer(challenge_id, answer)
            log.info(
                f"Auto-challenge: score={result.get('score', '?')}, "
                f"passed={result.get('passed', '?')}"
            )
            return result
        except Exception as e:
            log.debug(f"Auto-challenge handling skipped: {e}")
            return None

    # === DID Succession (key rotation) ===

    def migrate(self, new_agent: "AVPAgent") -> dict:
        """
        Migrate this agent's identity to a new DID (key rotation).

        Both this agent (old key) and new_agent (new key) must sign the
        migration message. Reputation transfers from old DID to new DID
        with a small decay factor (server default 0.9x). Old DID becomes
        status=SUCCEEDED and can no longer be used for authenticated calls.

        After migration, continue using new_agent for all operations.

        Args:
            new_agent: A fresh AVPAgent (created with AVPAgent.create()),
                       not yet registered on the server.

        Returns:
            Migration result dict with old_did, new_did, old_score, new_score,
            decay_factor, cooldown_until, migrated_at.

        Raises:
            AVPError: If the server rejects the migration (409, 429, 403, etc.)
        """
        from datetime import datetime, timezone

        if new_agent.did == self._did:
            raise AVPValidationError("new_agent must have a different DID")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        message = f"avp:migrate:v1:{self._did}:{new_agent.did}:{timestamp}".encode()

        old_signing_key = SigningKey(self._private_key)
        new_signing_key = SigningKey(new_agent._private_key)
        signature_old = old_signing_key.sign(message).signature.hex()
        signature_new = new_signing_key.sign(message).signature.hex()

        body = {
            "old_did": self._did,
            "new_did": new_agent.did,
            "reason": "key_rotation",
            "signature_old": signature_old,
            "signature_new": signature_new,
            "timestamp": timestamp,
        }

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/agents/migrate", json=body)
            result = self._handle_response(r)

        # Update new agent state to match successful migration
        new_agent._is_registered = True
        new_agent._is_verified = True

        log.info(
            f"DID migration successful: {self._did[:30]}... → "
            f"{new_agent.did[:30]}... "
            f"(score {result.get('old_score', 0):.3f} → {result.get('new_score', 0):.3f})"
        )
        return result

    # === Agent Cards ===

    def publish_card(
        self,
        capabilities: list[str],
        provider: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        signature: Optional[str] = None,
    ) -> dict:
        """
        Publish or update agent's capability card.

        Args:
            capabilities: List of capabilities (e.g. ["code_review", "testing"])
            provider: LLM provider (e.g. "anthropic", "openai")
            endpoint_url: URL where this agent can be reached
            signature: Optional card signature
        """
        body_data = {"capabilities": capabilities}
        if provider:
            body_data["provider"] = provider
        if endpoint_url:
            body_data["endpoint_url"] = endpoint_url
        if signature:
            body_data["signature"] = signature

        return self._post_json("/v1/cards", body_data)

    def search_agents(
        self,
        capability: Optional[str] = None,
        provider: Optional[str] = None,
        min_reputation: Optional[float] = None,
        limit: int = 20,
    ) -> list[dict]:
        """Search for agents by capability, provider, or minimum reputation."""
        params = {"limit": limit}
        if capability:
            params["capability"] = capability
        if provider:
            params["provider"] = provider
        if min_reputation is not None:
            params["min_reputation"] = min_reputation

        results = self._get_public_json("/v1/cards", params=params)
        if not isinstance(results, list):
            return results

        normalized = []
        for item in results:
            if isinstance(item, dict) and "did" not in item and "agent_did" in item:
                item = {**item, "did": item["agent_did"]}
            normalized.append(item)
        return normalized

    # === Attestations ===

    def attest(
        self,
        to_did: str,
        outcome: str = "positive",
        weight: float = 1.0,
        context: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        is_private: bool = False,
        interaction_id: Optional[str] = None,
    ) -> dict:
        """
        Submit an attestation about another agent.

        Args:
            to_did: DID of agent being rated
            outcome: "positive", "negative", or "neutral"
            weight: Confidence weight (0.0 to 1.0)
            context: Interaction type (e.g. "task_completion"). REQUIRED
                when `outcome="negative"`.
            evidence_hash: SHA-256 hex of interaction log (lowercase, 64 chars).
                REQUIRED when `outcome="negative"`. The server rejects
                negative attestations without justification — both `context`
                and `evidence_hash` must be supplied together.
            is_private: If True, attestation is not publicly visible
            interaction_id: Optional UUID linking to a specific interaction

        Returns:
            Attestation details
        """
        if outcome not in ("positive", "negative", "neutral"):
            raise AVPValidationError(f"Invalid outcome: {outcome}. Must be positive/negative/neutral")
        if not 0.0 <= weight <= 1.0:
            raise AVPValidationError(f"Weight must be 0.0-1.0, got {weight}")
        # Mirror server policy (app/api/v1/attestations.py): negative
        # attestations require both context and a valid SHA-256 evidence_hash.
        # Validate client-side so callers fail fast with a clear message
        # instead of chasing a 400 from the server.
        if outcome == "negative":
            missing = []
            if not context:
                missing.append("context")
            if not evidence_hash:
                missing.append("evidence_hash")
            if missing:
                raise AVPValidationError(
                    f"Negative attestations require {' and '.join(missing)}. "
                    f"Pass context='task_completion' (or similar) and "
                    f"evidence_hash=<sha256 hex of the interaction log>."
                )
            import re as _re
            if not _re.match(r"^[a-f0-9]{64}$", evidence_hash):
                raise AVPValidationError(
                    "evidence_hash must be lowercase SHA-256 hex (64 chars). "
                    "Got: " + (evidence_hash[:16] + "..." if len(evidence_hash) > 16 else evidence_hash)
                )

        # Build and sign attestation payload
        attest_payload = json.dumps({
            "to": to_did,
            "outcome": outcome,
            "weight": weight,
            "context": context or "",
            "evidence_hash": evidence_hash or "",
        }, sort_keys=True, separators=(",", ":")).encode()

        signing_key = SigningKey(self._private_key)
        signed = signing_key.sign(attest_payload)
        sig_hex = signed.signature.hex()

        body_data = {
            "to_agent_did": to_did,
            "outcome": outcome,
            "weight": weight,
            "signature": sig_hex,
        }
        if context:
            body_data["context"] = context
        if evidence_hash:
            body_data["evidence_hash"] = evidence_hash
        if is_private:
            body_data["is_private"] = True
        if interaction_id:
            body_data["interaction_id"] = interaction_id

        body = json.dumps(body_data).encode()
        headers = self._auth_headers("POST", "/v1/attestations", body)

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/attestations", content=body, headers=headers)
            return self._handle_response(r)

    def attest_batch(self, attestations: list[dict]) -> dict:
        """
        Submit multiple attestations in a single request (up to 50).

        Each attestation is validated independently — partial success is possible.

        Args:
            attestations: List of dicts, each with:
                - to_did (str): Target agent DID
                - outcome (str): "positive", "negative", or "neutral"
                - weight (float): 0.0-1.0 (default 1.0)
                - context (str, optional): Interaction type
                - evidence_hash (str, optional): SHA256 of evidence
                - is_private (bool, optional): Default False
                - interaction_id (str, optional): UUID

        Returns:
            dict with total, succeeded, failed, results
        """
        if not attestations or len(attestations) > 50:
            raise AVPValidationError("Batch must contain 1-50 attestations")

        signing_key = SigningKey(self._private_key)
        items = []

        for att in attestations:
            to_did = att["to_did"]
            outcome = att.get("outcome", "positive")
            weight = att.get("weight", 1.0)
            context = att.get("context")
            evidence_hash = att.get("evidence_hash")

            if outcome not in ("positive", "negative", "neutral"):
                raise AVPValidationError(f"Invalid outcome: {outcome}")
            if not 0.0 <= weight <= 1.0:
                raise AVPValidationError(f"Weight must be 0.0-1.0, got {weight}")

            # Sign each attestation
            attest_payload = json.dumps({
                "to": to_did,
                "outcome": outcome,
                "weight": weight,
                "context": context or "",
                "evidence_hash": evidence_hash or "",
            }, sort_keys=True, separators=(",", ":")).encode()
            signed = signing_key.sign(attest_payload)

            item = {
                "to_agent_did": to_did,
                "outcome": outcome,
                "weight": weight,
                "signature": signed.signature.hex(),
            }
            if context:
                item["context"] = context
            if evidence_hash:
                item["evidence_hash"] = evidence_hash
            if att.get("is_private"):
                item["is_private"] = True
            if att.get("interaction_id"):
                item["interaction_id"] = att["interaction_id"]
            items.append(item)

        body = json.dumps({"attestations": items}).encode()
        headers = self._auth_headers("POST", "/v1/attestations/batch", body)

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/attestations/batch", content=body, headers=headers)
            return self._handle_response(r)

    # === Reputation ===

    def get_reputation(self, did: Optional[str] = None) -> dict:
        """
        Get reputation score for an agent.

        Args:
            did: Agent DID (defaults to self)

        Returns:
            dict with score, confidence, interpretation
        """
        target = did or self._did
        return self._get_public_json(f"/v1/reputation/{target}")

    def can_trust(
        self,
        did: str,
        min_tier: str = "trusted",
        task_type: Optional[str] = None,
    ) -> dict:
        """
        Advisory trust decision: should I delegate a task to this agent?

        Checks if the agent's reputation tier meets the minimum requirement
        and whether risk level is acceptable. Returns a decision with
        explanation — NOT a guarantee.

        Args:
            did: Target agent DID
            min_tier: Minimum required tier ("newcomer", "basic", "trusted", "elite")
            task_type: Optional task category ("code_quality", "task_completion", etc.)

        Returns:
            dict with allowed, score, tier, risk_level, reason, disclaimer
        """
        params: dict[str, str] = {"min_tier": min_tier}
        if task_type:
            params["task_type"] = task_type

        return self._get_public_json(f"/v1/reputation/{did}/trust-check", params=params)

    def get_reputation_bulk(self, dids: list[str]) -> dict:
        """
        Get reputation scores for multiple agents in one request (up to 100).

        Args:
            dids: List of agent DIDs

        Returns:
            dict with total, found, results (list of {did, found, reputation, error})
        """
        if not dids or len(dids) > 100:
            raise AVPValidationError("Bulk query requires 1-100 DIDs")

        dids_param = ",".join(dids)
        return self._get_public_json("/v1/reputation/bulk", params={"dids": dids_param})

    def get_reputation_tracks(self, did: Optional[str] = None) -> dict:
        """
        Get specialized reputation scores by track (category).

        Returns per-track scores derived from the attestation `context` field:
        code_quality, task_completion, data_accuracy, negotiation, general.

        Args:
            did: Agent DID (defaults to self)

        Returns:
            dict with did and tracks: {track_name: {score, confidence, attestations}}
        """
        target = did or self._did
        return self._get_public_json(f"/v1/reputation/{target}/tracks")

    def get_audit_trail(
        self,
        did: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """Fetch public audit trail entries for an agent DID."""
        target = did or self._did
        result = self._get_public_json(
            f"/v1/audit/{target}",
            params={"limit": limit, "offset": offset},
        )
        if not isinstance(result, list):
            raise AVPServerError(
                f"Audit trail response must be a list, got {type(result).__name__}",
                200,
                str(result)[:200],
            )
        return result

    # === Runtime Control ===

    def runtime_evaluate(
        self,
        action: str,
        resource: str,
        environment: str,
        delegation_receipt: dict,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
    ) -> dict:
        """
        Evaluate whether this agent may perform one action right now.

        The agent DID is always derived from this SDK identity; callers cannot
        override it. The returned decision is one of ALLOW, BLOCK, or
        WAITING_FOR_HUMAN_APPROVAL.
        """
        body_data = {
            "agent_did": self._did,
            "action": action,
            "resource": resource,
            "environment": environment,
            "receipt": delegation_receipt,
        }
        if amount is not None:
            body_data["amount"] = amount
        if currency is not None:
            body_data["currency"] = currency
        return self._post_json("/v1/runtime/evaluate", body_data)

    def get_runtime_decision(self, audit_id: str) -> dict:
        """Fetch this agent's Runtime Gate decision by audit_id."""
        return self._get_json(f"/v1/runtime/decisions/{audit_id}")

    def get_decision_receipt(self, audit_id: str) -> str:
        """
        Fetch the exact signed Runtime Gate DecisionReceipt JSON text.

        Pass this exact string to ``build_proof_packet(...)``; parsing and
        re-serializing changes the signed bytes.
        """
        return self._get_raw_json(f"/v1/runtime/decisions/{audit_id}/receipt")

    def execute(
        self,
        audit_id: str,
        action: str,
        resource: str,
        environment: str,
        params: Optional[dict] = None,
        approval_id: Optional[str] = None,
    ) -> str:
        """
        Execute an approved Runtime Gate decision.

        Returns the exact signed execution receipt JSON text. Keep this string
        for offline proof; parsing and re-serializing changes the bytes.
        """
        body_data = {
            "audit_id": audit_id,
            "action": action,
            "resource": resource,
            "environment": environment,
            "params": params or {},
        }
        if approval_id is not None:
            body_data["approval_id"] = approval_id
        return self._post_raw_json("/v1/execute", body_data)

    def get_execution_receipt(self, receipt_id: str) -> str:
        """Fetch the exact signed execution receipt JSON text."""
        return self._get_raw_json(f"/v1/execution/receipts/{receipt_id}")

    # === Human Approval ===

    def create_approval(
        self,
        audit_id: str,
        delegation_receipt: dict,
        expires_in_seconds: int = 3600,
    ) -> dict:
        """Create or fetch a human approval request for a WAITING decision."""
        body_data = {
            "audit_id": audit_id,
            "delegation_receipt": delegation_receipt,
            "expires_in_seconds": expires_in_seconds,
        }
        return self._post_json("/v1/human-approvals", body_data)

    def get_approval(self, approval_id: str) -> dict:
        """Fetch a human approval request visible to this agent."""
        return self._get_json(f"/v1/human-approvals/{approval_id}")

    def approve(self, approval_id: str) -> str:
        """
        Approve a human approval request as the principal.

        Returns the exact signed approval receipt JSON text.
        """
        return self._post_raw_json(f"/v1/human-approvals/{approval_id}/approve")

    def deny(self, approval_id: str, reason: Optional[str] = None) -> str:
        """
        Deny a human approval request as the principal.

        Returns the exact signed denial receipt JSON text.
        """
        body_data = {"reason": reason} if reason is not None else None
        return self._post_raw_json(f"/v1/human-approvals/{approval_id}/deny", body_data)

    # === Governance ===

    def create_governance_policy(self, name: str, rules_jsonb: dict) -> dict:
        """Create a DRAFT governance policy owned by this agent."""
        return self._post_json(
            "/v1/governance/policies",
            {"name": name, "rules_jsonb": rules_jsonb},
        )

    def get_governance_policy(self, policy_id: str) -> dict:
        """Fetch this agent's governance policy by id."""
        return self._get_json(f"/v1/governance/policies/{policy_id}")

    def activate_governance_policy(self, policy_id: str) -> dict:
        """Activate one of this agent's governance policies."""
        return self._post_json(f"/v1/governance/policies/{policy_id}/activate", {})

    def create_governance_risk_event(
        self,
        target_agent_did: str,
        event_type: str,
        severity: str,
        occurred_at: str,
        evidence_hash: Optional[str] = None,
    ) -> dict:
        """Record a governance risk event. reporter_did is server-derived."""
        body_data = {
            "target_agent_did": target_agent_did,
            "event_type": event_type,
            "severity": severity,
            "occurred_at": occurred_at,
        }
        if evidence_hash is not None:
            body_data["evidence_hash"] = evidence_hash
        return self._post_json("/v1/governance/risk-events", body_data)

    # === Remediation ===

    def create_remediation_case(
        self,
        case_type: str,
        reason: str,
        category: str,
        evidence_hash: Optional[str] = None,
        **references,
    ) -> dict:
        """
        Open a remediation case.

        Pass exactly the immutable reference required by the case type, such as
        execution_receipt_id, approval_id, attestation_id, or
        governance_risk_event_id. Party DIDs are server-derived.
        """
        body_data = {
            "case_type": case_type,
            "reason": reason,
            "category": category,
        }
        if evidence_hash is not None:
            body_data["evidence_hash"] = evidence_hash
        allowed_references = {
            "execution_receipt_id",
            "approval_id",
            "runtime_gate_audit_id",
            "attestation_id",
            "attestation_dispute_id",
            "governance_risk_event_id",
            "arbitrator_did",
        }
        for key, value in references.items():
            if key not in allowed_references:
                raise AVPValidationError(f"Unknown remediation reference field: {key}")
            if value is not None:
                body_data[key] = value
        return self._post_json("/v1/remediation/cases", body_data)

    def list_remediation_cases(
        self,
        role: str = "party",
        status: Optional[str] = None,
        case_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """List remediation cases visible to this agent."""
        params = {"role": role, "limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        if case_type is not None:
            params["case_type"] = case_type
        return self._get_json("/v1/remediation/cases", params=params)

    def get_remediation_case(self, case_id: str) -> dict:
        """Fetch one remediation case visible to this agent."""
        return self._get_json(f"/v1/remediation/cases/{case_id}")

    def add_remediation_evidence(
        self,
        case_id: str,
        reference_type: str,
        evidence_hash: Optional[str] = None,
        reference_uri: Optional[str] = None,
        summary_jsonb: Optional[dict] = None,
    ) -> dict:
        """Append evidence metadata to an open remediation case."""
        body_data = {"reference_type": reference_type}
        if evidence_hash is not None:
            body_data["evidence_hash"] = evidence_hash
        if reference_uri is not None:
            body_data["reference_uri"] = reference_uri
        if summary_jsonb is not None:
            body_data["summary_jsonb"] = summary_jsonb
        return self._post_json(f"/v1/remediation/cases/{case_id}/evidence", body_data)

    # === Controlled Action Orchestration ===

    def controlled_action(
        self,
        action: str,
        resource: str,
        environment: str,
        delegation_receipt: dict,
        params: Optional[dict] = None,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
        approval_expires_in_seconds: int = 3600,
    ) -> ControlledActionOutcome:
        """
        Run the high-level controlled-action flow without bypassing AVP.

        Returns a ControlledActionOutcome with status:
          - executed
          - approval_required
          - blocked

        Human approval is never auto-approved. If approval is required, call
        execute_after_approval(...) after the principal approves the request.
        """
        decision = self.runtime_evaluate(
            action=action,
            resource=resource,
            environment=environment,
            delegation_receipt=delegation_receipt,
            amount=amount,
            currency=currency,
        )
        gate_decision = decision.get("decision")

        if gate_decision == "ALLOW":
            receipt_jcs = self.execute(
                audit_id=decision["audit_id"],
                action=action,
                resource=resource,
                environment=environment,
                params=params or {},
            )
            return ControlledActionOutcome(
                status="executed",
                decision=decision,
                receipt_jcs=receipt_jcs,
                receipt=json.loads(receipt_jcs),
            )

        if gate_decision == "WAITING_FOR_HUMAN_APPROVAL":
            approval = self.create_approval(
                audit_id=decision["audit_id"],
                delegation_receipt=delegation_receipt,
                expires_in_seconds=approval_expires_in_seconds,
            )
            return ControlledActionOutcome(
                status="approval_required",
                decision=decision,
                approval=approval,
            )

        return ControlledActionOutcome(
            status="blocked",
            decision=decision,
            reason=decision.get("reason", "runtime_gate_blocked"),
        )

    def execute_after_approval(
        self,
        audit_id: str,
        approval_id: str,
        action: str,
        resource: str,
        environment: str,
        params: Optional[dict] = None,
    ) -> ControlledActionOutcome:
        """Resume a controlled action after the principal approved it."""
        receipt_jcs = self.execute(
            audit_id=audit_id,
            action=action,
            resource=resource,
            environment=environment,
            params=params or {},
            approval_id=approval_id,
        )
        return ControlledActionOutcome(
            status="executed",
            audit_id=audit_id,
            approval_id=approval_id,
            receipt_jcs=receipt_jcs,
            receipt=json.loads(receipt_jcs),
        )

    def issue_delegation_receipt(
        self,
        *,
        agent_did: str,
        allowed_categories: list[str],
        valid_for: timedelta,
        max_spend: Optional[dict[str, Any]] = None,
        purpose: str = "Controlled-action delegation",
        **unsupported_scope_kwargs: Any,
    ) -> dict[str, Any]:
        """
        Locally issue a v1 DelegationReceipt for an agent.

        This wrapper only emits predicates the current backend Runtime Gate
        already enforces: `allowed_category` and optional `max_spend`. It does
        not grant execution by itself; Runtime Gate, Governance, Human
        Approval, and execution cross-checks remain authoritative.
        """
        unsupported = {
            key
            for key in unsupported_scope_kwargs
            if key in {"allowed_actions", "allowed_resources", "allowed_environments"}
        }
        if unsupported:
            names = ", ".join(sorted(unsupported))
            raise ValueError(
                f"unsupported exact-scope delegation fields for v1: {names}"
            )
        if unsupported_scope_kwargs:
            names = ", ".join(sorted(unsupported_scope_kwargs))
            raise TypeError(f"unexpected delegation receipt arguments: {names}")
        if not isinstance(valid_for, timedelta) or valid_for.total_seconds() <= 0:
            raise ValueError("valid_for must be a positive timedelta")
        if (
            not isinstance(allowed_categories, list)
            or not allowed_categories
            or any(
                not isinstance(category, str) or not category
                for category in allowed_categories
            )
        ):
            raise ValueError("allowed_categories must be a non-empty list of strings")

        scope: list[dict[str, Any]] = [
            {"predicate": "allowed_category", "value": category}
            for category in allowed_categories
        ]
        if max_spend is not None:
            if not isinstance(max_spend, dict):
                raise ValueError("max_spend must be a dict with currency and amount")
            currency = max_spend.get("currency")
            amount = max_spend.get("amount")
            if not isinstance(currency, str) or len(currency) != 3:
                raise ValueError("max_spend.currency must be a 3-letter ISO 4217 code")
            if (
                isinstance(amount, bool)
                or not isinstance(amount, (int, float))
                or amount <= 0
            ):
                raise ValueError("max_spend.amount must be a positive number")
            scope.append({
                "predicate": "max_spend",
                "currency": currency,
                "amount": amount,
            })

        from agentveil.delegation import issue_delegation

        return issue_delegation(
            principal_private_key=self._private_key,
            agent_did=agent_did,
            scope=scope,
            purpose=purpose,
            valid_for=valid_for,
        )

    def verify_delegation_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Verify a DelegationReceipt offline using the v1 verifier."""
        from agentveil.delegation import verify_delegation

        return verify_delegation(receipt)

    def build_proof_packet(
        self,
        delegation_receipt: dict,
        outcome: ControlledActionOutcome,
        decision_receipt_jcs: Optional[str] = None,
        approval_receipt_jcs: Optional[str] = None,
        remediation_case: Optional[dict] = None,
        remediation_refs: Optional[list[dict]] = None,
    ) -> ProofPacket:
        """
        Build a proof packet from explicit local artifacts only.

        This helper does not fetch remote resources or modify signed receipt
        text. Store `decision_receipt_jcs`, `execution_receipt_jcs`, and
        `approval_receipt_jcs` exactly as returned by AVP.
        """
        audit_id = outcome.audit_id
        if audit_id is None and outcome.decision is not None:
            audit_id = outcome.decision.get("audit_id")

        decision_receipt = None
        if decision_receipt_jcs is not None:
            decision_receipt = json.loads(decision_receipt_jcs)

        approval_receipt = None
        if approval_receipt_jcs is not None:
            approval_receipt = json.loads(approval_receipt_jcs)

        try:
            sdk_version = version("agentveil")
        except PackageNotFoundError:
            sdk_version = "0.7.10"

        return ProofPacket(
            agent_did=self._did,
            base_url=self._base_url,
            sdk_version=sdk_version,
            generated_at=datetime.now(timezone.utc).isoformat(),
            delegation_receipt=deepcopy(delegation_receipt),
            outcome_status=outcome.status,
            audit_id=audit_id,
            decision_receipt_jcs=decision_receipt_jcs,
            decision_receipt=decision_receipt,
            execution_receipt_jcs=outcome.receipt_jcs,
            execution_receipt=deepcopy(outcome.receipt),
            approval=deepcopy(outcome.approval),
            approval_receipt_jcs=approval_receipt_jcs,
            approval_receipt=approval_receipt,
            remediation_case=deepcopy(remediation_case),
            remediation_refs=deepcopy(remediation_refs),
        )

    def get_reputation_velocity(self, did: Optional[str] = None) -> dict:
        """
        Get reputation velocity — rate of score change over time.

        Returns deltas over 1d, 7d, 30d windows with trend classification
        and alert flags for sudden drops.

        Args:
            did: Agent DID (defaults to self)

        Returns:
            dict with current_score, velocity, trend, alert, alert_reason
        """
        target = did or self._did
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(f"/v1/reputation/{target}/velocity")
            return self._handle_response(r)

    # ── Alert Webhooks ──────────────────────────────────────────────────

    def set_alert(
        self,
        webhook_url: str,
        threshold: float = 0.5,
    ) -> dict:
        """
        Subscribe to score drop alerts.

        When this agent's score falls below threshold, AVP POSTs to webhook_url.
        Upserts: if (agent, url) already exists, updates threshold.

        Args:
            webhook_url: HTTPS endpoint (Discord, Teams, PagerDuty, Zapier, custom)
            threshold: Score threshold (default 0.5, range 0.0-1.0)

        Returns:
            dict with alert subscription details
        """
        body = json.dumps({
            "webhook_url": webhook_url,
            "threshold": threshold,
        }).encode()
        headers = self._auth_headers("POST", "/v1/alerts", body)

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/alerts", content=body, headers=headers)
            return self._handle_response(r)

    def remove_alert(self, alert_id: str) -> None:
        """Remove an alert subscription by ID."""
        path = f"/v1/alerts/{alert_id}"
        headers = self._auth_headers("DELETE", path, b"")

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.delete(path, headers=headers)
            if r.status_code != 204:
                self._handle_response(r)

    def list_alerts(self) -> list[dict]:
        """List all alert subscriptions for this agent."""
        headers = self._auth_headers("GET", "/v1/alerts", b"")

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get("/v1/alerts", headers=headers)
            return self._handle_response(r)

    # ── Reputation Credentials ────────────────────────────────────────

    def get_reputation_credential(
        self,
        did: Optional[str] = None,
        risk_level: str = "medium",
        format: str = "avp",
    ) -> dict:
        """
        Get a signed reputation credential for offline verification.

        The credential is signed by the AVP server's Ed25519 key and contains
        the agent's score, confidence, and an expiration time based on risk_level.

        Args:
            did: Agent DID (defaults to self)
            risk_level: "low" (60min TTL), "medium" (15min), "high" (5min).
                        "critical" is rejected — use get_reputation() instead.
            format: "avp" (default, AVP-native format) or "w3c" (W3C VC v2.0).
                    W3C format is verifiable by any standard VC library.

        Returns:
            dict — AVP format or W3C Verifiable Credential depending on format param.
            Use verify_credential() for AVP format, verify_w3c_credential() for W3C.
        """
        if risk_level not in ("low", "medium", "high", "critical"):
            raise AVPValidationError(
                f"Invalid risk_level: {risk_level}. Must be low/medium/high/critical"
            )
        if format not in ("avp", "w3c"):
            raise AVPValidationError(
                f"Invalid format: {format}. Must be avp or w3c"
            )
        target = did or self._did
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(
                f"/v1/reputation/{target}/credential",
                params={"risk_level": risk_level, "format": format},
            )
            return self._handle_response(r)

    @staticmethod
    def verify_credential(credential: dict) -> bool:
        """
        Verify a reputation credential offline — no API call needed.

        Checks:
        1. Ed25519 signature is valid (signer_did → public key → verify)
        2. Credential has not expired (expires_at > now)
        3. DID field is present and non-empty

        Args:
            credential: The credential dict from get_reputation_credential()

        Returns:
            True if the credential is valid and not expired
        """
        import base58
        from datetime import datetime, timezone

        try:
            # Check required fields
            for field in ("did", "score", "confidence", "issued_at", "expires_at",
                          "risk_level", "signature", "signer_did"):
                if field not in credential:
                    return False

            # Check not expired
            expires_at = datetime.strptime(
                credential["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                return False

            # Extract public key from signer_did
            signer_did = credential["signer_did"]
            if not signer_did.startswith("did:key:z"):
                return False
            decoded = base58.b58decode(signer_did[9:])
            if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
                return False
            public_key = decoded[2:]
            if len(public_key) != 32:
                return False

            # Reconstruct the signed payload
            payload = {
                k: v for k, v in credential.items()
                if k not in ("signature", "signer_did")
            }
            message = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode()

            # Verify Ed25519 signature
            signature = bytes.fromhex(credential["signature"])
            verify_key = VerifyKey(public_key)
            verify_key.verify(message, signature)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_w3c_credential(credential: dict) -> bool:
        """
        Verify a W3C VC v2.0 reputation credential offline — no API call needed.

        Checks:
        1. W3C VC structure (@context, type, proof)
        2. Temporal validity (validFrom/validUntil)
        3. Data Integrity proof (eddsa-jcs-2022): Ed25519 signature over
           JCS-canonicalized credential (proof removed)

        Args:
            credential: The W3C VC dict from get_reputation_credential(format="w3c")

        Returns:
            True if the credential is valid, not expired, and signature checks out
        """
        import base58
        from datetime import datetime, timezone, timedelta

        try:
            # Structure checks
            contexts = credential.get("@context", [])
            if "https://www.w3.org/ns/credentials/v2" not in contexts:
                return False
            types = credential.get("type", [])
            if "VerifiableCredential" not in types:
                return False
            proof = credential.get("proof")
            if not proof or proof.get("type") != "DataIntegrityProof":
                return False
            if proof.get("cryptosuite") != "eddsa-jcs-2022":
                return False

            # Temporal validity
            now = datetime.now(timezone.utc)
            valid_until = credential.get("validUntil")
            if valid_until:
                expires = datetime.strptime(
                    valid_until, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
                if now > expires:
                    return False
            valid_from = credential.get("validFrom")
            if valid_from:
                starts = datetime.strptime(
                    valid_from, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
                if now < starts - timedelta(seconds=60):
                    return False

            # Extract public key from verification method DID
            vm = proof.get("verificationMethod", "")
            signer_did = vm.split("#")[0]
            if not signer_did.startswith("did:key:z"):
                return False
            decoded = base58.b58decode(signer_did[9:])
            if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
                return False
            public_key = decoded[2:]
            if len(public_key) != 32:
                return False

            # Reconstruct signed payload (credential without proof, RFC 8785 JCS)
            import jcs
            payload = {k: v for k, v in credential.items() if k != "proof"}
            message = jcs.canonicalize(payload)

            # Decode multibase proof value and verify
            proof_value = proof.get("proofValue", "")
            if not proof_value.startswith("z"):
                return False
            signature = base58.b58decode(proof_value[1:])
            verify_key = VerifyKey(public_key)
            verify_key.verify(message, signature)
            return True
        except Exception:
            return False

    def get_agent_info(self, did: Optional[str] = None) -> dict:
        """Get public info about an agent."""
        target = did or self._did
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(f"/v1/agents/{target}")
            return self._handle_response(r)

    # === Verification ===

    def verify_email(self, email: str) -> dict:
        """
        Start email verification. Sends OTP code to the given email.

        Args:
            email: Email address to verify

        Returns:
            dict with message and expires_in
        """
        body = json.dumps({"email": email}).encode()
        headers = self._auth_headers("POST", "/v1/verify/email", body)
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/verify/email", content=body, headers=headers)
            return self._handle_response(r)

    def confirm_email(self, otp: str) -> dict:
        """
        Confirm email OTP code. Upgrades to EMAIL tier (0.3x trust boost).

        Args:
            otp: 6-digit verification code from email

        Returns:
            dict with verified, tier, trust_boost
        """
        body = json.dumps({"otp": otp}).encode()
        headers = self._auth_headers("POST", "/v1/verify/email/confirm", body)
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/verify/email/confirm", content=body, headers=headers)
            return self._handle_response(r)

    def verify_moltbook(self, moltbook_username: str) -> dict:
        """
        DEPRECATED — Moltbook is a legacy / compatibility surface, not an
        active trust tier.

        The call still succeeds and the bot still processes the request,
        but a successful verification grants NONE-equivalent trust
        (0.1x multiplier), identical to an unverified agent. For active
        verification, use ``verify_email`` or start GitHub OAuth via the
        AVP API (``POST /v1/verify/github``).

        Args:
            moltbook_username: Your Moltbook username

        Returns:
            dict with message and status
        """
        import warnings

        warnings.warn(
            "AVPAgent.verify_moltbook is deprecated: Moltbook is a legacy "
            "compatibility surface and grants NONE-equivalent trust (0.1x). "
            "Use verify_email or GitHub verification instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        body = json.dumps({"moltbook_username": moltbook_username}).encode()
        headers = self._auth_headers("POST", "/v1/verify/moltbook", body)
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post("/v1/verify/moltbook", content=body, headers=headers)
            return self._handle_response(r)

    def get_verification_status(self, did: Optional[str] = None) -> dict:
        """
        Check verification status for an agent.

        Args:
            did: Agent DID (defaults to self)

        Returns:
            dict with did, tier, trust_boost, verified_at
        """
        target = did or self._did
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(f"/v1/verify/status/{target}")
            return self._handle_response(r)

    # === Onboarding / Challenge ===

    def get_onboarding_challenge(self) -> Optional[dict]:
        """
        Get the current onboarding challenge for this agent.

        This owner-only endpoint is fetched with AVP-Sig automatically.

        Returns:
            Challenge dict with challenge_id, challenge_text, challenge_type,
            target_capability, deadline, status. None if no challenge exists.
        """
        path = f"/v1/onboarding/{self._did}/challenge"
        headers = self._auth_headers("GET", path)
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(path, headers=headers)
            if r.status_code == 404:
                return None
            return self._handle_response(r)

    def submit_challenge_answer(self, challenge_id: str, answer: str) -> dict:
        """
        Submit an answer to the onboarding challenge.

        Args:
            challenge_id: The challenge_id from get_onboarding_challenge()
            answer: The agent's answer (10-5000 chars)

        Returns:
            dict with challenge_id, score, passed, reasoning, pipeline_status
        """
        body_data = {"challenge_id": challenge_id, "answer": answer}
        body = json.dumps(body_data).encode()
        path = f"/v1/onboarding/{self._did}/challenge"
        headers = self._auth_headers("POST", path, body)

        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.post(path, content=body, headers=headers)
            return self._handle_response(r)

    def get_onboarding_status(self) -> dict:
        """Get current onboarding status for this agent."""
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get(f"/v1/onboarding/{self._did}")
            return self._handle_response(r)

    # === Utility ===

    def health(self) -> dict:
        """Check AVP server health."""
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as c:
            r = c.get("/v1/health")
            return self._handle_response(r)

    def __repr__(self) -> str:
        status = "verified" if self._is_verified else ("registered" if self._is_registered else "new")
        return f"AVPAgent(name={self._name}, did={self._did[:35]}..., status={status})"
