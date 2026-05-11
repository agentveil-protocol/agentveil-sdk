"""Tests for Ed25519 identity: key generation, DID creation, agent lifecycle."""

import json
import os
import tempfile

import pytest
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent, _public_key_to_did


class TestPublicKeyToDid:
    """DID derivation from Ed25519 public keys."""

    def test_did_starts_with_prefix(self, public_key):
        did = _public_key_to_did(public_key)
        assert did.startswith("did:key:z")

    def test_did_is_deterministic(self, public_key):
        did1 = _public_key_to_did(public_key)
        did2 = _public_key_to_did(public_key)
        assert did1 == did2

    def test_different_keys_produce_different_dids(self):
        key1 = bytes(SigningKey.generate().verify_key)
        key2 = bytes(SigningKey.generate().verify_key)
        assert _public_key_to_did(key1) != _public_key_to_did(key2)

    def test_did_contains_multicodec_prefix(self, public_key):
        import base58
        did = _public_key_to_did(public_key)
        encoded = did[9:]  # strip "did:key:z"
        decoded = base58.b58decode(encoded)
        assert decoded[0] == 0xED
        assert decoded[1] == 0x01
        assert decoded[2:] == public_key


class TestAVPAgentCreate:
    """Agent creation and key management."""

    def test_create_generates_valid_did(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        assert agent.did.startswith("did:key:z")

    def test_create_different_agents_have_different_dids(self):
        a1 = AVPAgent.create("https://example.com", name="a1", save=False)
        a2 = AVPAgent.create("https://example.com", name="a2", save=False)
        assert a1.did != a2.did

    def test_create_initial_state(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        assert not agent.is_registered
        assert not agent.is_verified

    def test_create_mock_returns_mock_agent(self):
        agent = AVPAgent.create(mock=True, name="mock_test")
        from agentveil.mock import AVPMockAgent
        assert isinstance(agent, AVPMockAgent)

    def test_create_without_base_url_raises(self):
        with pytest.raises(ValueError, match="base_url is required"):
            AVPAgent.create("", name="test", save=False)

    def test_public_key_hex_is_64_chars(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        assert len(agent.public_key_hex) == 64
        int(agent.public_key_hex, 16)  # valid hex


class TestAVPAgentSaveLoad:
    """Key persistence."""

    def test_save_and_load_roundtrip(self, private_key):
        with tempfile.TemporaryDirectory() as tmpdir:
            import agentveil.agent as agent_mod
            original_dir = agent_mod.AGENTS_DIR
            agent_mod.AGENTS_DIR = tmpdir
            try:
                agent = AVPAgent("https://example.com", private_key, name="roundtrip")
                agent.save()

                loaded = AVPAgent.load("https://example.com", name="roundtrip")
                assert loaded.did == agent.did
                assert loaded.public_key_hex == agent.public_key_hex
            finally:
                agent_mod.AGENTS_DIR = original_dir

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            AVPAgent.load("https://example.com", name="nonexistent_agent_xyz")

    def test_save_file_permissions(self, private_key):
        if os.name == "nt":
            pytest.skip("POSIX mode bits do not represent Windows profile ACLs")

        with tempfile.TemporaryDirectory() as tmpdir:
            import agentveil.agent as agent_mod
            original_dir = agent_mod.AGENTS_DIR
            agent_mod.AGENTS_DIR = tmpdir
            try:
                agent = AVPAgent("https://example.com", private_key, name="perms")
                path = agent.save()
                mode = os.stat(path).st_mode & 0o777
                assert mode == 0o600
            finally:
                agent_mod.AGENTS_DIR = original_dir

    def test_save_file_contains_valid_json(self, private_key):
        with tempfile.TemporaryDirectory() as tmpdir:
            import agentveil.agent as agent_mod
            original_dir = agent_mod.AGENTS_DIR
            agent_mod.AGENTS_DIR = tmpdir
            try:
                agent = AVPAgent("https://example.com", private_key, name="json_test")
                path = agent.save()
                with open(path) as f:
                    data = json.load(f)
                assert data["did"] == agent.did
                assert data["public_key_hex"] == agent.public_key_hex
                assert "private_key_hex" in data
            finally:
                agent_mod.AGENTS_DIR = original_dir


class TestAVPAgentFromPrivateKey:
    """Factory from hex key."""

    def test_from_private_key_restores_did(self, private_key):
        agent1 = AVPAgent("https://example.com", private_key, name="orig")
        agent2 = AVPAgent.from_private_key(
            "https://example.com", private_key.hex(), name="restored"
        )
        assert agent1.did == agent2.did


class TestAVPAgentRepr:
    """String representation."""

    def test_repr_new_agent(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        r = repr(agent)
        assert "test" in r
        assert "new" in r

    def test_repr_contains_did_prefix(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        r = repr(agent)
        assert "did:key:z" in r


class TestAVPAgentValidation:
    """Input validation in attest()."""

    def test_attest_invalid_outcome_raises(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        from agentveil.exceptions import AVPValidationError
        with pytest.raises(AVPValidationError, match="Invalid outcome"):
            agent.attest("did:key:z6MkTest", outcome="invalid")

    def test_attest_weight_out_of_range_raises(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        from agentveil.exceptions import AVPValidationError
        with pytest.raises(AVPValidationError, match="Weight must be"):
            agent.attest("did:key:z6MkTest", outcome="positive", weight=1.5)

    def test_credential_invalid_risk_level_raises(self):
        agent = AVPAgent.create("https://example.com", name="test", save=False)
        from agentveil.exceptions import AVPValidationError
        with pytest.raises(AVPValidationError, match="Invalid risk_level"):
            agent.get_reputation_credential(risk_level="extreme")
