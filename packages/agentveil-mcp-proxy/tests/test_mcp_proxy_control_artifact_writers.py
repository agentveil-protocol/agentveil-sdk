"""P2-11: control-artifact writer custody (symlink / mode / atomic publish)."""

from __future__ import annotations

import json
import os
import secrets
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import agentveil_mcp_proxy.control_artifacts as control_artifacts_module
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    MANIFEST_SCHEMA_VERSION,
    PersistentApprovalCenterError,
    load_manifest,
    manifest_path,
    save_manifest,
)
from agentveil_mcp_proxy.approval.server import (
    clear_owner_claim,
    publish_owner_claim,
    read_owner_claim,
)
from agentveil_mcp_proxy.client_guidance import (
    HookRuntimeBinding,
    clear_hook_runtime_binding,
    hook_runtime_binding_path,
    write_hook_runtime_binding,
)
from agentveil_mcp_proxy.control_artifacts import (
    ControlArtifactError,
    ensure_control_directory,
    rewrite_locked_control_file,
    write_atomic_control_file,
)


SECRET_TOKEN = "session-token-SHOULD-NOT-LEAK"
REGISTER_TOKEN = "internal-register-SHOULD-NOT-LEAK"
INSTANCE_TOKEN = "inst-token-SHOULD-NOT-LEAK"


def _manifest(*, session_token: str = SECRET_TOKEN) -> ApprovalCenterManifest:
    return ApprovalCenterManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        host="127.0.0.1",
        port=8765,
        session_token=session_token,
        token_hash="sha256:" + ("ab" * 32),
        internal_register_token=REGISTER_TOKEN,
        pid=os.getpid(),
        started_at=1_700_000_000,
        runtime_identity="sha256:" + ("cd" * 32),
    )


def _binding(*, instance_token: str = INSTANCE_TOKEN) -> HookRuntimeBinding:
    return HookRuntimeBinding(
        owner_pid=os.getpid(),
        instance_token=instance_token,
        session_id="session-abc",
        client_id=f"github:pid:{os.getpid()}:inst:{instance_token}",
        downstream_server="github",
        downstream_startup_fingerprint="sha256:" + ("11" * 32),
        project_workspace_root_hash="sha256:" + ("22" * 32),
        project_scope_fingerprint="sha256:" + ("33" * 32),
        written_at=1_700_000_000,
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _secure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def test_ensure_control_directory_creates_0700_under_permissive_umask(tmp_path):
    control = tmp_path / "control"
    previous = os.umask(0o000)
    try:
        ensure_control_directory(control)
    finally:
        os.umask(previous)
    assert control.is_dir()
    assert not control.is_symlink()
    assert _mode(control) == 0o700


def test_ensure_control_directory_rejects_symlink_parent(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ControlArtifactError) as excinfo:
        ensure_control_directory(link)
    assert SECRET_TOKEN not in str(excinfo.value)
    assert str(link) not in str(excinfo.value)


def test_ensure_control_directory_rejects_file_parent(tmp_path):
    path = tmp_path / "not-a-dir"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(ControlArtifactError):
        ensure_control_directory(path)


def test_ensure_control_directory_rejects_existing_unsafe_mode(tmp_path):
    control = tmp_path / "control"
    control.mkdir(mode=0o755)
    os.chmod(control, 0o755)
    assert _mode(control) == 0o755
    with pytest.raises(ControlArtifactError) as excinfo:
        ensure_control_directory(control)
    assert _mode(control) == 0o755
    assert str(excinfo.value) == "control_directory_invalid"
    assert str(control) not in str(excinfo.value)


def test_ensure_control_directory_rejects_wrong_owner(tmp_path, monkeypatch):
    control = tmp_path / "control"
    _secure_dir(control)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ControlArtifactError) as excinfo:
        ensure_control_directory(control)
    assert str(control) not in str(excinfo.value)


def test_non_posix_directory_does_not_require_posix_mode_bits(tmp_path, monkeypatch):
    monkeypatch.setattr(
        control_artifacts_module,
        "_uses_posix_filesystem_custody",
        lambda: False,
    )
    control = tmp_path / "control"
    control.mkdir(mode=0o755)
    os.chmod(control, 0o755)

    ensure_control_directory(control)


def test_non_posix_atomic_writer_preserves_available_custody(tmp_path, monkeypatch):
    monkeypatch.setattr(
        control_artifacts_module,
        "_uses_posix_filesystem_custody",
        lambda: False,
    )
    control = tmp_path / "control"
    control.mkdir(mode=0o755)
    os.chmod(control, 0o755)
    path = control / "artifact.json"

    write_atomic_control_file(path, b'{"ok":true}')

    assert path.read_bytes() == b'{"ok":true}'
    assert path.is_file()
    assert not path.is_symlink()


def test_non_posix_rewrite_preserves_bounded_file_custody(tmp_path, monkeypatch):
    monkeypatch.setattr(
        control_artifacts_module,
        "_uses_posix_filesystem_custody",
        lambda: False,
    )
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda *_args: pytest.fail("non-POSIX path must not call fchmod"),
        raising=False,
    )
    control = tmp_path / "control"
    control.mkdir()
    path = control / "x.claim"
    path.write_bytes(b"old")

    with open(path, "r+", encoding="utf-8", newline="") as fh:
        rewrite_locked_control_file(fh, b'{"ok":true}', directory=control)

    assert path.read_bytes() == b'{"ok":true}'


def test_non_posix_directory_fsync_is_not_simulated(tmp_path, monkeypatch):
    monkeypatch.setattr(
        control_artifacts_module,
        "_uses_posix_filesystem_custody",
        lambda: False,
    )
    monkeypatch.setattr(
        os,
        "open",
        lambda *_args, **_kwargs: pytest.fail(
            "non-POSIX path must not open a directory for fsync"
        ),
    )

    control_artifacts_module._fsync_directory(tmp_path)


def test_missing_o_cloexec_uses_available_exclusive_flags(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "O_CLOEXEC", raising=False)
    control = _secure_dir(tmp_path / "control")
    artifact = control / "artifact.json"

    write_atomic_control_file(artifact, b'{"ok":true}')
    lease = publish_owner_claim(
        control,
        pid=os.getpid(),
        instance_token="no-cloexec",
        session_id="session",
    )
    try:
        assert artifact.read_bytes() == b'{"ok":true}'
        claim = read_owner_claim(
            control,
            os.getpid(),
            instance_token="no-cloexec",
        )
        assert claim is not None
        assert claim["session_id"] == "session"
    finally:
        clear_owner_claim(lease)


def test_save_manifest_parent_0700_and_file_0600(tmp_path):
    proxy_dir = tmp_path / "proxy"
    previous = os.umask(0o000)
    try:
        save_manifest(proxy_dir, _manifest())
    finally:
        os.umask(previous)
    path = manifest_path(proxy_dir)
    assert _mode(proxy_dir) == 0o700
    assert _mode(path) == 0o600
    loaded = load_manifest(proxy_dir)
    assert loaded is not None
    assert loaded.session_token == SECRET_TOKEN
    assert loaded.internal_register_token == REGISTER_TOKEN
    assert set(json.loads(path.read_text(encoding="utf-8"))) == set(loaded.to_dict())


def test_save_manifest_target_symlink_leaves_victim_unchanged(tmp_path):
    proxy_dir = _secure_dir(tmp_path / "proxy")
    victim = tmp_path / "victim.txt"
    original = b"VICTIM-BYTES-UNCHANGED\n"
    victim.write_bytes(original)
    target = manifest_path(proxy_dir)
    target.symlink_to(victim)
    with pytest.raises(PersistentApprovalCenterError) as excinfo:
        save_manifest(proxy_dir, _manifest())
    assert victim.read_bytes() == original
    assert SECRET_TOKEN not in str(excinfo.value)
    assert REGISTER_TOKEN not in str(excinfo.value)
    assert str(victim) not in str(excinfo.value)


def test_save_manifest_temp_symlink_leaves_victim_unchanged(tmp_path, monkeypatch):
    proxy_dir = _secure_dir(tmp_path / "proxy")
    victim = tmp_path / "victim-temp.txt"
    original = b"TEMP-VICTIM-UNCHANGED\n"
    victim.write_bytes(original)
    target = manifest_path(proxy_dir)
    nonce = "aabbccddeeff0011"
    monkeypatch.setattr(secrets, "token_hex", lambda n=8: nonce)
    bait = target.with_name(f".{target.name}.{os.getpid()}.{nonce}.tmp")
    bait.symlink_to(victim)
    with pytest.raises(PersistentApprovalCenterError) as excinfo:
        save_manifest(proxy_dir, _manifest())
    assert victim.read_bytes() == original
    assert not target.exists() or target.is_symlink()
    assert SECRET_TOKEN not in str(excinfo.value)
    assert str(victim) not in str(excinfo.value)


def test_write_hook_runtime_binding_symlink_and_modes(tmp_path):
    proxy_home = tmp_path / "home"
    binding = _binding()
    previous = os.umask(0o000)
    try:
        write_hook_runtime_binding(proxy_home, binding)
    finally:
        os.umask(previous)
    path = hook_runtime_binding_path(
        proxy_home,
        owner_pid=binding.owner_pid,
        instance_token=binding.instance_token,
    )
    assert _mode(path.parent) == 0o700
    assert _mode(path) == 0o600
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["instance_token"] == INSTANCE_TOKEN
    assert set(payload) == {
        "owner_pid",
        "instance_token",
        "session_id",
        "client_id",
        "downstream_server",
        "downstream_startup_fingerprint",
        "project_workspace_root_hash",
        "project_scope_fingerprint",
        "written_at",
    }

    victim = tmp_path / "hook-victim.json"
    original = b'{"keep":true}\n'
    victim.write_bytes(original)
    clear_hook_runtime_binding(
        proxy_home,
        owner_pid=binding.owner_pid,
        instance_token=binding.instance_token,
    )
    path.symlink_to(victim)
    with pytest.raises(ControlArtifactError) as excinfo:
        write_hook_runtime_binding(proxy_home, binding)
    assert victim.read_bytes() == original
    assert INSTANCE_TOKEN not in str(excinfo.value)
    assert str(victim) not in str(excinfo.value)


def test_atomic_write_stale_temp_does_not_publish_partial(tmp_path):
    target = tmp_path / "ctrl" / "file.json"
    ensure_control_directory(target.parent)
    stale = target.with_name(f".{target.name}.99999.deadbeef.tmp")
    stale.write_text("stale-partial", encoding="utf-8")
    write_atomic_control_file(target, b'{"ok":true}\n')
    assert target.read_bytes() == b'{"ok":true}\n'
    assert stale.read_text(encoding="utf-8") == "stale-partial"
    assert _mode(target) == 0o600


def test_atomic_write_zero_write_leaves_no_publish(tmp_path, monkeypatch):
    target = tmp_path / "ctrl" / "file.json"

    def zero_write(fd, data):
        return 0

    monkeypatch.setattr(os, "write", zero_write)
    with pytest.raises(ControlArtifactError):
        write_atomic_control_file(target, b'{"ok":true}\n')
    assert not target.exists()
    assert list((tmp_path / "ctrl").glob("*.tmp")) == []


def test_atomic_write_fsync_failure_leaves_no_partial_publish(tmp_path, monkeypatch):
    target = tmp_path / "ctrl" / "file.json"
    calls = {"fsync": 0}
    real_fsync = os.fsync

    def boom(fd):
        calls["fsync"] += 1
        if calls["fsync"] == 1:
            raise OSError("simulated fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(ControlArtifactError):
        write_atomic_control_file(target, b'{"ok":true}\n')
    assert not target.exists()
    assert list((tmp_path / "ctrl").glob("*.tmp")) == []


def test_atomic_write_replace_failure_leaves_no_partial_publish(tmp_path, monkeypatch):
    target = tmp_path / "ctrl" / "file.json"

    def boom(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(ControlArtifactError):
        write_atomic_control_file(target, b'{"ok":true}\n')
    assert not target.exists()
    assert list((tmp_path / "ctrl").glob("*.tmp")) == []


def test_publish_owner_claim_rejects_symlink_and_preserves_victim(tmp_path):
    claim_dir = _secure_dir(tmp_path / "claims")
    victim = tmp_path / "claim-victim"
    original = b"CLAIM-VICTIM\n"
    victim.write_bytes(original)
    path = claim_dir / f"{os.getpid()}-tok.claim"
    path.symlink_to(victim)
    with pytest.raises(OSError) as excinfo:
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="tok",
            session_id="sess",
        )
    assert victim.read_bytes() == original
    assert str(excinfo.value) == "control_artifact_write_failed"
    assert str(victim) not in str(excinfo.value)


def test_publish_owner_claim_rejects_hardlink(tmp_path):
    claim_dir = _secure_dir(tmp_path / "claims")
    primary = claim_dir / "primary.claim"
    primary.write_text("{}", encoding="utf-8")
    linked = claim_dir / f"{os.getpid()}-hl.claim"
    try:
        os.link(primary, linked)
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises(OSError) as excinfo:
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="hl",
            session_id="sess",
        )
    assert str(excinfo.value) == "control_artifact_write_failed"
    assert primary.read_text(encoding="utf-8") == "{}"


def test_publish_owner_claim_sets_0600_before_first_secret_byte(tmp_path, monkeypatch):
    claim_dir = _secure_dir(tmp_path / "claims")
    path = claim_dir / f"{os.getpid()}-stale.claim"
    path.write_text('{"pid":1,"instance_token":"stale","session_id":"old"}', encoding="utf-8")
    os.chmod(path, 0o644)
    assert _mode(path) == 0o644

    modes_at_write: list[int] = []
    real_write = os.write

    def tracked_write(fd, data):
        modes_at_write.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", tracked_write)
    lease = publish_owner_claim(
        claim_dir,
        pid=os.getpid(),
        instance_token="stale",
        session_id="new-session",
    )
    assert modes_at_write
    assert modes_at_write[0] == 0o600
    assert _mode(path) == 0o600
    claim = read_owner_claim(claim_dir, os.getpid(), instance_token="stale")
    assert claim is not None
    assert claim["session_id"] == "new-session"
    clear_owner_claim(lease)


def test_publish_owner_claim_short_write_is_not_success(tmp_path, monkeypatch):
    claim_dir = _secure_dir(tmp_path / "claims")
    state = {"n": 0}

    def short_write(fd, data):
        state["n"] += 1
        if state["n"] == 1 and len(data) > 1:
            return 1
        return 0

    monkeypatch.setattr(os, "write", short_write)
    with pytest.raises(OSError) as excinfo:
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="short",
            session_id="sess",
        )
    assert str(excinfo.value) == "control_artifact_write_failed"
    path = claim_dir / f"{os.getpid()}-short.claim"
    assert path.exists()
    with pytest.raises((json.JSONDecodeError, UnicodeDecodeError, ValueError)):
        json.loads(path.read_text(encoding="utf-8"))


def test_publish_owner_claim_fsync_failure_is_not_success(tmp_path, monkeypatch):
    claim_dir = _secure_dir(tmp_path / "claims")
    real_fsync = os.fsync
    calls = {"n": 0}

    def boom(fd):
        calls["n"] += 1
        # First fsync is the claim file content.
        if calls["n"] == 1:
            raise OSError("simulated claim fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError) as excinfo:
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="fsync",
            session_id="sess",
        )
    assert str(excinfo.value) == "control_artifact_write_failed"


def test_publish_owner_claim_dir_fsync_failure_is_not_success(tmp_path, monkeypatch):
    claim_dir = _secure_dir(tmp_path / "claims")
    real_fsync = os.fsync
    file_fsync_done = {"ok": False}

    def boom(fd):
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode):
            file_fsync_done["ok"] = True
            return real_fsync(fd)
        raise OSError("simulated directory fsync failure")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError) as excinfo:
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="dirfsync",
            session_id="sess",
        )
    assert file_fsync_done["ok"] is True
    assert str(excinfo.value) == "control_artifact_write_failed"


def test_publish_owner_claim_concurrent_single_winner(tmp_path):
    claim_dir = _secure_dir(tmp_path / "claims")
    barrier = threading.Barrier(8)
    winners: list = []
    errors: list = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            lease = publish_owner_claim(
                claim_dir,
                pid=os.getpid(),
                instance_token="same",
                session_id="sess-1",
            )
            with lock:
                winners.append(lease)
        except OSError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: worker(), range(8)))

    assert len(winners) == 1
    assert len(errors) == 7
    assert {str(exc) for exc in errors} == {"owner claim lease is already held"}
    lease = winners[0]
    claim = read_owner_claim(claim_dir, os.getpid(), instance_token="same")
    assert claim is not None
    assert claim["session_id"] == "sess-1"
    clear_owner_claim(lease)


def test_publish_owner_claim_does_not_truncate_before_lock(tmp_path):
    claim_dir = _secure_dir(tmp_path / "claims")
    first = publish_owner_claim(
        claim_dir,
        pid=os.getpid(),
        instance_token="held",
        session_id="original-session",
    )
    path = first.path
    before = path.read_bytes()

    with pytest.raises(OSError, match="already held"):
        publish_owner_claim(
            claim_dir,
            pid=os.getpid(),
            instance_token="held",
            session_id="attacker-session",
        )
    assert path.read_bytes() == before
    claim = read_owner_claim(claim_dir, os.getpid(), instance_token="held")
    assert claim is not None
    assert claim["session_id"] == "original-session"
    clear_owner_claim(first)


def test_publish_owner_claim_lifecycle_clear_and_republish(tmp_path):
    claim_dir = _secure_dir(tmp_path / "claims")
    first = publish_owner_claim(
        claim_dir,
        pid=os.getpid(),
        instance_token="life",
        session_id="one",
    )
    clear_owner_claim(first)
    second = publish_owner_claim(
        claim_dir,
        pid=os.getpid(),
        instance_token="life",
        session_id="two",
    )
    claim = read_owner_claim(claim_dir, os.getpid(), instance_token="life")
    assert claim is not None
    assert claim["session_id"] == "two"
    clear_owner_claim(second)


def test_errors_do_not_leak_tokens_or_traceback(tmp_path):
    proxy_dir = _secure_dir(tmp_path / "proxy")
    bait = manifest_path(proxy_dir)
    outside = tmp_path / "outside"
    outside.write_text("x", encoding="utf-8")
    bait.symlink_to(outside)
    with pytest.raises(PersistentApprovalCenterError) as excinfo:
        save_manifest(proxy_dir, _manifest())
    text = str(excinfo.value)
    assert SECRET_TOKEN not in text
    assert REGISTER_TOKEN not in text
    assert "Traceback" not in text
    assert str(tmp_path) not in text
    assert text == "control_artifact_write_failed"


def test_approval_server_error_remains_importable_from_persistent():
    from agentveil_mcp_proxy.approval.persistent import ApprovalServerError
    from agentveil_mcp_proxy.approval.server import (
        ApprovalServerError as CanonicalApprovalServerError,
    )

    assert ApprovalServerError is CanonicalApprovalServerError


def test_rewrite_locked_control_file_requires_0600_before_payload(tmp_path, monkeypatch):
    control = _secure_dir(tmp_path / "ctrl")
    path = control / "x.claim"
    path.write_bytes(b"old")
    os.chmod(path, 0o644)
    fh = open(path, "r+", encoding="utf-8", newline="")
    try:
        modes: list[int] = []
        real_write = os.write

        def tracked(fd, data):
            modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
            return real_write(fd, data)

        monkeypatch.setattr(os, "write", tracked)
        rewrite_locked_control_file(fh, b'{"ok":true}', directory=control)
        assert modes == [0o600]
        assert _mode(path) == 0o600
    finally:
        fh.close()
