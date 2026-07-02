"""Real subprocess lifecycle tests for managed Approval Center."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import pytest

from agentveil_mcp_proxy.agent_launcher import (
    ensure_approval_center_running,
    project_avp_home,
    stop_managed_launch,
)
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    is_process_alive,
    load_manifest,
    save_manifest,
    token_hash_for,
)
from agentveil_mcp_proxy.approval.server import (
    _managed_process_is_active,
    _process_cmdline_matches_managed_center,
    clear_managed_approval_center_manifest,
    inspect_managed_approval_center,
    managed_center_cmdline_owns_pid,
    prepare_stale_managed_approval_center,
    scan_cmdline_proven_managed_center_pids,
    stop_managed_approval_center,
    terminate_managed_approval_center_pid,
)
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream


class ManagedCenterPidTracker:
    def __init__(self) -> None:
        self._pids_by_home: dict[str, set[int]] = {}

    def track(self, home: Path, pid: int | None) -> None:
        if pid is None:
            return
        key = str(Path(home).resolve())
        self._pids_by_home.setdefault(key, set()).add(int(pid))

    def tracked_for(self, home: Path) -> set[int]:
        return set(self._pids_by_home.get(str(Path(home).resolve()), set()))


def _force_cleanup_managed_centers_for_home(
    home: Path,
    *,
    tracked_pids: set[int] | None = None,
) -> None:
    """Best-effort cleanup so failed lifecycle tests cannot leave orphan centers."""

    # These PIDs were returned by the test-started helper in this process. Do
    # not depend on cmdline scanning here: sandboxed pytest may not be allowed
    # to run ps, and this cleanup path is precisely what prevents test orphans.
    for pid in set(tracked_pids or ()):
        if _managed_process_is_active(pid):
            terminate_managed_approval_center_pid(pid)

    candidates: set[int] = set()
    manifest = load_manifest(home / "mcp-proxy")
    if manifest is not None and manifest.pid is not None:
        candidates.add(manifest.pid)
    candidates.update(scan_cmdline_proven_managed_center_pids(home))

    for pid in candidates:
        if managed_center_cmdline_owns_pid(home, pid):
            terminate_managed_approval_center_pid(pid)

    clear_managed_approval_center_manifest(home)
    stop_managed_approval_center(home, require_healthy=False)

    for pid in scan_cmdline_proven_managed_center_pids(home):
        if managed_center_cmdline_owns_pid(home, pid):
            terminate_managed_approval_center_pid(pid)
    clear_managed_approval_center_manifest(home)


@pytest.fixture
def managed_center_pid_tracker() -> ManagedCenterPidTracker:
    return ManagedCenterPidTracker()


@pytest.fixture
def managed_project_home(tmp_path, managed_center_pid_tracker, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    sandbox = project / "sandbox"
    sandbox.mkdir()
    home = project_avp_home(project)
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )

    from agentveil_mcp_proxy import agent_launcher

    original_ensure = agent_launcher.ensure_approval_center_running

    def tracking_ensure(**kwargs):
        center, started, reason = original_ensure(**kwargs)
        managed_center_pid_tracker.track(kwargs["home"], center.pid)
        return center, started, reason

    monkeypatch.setattr(
        agent_launcher,
        "ensure_approval_center_running",
        tracking_ensure,
    )

    try:
        yield project, home, managed_center_pid_tracker
    finally:
        _force_cleanup_managed_centers_for_home(
            home,
            tracked_pids=managed_center_pid_tracker.tracked_for(home),
        )


def test_cmdline_match_accepts_macos_private_path_variants(tmp_path):
    home = tmp_path / "project" / ".avp"
    home.mkdir(parents=True)
    config = home / "mcp-proxy" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")

    resolved = home.resolve()
    ps_home = str(resolved)
    if ps_home.startswith("/private/"):
        ps_home = ps_home[len("/private") :]
    cmd = (
        "python -c main(['approval-center', 'serve', '--home', "
        f"'{ps_home}', '--config', '{ps_home}/mcp-proxy/config.json', '--port', '0'])"
    )

    from agentveil_mcp_proxy.approval.server import _cmdline_contains_path

    assert _cmdline_contains_path(cmd, home)
    assert _cmdline_contains_path(cmd, config)


def test_stale_manifest_is_not_running(managed_project_home):
    _project, home, _tracker = managed_project_home
    status = inspect_managed_approval_center(home)
    assert status.state in {"down", "stale", "running"}

    proxy_dir = home / "mcp-proxy"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=59999,
            session_token="stale-token",
            token_hash="sha256:" + "a" * 64,
            internal_register_token="internal-token",
            pid=999999,
            started_at=1,
        ),
    )
    stale = inspect_managed_approval_center(home)
    assert stale.state == "stale"
    assert stale.pid == 999999


def test_stale_manifest_does_not_kill_unowned_active_pid(managed_project_home, monkeypatch):
    _project, home, _tracker = managed_project_home
    foreign_pid = os.getpid()
    proxy_dir = home / "mcp-proxy"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=59999,
            session_token="stale-token",
            token_hash=token_hash_for("stale-token"),
            internal_register_token="internal-token",
            pid=foreign_pid,
            started_at=1,
        ),
    )
    assert inspect_managed_approval_center(home).state == "stale"

    def forbid_terminate(*_args, **_kwargs):
        raise AssertionError("must not terminate unowned pid")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.terminate_managed_approval_center_pid",
        forbid_terminate,
    )

    prepared = prepare_stale_managed_approval_center(home)
    assert prepared["prepared"] is True
    assert prepared["stopped"] is False
    assert "without killing unowned pid" in prepared["reason"]
    assert load_manifest(proxy_dir) is None
    assert os.getpid() == foreign_pid


def test_managed_approval_center_subprocess_start_stop_reuse(managed_project_home):
    project, home, _tracker = managed_project_home
    proxy_command = sys.executable

    center, started, _reason = ensure_approval_center_running(
        home=home,
        proxy_command=proxy_command,
    )
    assert started is True
    assert center.state == "running"
    pid = center.pid
    assert pid is not None
    assert is_process_alive(pid)

    center2, started2, _reason2 = ensure_approval_center_running(
        home=home,
        proxy_command=proxy_command,
    )
    assert started2 is False
    assert center2.state == "running"
    assert center2.pid == pid

    outcome = stop_managed_approval_center(home)
    assert outcome["stopped"] is True
    assert outcome["pid"] == pid
    assert not _managed_process_is_active(pid)
    assert load_manifest(home / "mcp-proxy") is None


def test_prepare_stale_replaces_before_new_start(managed_project_home, monkeypatch):
    _project, home, tracker = managed_project_home
    proxy_command = sys.executable

    center, _started, _ = ensure_approval_center_running(
        home=home,
        proxy_command=proxy_command,
    )
    pid = center.pid
    assert pid is not None
    tracker.track(home, pid)

    proxy_dir = home / "mcp-proxy"
    manifest = load_manifest(proxy_dir)
    assert manifest is not None
    stale_manifest = ApprovalCenterManifest(
        schema_version=manifest.schema_version,
        host=manifest.host,
        port=manifest.port + 1,
        session_token=manifest.session_token,
        token_hash=manifest.token_hash,
        internal_register_token=manifest.internal_register_token,
        pid=pid,
        started_at=manifest.started_at,
    )
    save_manifest(proxy_dir, stale_manifest)
    assert inspect_managed_approval_center(home).state == "stale"

    # Product code uses ps cmdline proof for stale-but-owned processes. The
    # sandboxed test runner may block ps, so model the command line while still
    # using a real Approval Center subprocess and exact PID termination.
    ps_home = str(home)
    if ps_home.startswith("/private/"):
        ps_home = ps_home[len("/private") :]
    cmdline = (
        "python -c main(['approval-center', 'serve', '--home', "
        f"'{ps_home}', '--config', '{ps_home}/mcp-proxy/config.json', '--port', '0'])"
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server._read_process_command",
        lambda seen_pid: cmdline if seen_pid == pid else "",
    )
    assert managed_center_cmdline_owns_pid(home, pid)

    prepared = prepare_stale_managed_approval_center(home)
    assert prepared["prepared"] is True
    assert prepared["stopped"] is True
    assert not _managed_process_is_active(pid)

    center2, started2, _ = ensure_approval_center_running(
        home=home,
        proxy_command=proxy_command,
    )
    assert started2 is True
    assert center2.state == "running"
    assert center2.pid is not None
    assert center2.pid != pid


def test_launch_stop_uses_managed_center_stop(managed_project_home):
    project, home, _tracker = managed_project_home
    proxy_command = sys.executable
    center, _, _ = ensure_approval_center_running(
        home=home,
        proxy_command=proxy_command,
    )
    pid = center.pid
    assert pid is not None

    outcome = stop_managed_launch(project_dir=project)
    assert outcome["stopped_center"] is True
    assert not _managed_process_is_active(pid)


def test_stop_managed_does_not_kill_unhealthy_unowned_manifest(tmp_path, monkeypatch):
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        save_manifest,
        token_hash_for,
    )

    home = tmp_path / ".avp"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=43210,
            session_token="session-token",
            token_hash=token_hash_for("session-token"),
            internal_register_token="internal",
            pid=12345,
            started_at=1,
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server._managed_process_is_active",
        lambda _pid: True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: False,
    )

    def fail_kill(_pid, _signal):
        raise AssertionError("must not kill an unhealthy unowned manifest pid")

    monkeypatch.setattr("agentveil_mcp_proxy.approval.server.os.kill", fail_kill)
    result = stop_managed_approval_center(home, require_healthy=True)
    assert result["stopped"] is False
    assert "not a healthy AgentVeil Approval Center" in result["reason"]


def test_stop_managed_stops_cmdline_owned_unhealthy_manifest(tmp_path, monkeypatch):
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        save_manifest,
        token_hash_for,
    )

    home = tmp_path / ".avp"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=43210,
            session_token="session-token",
            token_hash=token_hash_for("session-token"),
            internal_register_token="internal",
            pid=12345,
            started_at=1,
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server._managed_process_is_active",
        lambda _pid: True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.terminate_managed_approval_center_pid",
        lambda _pid, **kwargs: True,
    )

    result = stop_managed_approval_center(home, require_healthy=True)
    assert result["stopped"] is True
    assert result["pid"] == 12345


def test_terminate_managed_pid_uses_exact_pid_only(tmp_path, monkeypatch):
    killed: list[tuple[int, int]] = []
    active = {"value": True}

    def fake_kill(pid, sig):
        killed.append((pid, sig))
        if sig == signal.SIGTERM:
            active["value"] = False

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.os.kill",
        fake_kill,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server._managed_process_is_active",
        lambda pid: active["value"] and pid == 4242,
    )

    assert terminate_managed_approval_center_pid(4242) is True
    assert killed == [(4242, signal.SIGTERM)]
