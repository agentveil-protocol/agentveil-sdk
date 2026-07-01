"""Unit tests for managed runtime launcher."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentveil_mcp_proxy.agent_launcher import (
    AGENTVEIL_AVP_HOME_ENV,
    AGENTVEIL_MCP_PROXY_COMMAND_ENV,
    AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV,
    AGENTVEIL_RUNTIME_PROFILE_ENV,
    AGENTVEIL_RUNTIME_SESSION_ENV,
    AgentLauncherError,
    bounded_command_metadata,
    build_launch_status,
    launch_managed_process,
    launch_manifest_path,
    load_launch_manifest,
    normalize_child_command,
    project_avp_home,
    resolve_project_dir,
    runtime_route_path,
    runtime_state_home,
    stop_managed_launch,
    write_runtime_route_config,
)
from agentveil_mcp_proxy.agent_runtime_profiles import GENERIC_PROCESS_PROFILE


def test_normalize_child_command_strips_separator():
    assert normalize_child_command(["--", "python", "-c", "print(1)"]) == [
        "python",
        "-c",
        "print(1)",
    ]


def test_normalize_child_command_requires_command():
    with pytest.raises(AgentLauncherError, match="child command required"):
        normalize_child_command(["--"])


def test_resolve_project_dir_rejects_missing(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(AgentLauncherError, match="does not exist"):
        resolve_project_dir(missing)


def test_write_runtime_route_config_bounded(tmp_path):
    home = tmp_path / ".avp"
    write_runtime_route_config(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        session_id="session-1",
        proxy_command="agentveil-mcp-proxy",
        run_args=["run", "--home", str(home)],
    )
    payload = json.loads(runtime_route_path(home).read_text(encoding="utf-8"))
    assert payload["profile_id"] == "generic-process"
    assert payload["host_wide_control_claim"] is False
    assert payload["evidence_enabled"] is True
    assert "/private/" not in json.dumps(payload)
    assert "/Users/" not in json.dumps(payload)


def test_launch_managed_process_fail_closed_when_center_down(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="down", pid=None, port=None),
            False,
            "approval center unavailable",
        ),
    )

    with pytest.raises(AgentLauncherError, match="preflight failed"):
        launch_managed_process(
            project_dir=project,
            profile_id="generic-process",
            child_command=["python", "-c", "print('noop')"],
            proxy_command="agentveil-mcp-proxy",
        )


def test_launch_managed_process_starts_child_with_bounded_env(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    project = tmp_path / "project"
    project.mkdir()
    seen: dict[str, object] = {}

    def fake_popen(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.subprocess.Popen", fake_popen)

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    result = launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=["python", "-c", "print('ok')"],
        proxy_command="/bin/agentveil-mcp-proxy",
    )

    assert result.child_started is True
    env = seen["env"]
    assert env[AGENTVEIL_AVP_HOME_ENV] == str(home)
    assert env[AGENTVEIL_MCP_PROXY_COMMAND_ENV] == "agentveil-mcp-proxy"
    assert env[AGENTVEIL_RUNTIME_PROFILE_ENV] == "generic-process"
    assert env[AGENTVEIL_RUNTIME_SESSION_ENV]
    assert json.loads(env[AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV])[0] == "run"
    runtime_home = env["HOME"]
    assert runtime_home != str(host_home)
    assert runtime_home.endswith("/home")
    assert f"{home}/runtime/generic-process/" in runtime_home
    manifest = load_launch_manifest(home)
    assert manifest is not None
    assert manifest.child_pid == 4242
    assert manifest.child_argv0 == "python"


def test_launch_child_gets_project_local_home_not_host_home(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    project = tmp_path / "project"
    project.mkdir()
    seen: dict[str, object] = {}

    def fake_popen(_command, **kwargs):
        seen["env"] = kwargs["env"]
        return SimpleNamespace(pid=5151)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.subprocess.Popen", fake_popen)

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=["python", "-c", "print('ok')"],
        proxy_command="agentveil-mcp-proxy",
    )

    child_home = seen["env"]["HOME"]
    assert child_home != str(host_home)
    assert child_home.startswith(str(home / "runtime" / "generic-process"))
    assert Path(child_home).name == "home"


SECRET_COMMAND_TOKEN = "SECRET_TOKEN_DO_NOT_PERSIST_IN_MANIFEST"
PROVIDER_API_KEY = "sk-FAKE_PROVIDER_KEY_DO_NOT_PERSIST"


def test_launch_persistence_data_minimization_gate(tmp_path, monkeypatch):
    """Manifest/status/route must not persist secrets, full argv, env, or user home paths."""

    host_home = tmp_path / "operator-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", PROVIDER_API_KEY)
    project = tmp_path / "project"
    project.mkdir()

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.subprocess.Popen",
        lambda *_args, **kwargs: SimpleNamespace(pid=6161),
    )

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=[
            "python",
            "-c",
            "print(1)",
            f"--api-key={SECRET_COMMAND_TOKEN}",
            f"--token={PROVIDER_API_KEY}",
        ],
        proxy_command="agentveil-mcp-proxy",
    )

    manifest_text = launch_manifest_path(home).read_text(encoding="utf-8")
    route_text = runtime_route_path(home).read_text(encoding="utf-8")
    status = build_launch_status(home=home, profile=GENERIC_PROCESS_PROFILE, project_dir=project)
    status_text = json.dumps(status.to_dict())
    combined = "\n".join((manifest_text, route_text, status_text))

    for forbidden in (
        SECRET_COMMAND_TOKEN,
        PROVIDER_API_KEY,
        str(host_home),
        "/Users/",
        "/private/",
    ):
        assert forbidden not in combined, f"forbidden persistence leak: {forbidden!r}"
    assert '"child_command":' not in manifest_text
    manifest = load_launch_manifest(home)
    assert manifest is not None
    assert manifest.child_argv0 == "python"
    assert manifest.child_command_ref


def test_launch_child_env_does_not_inherit_parent_secrets(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", PROVIDER_API_KEY)
    project = tmp_path / "project"
    project.mkdir()
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    def fake_popen(_args, **kwargs):
        seen["env"] = kwargs["env"]
        return SimpleNamespace(pid=1)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.subprocess.Popen",
        fake_popen,
    )

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=["python", "-c", "print(1)"],
        proxy_command="agentveil-mcp-proxy",
    )

    env = seen["env"]
    assert PROVIDER_API_KEY not in env.values()
    assert "OPENAI_API_KEY" not in env
    assert env["HOME"] != str(host_home)
    assert str(env["HOME"]).startswith(str(home / "runtime" / "generic-process"))


def test_launch_manifest_and_route_do_not_persist_command_secrets(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.subprocess.Popen",
        lambda *_args, **_kwargs: SimpleNamespace(pid=6161),
    )

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=[
            "python",
            "-c",
            "print(1)",
            f"--api-key={SECRET_COMMAND_TOKEN}",
        ],
        proxy_command="agentveil-mcp-proxy",
    )

    manifest_text = launch_manifest_path(home).read_text(encoding="utf-8")
    route_text = runtime_route_path(home).read_text(encoding="utf-8")
    status = build_launch_status(home=home, profile=GENERIC_PROCESS_PROFILE, project_dir=project)
    status_text = json.dumps(status.to_dict())

    assert SECRET_COMMAND_TOKEN not in manifest_text
    assert SECRET_COMMAND_TOKEN not in route_text
    assert SECRET_COMMAND_TOKEN not in status_text
    manifest = load_launch_manifest(home)
    assert manifest is not None
    assert manifest.child_argv0 == "python"
    assert bounded_command_metadata([
        "python",
        "-c",
        "print(1)",
        f"--api-key={SECRET_COMMAND_TOKEN}",
    ])["child_command_ref"] == manifest.child_command_ref


def test_build_launch_status_reflects_child_running(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: SimpleNamespace(state="running", pid=111, port=8765),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.load_launch_manifest",
        lambda _home: SimpleNamespace(
            child_pid=4242,
            session_id="abc",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.is_process_alive",
        lambda pid: pid == 4242,
    )

    status = build_launch_status(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    assert status.profile_status == "running"
    assert status.child_running is True
    assert status.host_wide_control_claim is False


def test_stop_managed_launch_only_stops_owned_processes(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    killed: list[int] = []

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.load_launch_manifest",
        lambda _home: SimpleNamespace(child_pid=9001),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.is_process_alive",
        lambda pid: pid in {9001, 9002},
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.load_manifest",
        lambda _proxy_dir: SimpleNamespace(
            pid=9002,
            approval_center_url=lambda: "http://127.0.0.1:8765/approval/token",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher._center_health",
        lambda _manifest: True,
    )

    def fake_kill(pid, _sig):
        killed.append(pid)

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.os.kill", fake_kill)

    outcome = stop_managed_launch(project_dir=project)
    assert outcome["stopped_child"] is True
    assert outcome["stopped_center"] is True
    assert set(killed) == {9001, 9002}
