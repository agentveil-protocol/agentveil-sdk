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
    HERMES_HOME_ENV,
    HERMES_MCP_SERVER_NAME,
    HERMES_MCP_TOOLSET,
    AgentLauncherError,
    LaunchManifest,
    LAUNCH_MANIFEST_SCHEMA_VERSION,
    bounded_command_metadata,
    build_hermes_config_document,
    build_launch_diagnostics,
    build_launch_doctor_report,
    build_launch_result_payload,
    build_launch_status,
    build_launch_status_view,
    CenterStatus,
    classify_approval_wait_mode,
    classify_evidence_state,
    classify_mcp_route_state,
    classify_provider_prerequisite,
    derive_protection_mode,
    ensure_interactive_connector_defaults,
    format_launch_doctor_human,
    format_launch_result_human,
    format_launch_status_human,
    hermes_config_path,
    hermes_runtime_home,
    launch_managed_process,
    LaunchResult,
    LaunchStatus,
    launch_manifest_path,
    load_launch_manifest,
    normalize_child_command,
    parse_hermes_agentveil_stdio_config,
    preflight_hermes_cli_executable,
    preflight_hermes_cli_provider,
    prepare_hermes_cli_command,
    project_avp_home,
    render_hermes_config_yaml,
    resolve_project_dir,
    runtime_route_path,
    runtime_state_home,
    save_launch_manifest,
    stop_managed_launch,
    verify_hermes_config_bootstrap,
    write_hermes_config,
    write_runtime_route_config,
)
from agentveil_mcp_proxy.agent_runtime_profiles import GENERIC_PROCESS_PROFILE, HERMES_CLI_PROFILE
from agentveil_mcp_proxy.evidence.events_show import LOCAL_PROOF_LAUNCHER_HINT
from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceStore, ApprovalStatus, PendingApproval


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
    runtime_home_path = Path(runtime_home)
    assert runtime_home_path.name == "home"
    assert runtime_home_path.parent.parent == home / "runtime" / "generic-process"
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
        lambda pid: pid == 9001,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.stop_managed_approval_center",
        lambda _home, **kwargs: {
            "stopped": True,
            "pid": 9002,
            "reason": "managed approval-center stopped",
        },
    )

    def fake_kill(pid, _sig):
        killed.append(pid)

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.os.kill", fake_kill)

    outcome = stop_managed_launch(project_dir=project)
    assert outcome["stopped_child"] is True
    assert outcome["stopped_center"] is True
    assert set(killed) == {9001}


# ----- P0.13b: hermes-cli profile ------------------------------------------------


def test_parse_hermes_agentveil_stdio_config_roundtrip(tmp_path):
    home = tmp_path / ".avp"
    hermes_home = hermes_runtime_home(home, "hermes-cli", "session-parse")
    write_hermes_config(
        hermes_home=hermes_home,
        proxy_command="agentveil-mcp-proxy",
        run_args=["run", "--home", str(home)],
        avp_home=home,
    )
    parsed = parse_hermes_agentveil_stdio_config(hermes_home)
    assert parsed["command"]
    assert parsed["args"][0] == "run"
    assert parsed["env"][AGENTVEIL_AVP_HOME_ENV] == str(home)
    assert "terminal" in parsed["disabled_toolsets"]


def test_parse_hermes_agentveil_stdio_config_unescapes_windows_paths(tmp_path):
    hermes_home = tmp_path / "hermes-home"
    avp_home = Path(r"C:\Users\runneradmin\AppData\Local\Temp\agentveil\.avp")
    write_hermes_config(
        hermes_home=hermes_home,
        proxy_command="agentveil-mcp-proxy",
        run_args=["run", "--home", str(avp_home)],
        avp_home=avp_home,
    )

    parsed = parse_hermes_agentveil_stdio_config(hermes_home)

    assert parsed["args"][-1] == str(avp_home)
    assert parsed["env"][AGENTVEIL_AVP_HOME_ENV] == str(avp_home)


def test_verify_hermes_config_bootstrap_rejects_missing_route(tmp_path):
    hermes_home = tmp_path / "hermes-home"
    hermes_home.mkdir(parents=True)
    hermes_config_path(hermes_home).write_text("mcp_servers: {}\n", encoding="utf-8")
    with pytest.raises(AgentLauncherError, match="missing AgentVeil MCP command"):
        verify_hermes_config_bootstrap(hermes_home)
    assert prepare_hermes_cli_command([
        "hermes",
        "chat",
        "-q",
        "hello",
    ]) == [
        "hermes",
        "chat",
        "--toolsets",
        HERMES_MCP_TOOLSET,
        "-q",
        "hello",
    ]


def test_prepare_hermes_cli_command_preserves_existing_toolsets():
    original = ["hermes", "chat", "--toolsets", "web", "-q", "hello"]
    assert prepare_hermes_cli_command(original) == original


def test_prepare_hermes_cli_command_injects_configured_mcp_server_name():
    result = prepare_hermes_cli_command(["hermes", "chat", "-q", "hello"])
    assert result == [
        "hermes",
        "chat",
        "--toolsets",
        HERMES_MCP_SERVER_NAME,
        "-q",
        "hello",
    ]
    assert HERMES_MCP_TOOLSET == HERMES_MCP_SERVER_NAME
    assert "mcp-agentveil" not in result


def test_preflight_hermes_cli_executable_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", lambda _name: None)
    with pytest.raises(AgentLauncherError, match="hermes executable not found"):
        preflight_hermes_cli_executable(["hermes", "chat"])


def test_preflight_hermes_cli_executable_rejects_non_hermes(tmp_path):
    with pytest.raises(AgentLauncherError, match="expects the child command to invoke hermes"):
        preflight_hermes_cli_executable(["python", "-c", "print(1)"])


def test_build_hermes_config_document_includes_agentveil_stdio(tmp_path):
    home = tmp_path / ".avp"
    document = build_hermes_config_document(
        proxy_command="agentveil-mcp-proxy",
        run_args=["run", "--home", str(home)],
        avp_home=home,
    )
    server = document["mcp_servers"][HERMES_MCP_SERVER_NAME]
    assert server["command"]
    assert server["args"][0] == "run"
    assert server["env"][AGENTVEIL_AVP_HOME_ENV] == str(home)
    assert "terminal" in document["agent"]["disabled_toolsets"]


def test_hermes_proxy_stdio_invocation_python_ignores_global_script(tmp_path, monkeypatch):
    stale_global = tmp_path / "bin" / "agentveil-mcp-proxy"
    stale_global.parent.mkdir(parents=True)
    stale_global.write_text("#!/bin/sh\n", encoding="utf-8")
    stale_global.chmod(0o755)
    run_args = ["run", "--home", "/tmp/project/.avp"]

    def fake_which(name):
        if name == "agentveil-mcp-proxy":
            return str(stale_global)
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)

    home = tmp_path / ".avp"
    document = build_hermes_config_document(
        proxy_command="python3",
        run_args=run_args,
        avp_home=home,
    )
    server = document["mcp_servers"][HERMES_MCP_SERVER_NAME]
    assert server["command"] == "python3"
    assert server["args"] == ["-m", "agentveil_mcp_proxy.cli", *run_args]
    assert stale_global.name not in server["command"]


def test_hermes_proxy_stdio_invocation_installed_binary_uses_resolved_script(tmp_path, monkeypatch):
    installed = tmp_path / "bin" / "agentveil-mcp-proxy"
    installed.parent.mkdir(parents=True)
    installed.write_text("#!/bin/sh\n", encoding="utf-8")
    installed.chmod(0o755)
    run_args = ["run", "--home", "/tmp/project/.avp"]

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.shutil.which",
        lambda name: str(installed) if name == "agentveil-mcp-proxy" else None,
    )

    home = tmp_path / ".avp"
    document = build_hermes_config_document(
        proxy_command="agentveil-mcp-proxy",
        run_args=run_args,
        avp_home=home,
    )
    server = document["mcp_servers"][HERMES_MCP_SERVER_NAME]
    assert server["command"] == str(installed)
    assert server["args"] == run_args
    assert "PYTHONPATH" not in server["env"]


def test_build_hermes_config_python_route_includes_pythonpath(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/tmp/source-a:/tmp/source-b")
    home = tmp_path / ".avp"
    run_args = ["run", "--home", str(home)]

    document = build_hermes_config_document(
        proxy_command="python3",
        run_args=run_args,
        avp_home=home,
    )
    server = document["mcp_servers"][HERMES_MCP_SERVER_NAME]
    assert server["command"] == "python3"
    assert server["args"][:3] == ["-m", "agentveil_mcp_proxy.cli", "run"]
    assert server["env"]["PYTHONPATH"] == "/tmp/source-a:/tmp/source-b"
    assert server["env"][AGENTVEIL_AVP_HOME_ENV] == str(home)


def test_build_hermes_config_python_route_omits_empty_pythonpath(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    home = tmp_path / ".avp"

    document = build_hermes_config_document(
        proxy_command="python3",
        run_args=["run", "--home", str(home)],
        avp_home=home,
    )
    server = document["mcp_servers"][HERMES_MCP_SERVER_NAME]
    assert "PYTHONPATH" not in server["env"]


def test_build_hermes_config_env_data_minimization(tmp_path, monkeypatch):
    home = tmp_path / ".avp"
    provider_key = "sk-FAKE_HERMES_PROVIDER_KEY"
    secret_token = "SECRET_TOKEN_VALUE"

    monkeypatch.setenv("PYTHONPATH", "/tmp/source-only")
    monkeypatch.setenv("DEEPSEEK_API_KEY", provider_key)
    monkeypatch.setenv("OPENAI_API_KEY", provider_key)
    monkeypatch.setenv("SECRET_TOKEN", secret_token)

    document = build_hermes_config_document(
        proxy_command="python3",
        run_args=["run", "--home", str(home)],
        avp_home=home,
    )
    env = document["mcp_servers"][HERMES_MCP_SERVER_NAME]["env"]
    assert set(env.keys()) == {AGENTVEIL_AVP_HOME_ENV, "PYTHONPATH"}
    assert env["PYTHONPATH"] == "/tmp/source-only"
    rendered = json.dumps(env)
    for forbidden in (provider_key, secret_token, "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "SECRET_TOKEN"):
        assert forbidden not in rendered


def test_write_hermes_config_is_project_local(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    hermes_home = hermes_runtime_home(home, "hermes-cli", "session-1")
    path = write_hermes_config(
        hermes_home=hermes_home,
        proxy_command="agentveil-mcp-proxy",
        run_args=["run", "--home", str(home)],
        avp_home=home,
    )
    assert path == hermes_config_path(hermes_home)
    text = path.read_text(encoding="utf-8")
    assert "mcp_servers:" in text
    assert f"  {HERMES_MCP_SERVER_NAME}:" in text
    assert "disabled_toolsets:" in text
    assert str(tmp_path / "operator-home") not in text


def test_launch_hermes_cli_fail_closed_when_hermes_missing(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )

    with pytest.raises(AgentLauncherError, match="hermes executable not found"):
        launch_managed_process(
            project_dir=project,
            profile_id="hermes-cli",
            child_command=["hermes", "chat", "-q", "hello"],
            proxy_command="agentveil-mcp-proxy",
        )


def test_launch_hermes_cli_bootstraps_config_and_env(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)

    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-hermes-foreground")
    project = tmp_path / "project"
    project.mkdir()
    seen: dict[str, object] = {}

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        if name == "agentveil-mcp-proxy":
            return "/usr/local/bin/agentveil-mcp-proxy"
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)

    class FakeProcess:
        pid = 7777

        def wait(self) -> int:
            return 0

    def fake_popen(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["kwargs"] = kwargs
        return FakeProcess()

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
        profile_id="hermes-cli",
        child_command=["hermes", "chat", "-q", "hello"],
        proxy_command="agentveil-mcp-proxy",
    )

    assert result.child_started is True
    assert result.child_foreground is True
    assert result.child_exit_code == 0
    assert result.status.child_running is False
    assert result.status.profile_status == "stopped"
    assert seen["kwargs"].get("stdout") is None
    assert seen["kwargs"].get("stderr") is None
    assert seen["kwargs"].get("start_new_session") is not True
    assert seen["command"] == [
        "hermes",
        "chat",
        "--toolsets",
        HERMES_MCP_TOOLSET,
        "-q",
        "hello",
    ]
    env = seen["env"]
    hermes_home = env[HERMES_HOME_ENV]
    assert hermes_home.startswith(str(home / "runtime" / "hermes-cli"))
    assert hermes_home.endswith("hermes-home")
    assert env["HOME"] == hermes_home
    assert env[HERMES_HOME_ENV] == hermes_home
    assert env[AGENTVEIL_RUNTIME_PROFILE_ENV] == "hermes-cli"
    assert hermes_config_path(Path(hermes_home)).exists()
    config_text = hermes_config_path(Path(hermes_home)).read_text(encoding="utf-8")
    assert HERMES_MCP_SERVER_NAME in config_text
    assert str(host_home) not in config_text

    route = json.loads(runtime_route_path(home).read_text(encoding="utf-8"))
    assert route["profile_id"] == "hermes-cli"
    assert route["hermes_mcp_server"] == HERMES_MCP_SERVER_NAME
    assert route["hermes_toolset"] == HERMES_MCP_TOOLSET

    proxy_config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    assert proxy_config["approval"]["wait_for_decision"] is True
    assert "native_tool_containment" in route
    assert str(host_home) not in json.dumps(route)


def test_launch_hermes_cli_data_minimization_gate(tmp_path, monkeypatch):
    host_home = tmp_path / "operator-home"
    host_home.mkdir()
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)
    provider_key = "sk-FAKE_HERMES_PROVIDER_KEY"

    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", provider_key)
    project = tmp_path / "project"
    project.mkdir()

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        if name == "agentveil-mcp-proxy":
            return "/usr/local/bin/agentveil-mcp-proxy"
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)
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
        lambda *_args, **_kwargs: type("FakeProcess", (), {"pid": 8888, "wait": lambda self: 0})(),
    )

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="hermes-cli",
        child_command=["hermes", "chat", "-q", f"secret:{provider_key}"],
        proxy_command="agentveil-mcp-proxy",
    )

    manifest_text = launch_manifest_path(home).read_text(encoding="utf-8")
    route_text = runtime_route_path(home).read_text(encoding="utf-8")
    status = build_launch_status(home=home, profile=HERMES_CLI_PROFILE, project_dir=project)
    config_paths = list((home / "runtime" / "hermes-cli").glob("*/hermes-home/config.yaml"))
    assert len(config_paths) == 1
    config_text = config_paths[0].read_text(encoding="utf-8")
    operator_visible = "\n".join((manifest_text, route_text, json.dumps(status.to_dict())))

    for forbidden in (provider_key, str(host_home), "/Users/"):
        assert forbidden not in operator_visible, f"forbidden persistence leak: {forbidden!r}"
    assert provider_key not in config_text


def test_preflight_hermes_cli_provider_missing_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AgentLauncherError, match="LLM provider key"):
        preflight_hermes_cli_provider({})


def test_launch_hermes_cli_passes_deepseek_key_to_child_env(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)
    provider_key = "sk-FAKE_DEEPSEEK_KEY"

    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("DEEPSEEK_API_KEY", provider_key)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    seen: dict[str, object] = {}

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        if name == "agentveil-mcp-proxy":
            return "/usr/local/bin/agentveil-mcp-proxy"
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )
    def fake_popen(_command, **kwargs):
        seen["env"] = kwargs["env"]
        return type("FakeProcess", (), {"pid": 9999, "wait": lambda self: 0})()

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.subprocess.Popen",
        fake_popen,
    )

    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="hermes-cli",
        child_command=["hermes", "chat", "-q", "hello"],
        proxy_command="agentveil-mcp-proxy",
    )

    env = seen["env"]
    assert env["DEEPSEEK_API_KEY"] == provider_key
    assert provider_key not in launch_manifest_path(home).read_text(encoding="utf-8")


def test_ensure_interactive_connector_defaults_preserves_other_approval_fields(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "approval": {
                    "approval_timeout_seconds": 120,
                    "on_timeout": "deny",
                    "ui_open_mode": "terminal",
                }
            }
        ),
        encoding="utf-8",
    )

    ensure_interactive_connector_defaults(config_path)

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["approval"]["wait_for_decision"] is True
    assert payload["approval"]["approval_timeout_seconds"] == 120
    assert payload["approval"]["on_timeout"] == "deny"
    assert payload["approval"]["ui_open_mode"] == "terminal"


def test_launch_hermes_cli_patches_existing_config_wait_for_decision(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)

    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-hermes-wait-mode")
    project = tmp_path / "project"
    project.mkdir()

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        if name == "agentveil-mcp-proxy":
            return "/usr/local/bin/agentveil-mcp-proxy"
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)
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
        lambda *_args, **_kwargs: SimpleNamespace(pid=7777, wait=lambda: 0),
    )

    home = project_avp_home(project)
    config_path = home / "mcp-proxy" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps(
            {
                "approval": {
                    "approval_timeout_seconds": 90,
                    "on_timeout": "deny",
                }
            }
        ),
        encoding="utf-8",
    )

    launch_managed_process(
        project_dir=project,
        profile_id="hermes-cli",
        child_command=["hermes", "chat", "-q", "hello"],
        proxy_command="agentveil-mcp-proxy",
    )

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["approval"]["wait_for_decision"] is True
    assert payload["approval"]["approval_timeout_seconds"] == 90
    assert payload["approval"]["on_timeout"] == "deny"


def test_launch_hermes_cli_fresh_init_sets_wait_for_decision(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)

    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-hermes-fresh-init")
    project = tmp_path / "project"
    project.mkdir()

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        if name == "agentveil-mcp-proxy":
            return "/usr/local/bin/agentveil-mcp-proxy"
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)
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
        lambda *_args, **_kwargs: SimpleNamespace(pid=7777, wait=lambda: 0),
    )

    def fake_init_proxy(*, home, **_kwargs):
        config_path = home / "mcp-proxy" / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"approval": {}}), encoding="utf-8")

    home = project_avp_home(project)
    launch_managed_process(
        project_dir=project,
        profile_id="hermes-cli",
        child_command=["hermes", "chat", "-q", "hello"],
        proxy_command="agentveil-mcp-proxy",
        init_proxy_if_missing=fake_init_proxy,
    )

    payload = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    assert payload["approval"]["wait_for_decision"] is True


def test_launch_generic_process_does_not_set_wait_for_decision(tmp_path, monkeypatch):
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
    config_path = home / "mcp-proxy" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")

    launch_managed_process(
        project_dir=project,
        profile_id="generic-process",
        child_command=["python", "-c", "print(1)"],
        proxy_command="agentveil-mcp-proxy",
    )

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert "wait_for_decision" not in payload.get("approval", {})


def test_build_launch_status_prefers_manifest_profile_id(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    save_launch_manifest(
        home,
        LaunchManifest(
            schema_version=LAUNCH_MANIFEST_SCHEMA_VERSION,
            profile_id="hermes-cli",
            session_id="session-status",
            child_pid=None,
            child_argv0="hermes",
            child_command_ref="hermes chat -q hello",
            started_at=1,
            project_dir_ref="project",
        ),
    )

    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: SimpleNamespace(state="running", pid=111, port=8765),
    )

    status = build_launch_status(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    assert status.profile_id == "hermes-cli"
    assert status.profile_status == "stopped"


def _center_state(state: str) -> CenterStatus:
    return CenterStatus(state=state, pid=111 if state == "running" else None, port=8765)


def test_launch_status_view_protection_mode_matrix():
    assert derive_protection_mode(
        mcp_route_state="missing",
        center=_center_state("running"),
        profile_id="generic-process",
    ) == "not protected"
    assert derive_protection_mode(
        mcp_route_state="configured",
        center=_center_state("running"),
        profile_id="generic-process",
    ) == "controlled MCP route"
    assert derive_protection_mode(
        mcp_route_state="configured",
        center=_center_state("running"),
        profile_id="hermes-cli",
    ) == "advisory"


def test_launch_status_view_json_fields(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    view = build_launch_status_view(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    payload = view.to_dict()

    assert payload["profile_label"] == GENERIC_PROCESS_PROFILE.display_name
    assert payload["protection_mode"] == "advisory"
    assert payload["mcp_route_state"] == "configured"
    assert payload["proof_hint"] == ""
    assert str(project) not in json.dumps(payload)


def test_launch_status_human_prefers_agent_proof_hint_when_observed(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher._evidence_record_count",
        lambda _home: 1,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: _center_state("running"),
    )
    view = build_launch_status_view(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    text = "\n".join(format_launch_status_human(view))

    assert "AgentVeil managed runtime status" in text
    assert LOCAL_PROOF_LAUNCHER_HINT in text
    assert "Proof hint:" in text
    assert "events show" not in text.lower()


def test_launch_status_human_omits_proof_hint_when_unavailable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    view = build_launch_status_view(
        home=project_avp_home(project),
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    text = "\n".join(format_launch_status_human(view))

    assert "Proof hint:" not in text
    assert LOCAL_PROOF_LAUNCHER_HINT not in text
    assert "Initialize the project proxy route" in text


def test_launch_diagnostics_cover_stale_center_and_native_bypass():
    status = LaunchStatus(
        profile_id="hermes-cli",
        profile_status="configured",
        project_dir_ref="project",
        session_id=None,
        approval_center=_center_state("stale"),
        child_running=False,
        child_pid=None,
        evidence_enabled=False,
        scope="project",
        host_wide_control_claim=False,
    )
    diagnostics = build_launch_diagnostics(
        status=status,
        mcp_route_state="configured",
        evidence_state="ready_no_records",
        profile_id="hermes-cli",
        protection_mode="advisory",
    )
    joined = " ".join(diagnostics).lower()
    assert "approval center" in joined
    assert "native hermes" in joined


def test_classify_launch_route_and_evidence_states(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    assert classify_mcp_route_state(home) == "missing"
    assert classify_evidence_state(home=home, config_exists=False) == "not_initialized"

    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    assert classify_mcp_route_state(home) == "configured"
    assert classify_evidence_state(home=home, config_exists=True) == "ready_no_records"


def test_launch_result_payload_includes_child_outcome(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    view = build_launch_status_view(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
    )
    status = LaunchStatus(
        profile_id="generic-process",
        profile_status="stopped",
        project_dir_ref="project",
        session_id="session-1",
        approval_center=_center_state("running"),
        child_running=False,
        child_pid=None,
        evidence_enabled=True,
        scope="project",
        host_wide_control_claim=False,
    )
    result = LaunchResult(
        status=status,
        child_started=True,
        approval_center_started=True,
        proxy_initialized=True,
        reason="started",
        child_exit_code=0,
        child_foreground=True,
    )
    payload = build_launch_result_payload(result=result, view=view)
    assert payload["child_outcome"] == "finished"
    assert payload["proof_hint"] == ""


def test_launch_doctor_empty_project_is_not_ready(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    report = build_launch_doctor_report(
        home=project_avp_home(project),
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
        parent_env={},
    )
    assert report.project_route == "missing"
    assert report.local_proof == "not initialized"
    assert report.ready is False
    assert report.provider_key == "not applicable"
    assert "project_route" in report.blocking


def test_launch_doctor_configured_route_without_evidence(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text(
        json.dumps({"approval": {"wait_for_decision": True}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: _center_state("running"),
    )
    report = build_launch_doctor_report(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
        parent_env={},
    )
    assert report.project_route == "ready"
    assert report.local_proof == "empty"
    assert report.approval_center == "running"
    assert report.approval_wait == "not applicable"


def test_launch_doctor_observed_proof(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    now = 1_700_000_000
    record = PendingApproval(
        request_id="req-doctor-proof",
        session_id="session-1",
        client_id="cursor:session-7",
        downstream_server="filesystem",
        tool_name="filesystem.read",
        action_class="read",
        risk_class="read",
        resource_hash="sha256:" + "b" * 64,
        payload_hash="sha256:" + "a" * 64,
        policy_id="filesystem-default",
        policy_rule_id="rule-read",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.PENDING.value,
        created_at=now,
        expires_at=now + 3600,
    )
    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        store.write_pending(record)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: _center_state("running"),
    )
    report = build_launch_doctor_report(
        home=home,
        profile=GENERIC_PROCESS_PROFILE,
        project_dir=project,
        parent_env={},
    )
    assert report.local_proof == "observed"
    assert report.evidence_state == "observed"


def test_launch_doctor_hermes_provider_present_without_leaking_secret(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text(
        json.dumps({"approval": {"wait_for_decision": True}}),
        encoding="utf-8",
    )
    secret = "sk-test-secret-doctor-1234567890"
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: _center_state("running"),
    )
    report = build_launch_doctor_report(
        home=home,
        profile=HERMES_CLI_PROFILE,
        project_dir=project,
        parent_env={"OPENAI_API_KEY": secret},
    )
    text = "\n".join(format_launch_doctor_human(report))
    assert report.provider_key == "present"
    assert secret not in text
    assert secret not in json.dumps(report.to_dict())


def test_launch_doctor_hermes_provider_missing(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    report = build_launch_doctor_report(
        home=home,
        profile=HERMES_CLI_PROFILE,
        project_dir=project,
        parent_env={},
    )
    assert report.provider_key == "missing"
    assert report.approval_wait == "not configured"
    assert "provider_key" in report.blocking


def test_classify_approval_wait_mode_read_only(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    config_path = home / "mcp-proxy" / "config.json"
    assert classify_approval_wait_mode(home, GENERIC_PROCESS_PROFILE) == "not applicable"
    assert classify_approval_wait_mode(home, HERMES_CLI_PROFILE) == "not configured"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps({"approval": {"wait_for_decision": False}}), encoding="utf-8")
    assert classify_approval_wait_mode(home, HERMES_CLI_PROFILE) == "not configured"
    before = config_path.read_text(encoding="utf-8")
    config_path.write_text(json.dumps({"approval": {"wait_for_decision": True}}), encoding="utf-8")
    assert classify_approval_wait_mode(home, HERMES_CLI_PROFILE) == "enabled"
    ensure_interactive_connector_defaults(config_path)
    assert config_path.read_text(encoding="utf-8") != before
