"""Release workflow runtime and diagnostic guardrails."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
TESTS_WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
PROXY_TESTS = ROOT / "packages" / "agentveil-mcp-proxy" / "tests"


def _workflow_text() -> str:
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def test_publish_jobs_have_bounded_timeouts_and_tag_only_publish() -> None:
    text = _workflow_text()
    assert "workflow_dispatch:" in text
    assert text.count("timeout-minutes: 30") == 1
    assert text.count("timeout-minutes: 12") == 1
    assert text.count("timeout-minutes: 10") == 1
    assert text.count("timeout-minutes: 15") == 1
    assert "if: startsWith(github.ref, 'refs/tags/')" in text


def test_release_runs_each_full_suite_once_with_actionable_hang_diagnostics() -> None:
    publish_text = _workflow_text()
    tests_text = TESTS_WORKFLOW.read_text(encoding="utf-8")
    sdk_commands = re.findall(r"python -m pytest -v tests(?:\s|$)", publish_text)
    proxy_commands = re.findall(
        r"python -m pytest -v packages/agentveil-mcp-proxy/tests(?:\s|$)",
        publish_text,
    )
    assert len(sdk_commands) == 1
    assert len(proxy_commands) == 1
    assert publish_text.count("--durations=50 --durations-min=1.0") == 2
    assert publish_text.count("-o faulthandler_timeout=120") == 2
    assert 'tags: ["v*"]' not in tests_text
    assert "compatibility-full:" not in tests_text


def test_publish_uses_bounded_python_os_and_approval_center_jobs() -> None:
    text = _workflow_text()
    assert "full-suite:" in text
    assert "compatibility-smoke:" in text
    assert "approval-center-e2e:" in text
    assert "needs: [full-suite, compatibility-smoke, approval-center-e2e]" in text

    assert text.count('python-version: "3.10"') == 1
    assert text.count('python-version: "3.11"') == 1
    assert text.count('python-version: "3.13"') == 1
    assert text.count("- os: windows-latest") == 1
    assert text.count("- os: macos-latest") == 1
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in text

    assert text.count("Run bounded compatibility smoke") == 1
    assert text.count("Run managed Approval Center process E2E") == 1
    assert (
        text.count(
            "test_run_proxy_cancelled_request_shows_terminal_managed_center_page"
        )
        == 1
    )


def test_process_tests_do_not_block_on_live_child_stderr_eof() -> None:
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in PROXY_TESTS.glob("test_*.py")
        if ".stderr.read()" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
