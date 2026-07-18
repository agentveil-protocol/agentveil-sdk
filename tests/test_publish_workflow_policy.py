"""Release workflow runtime and diagnostic guardrails."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
PROXY_TESTS = ROOT / "packages" / "agentveil-mcp-proxy" / "tests"


def _workflow_text() -> str:
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def test_publish_compatibility_and_publish_jobs_have_hard_timeouts() -> None:
    text = _workflow_text()
    assert "workflow_dispatch:" in text
    assert text.count("timeout-minutes: 35") == 1
    assert text.count("timeout-minutes: 15") == 1
    assert "if: startsWith(github.ref, 'refs/tags/')" in text


def test_publish_runs_each_test_suite_once_with_actionable_hang_diagnostics() -> None:
    text = _workflow_text()
    sdk_commands = re.findall(r"python -m pytest -v tests(?:\s|$)", text)
    proxy_commands = re.findall(
        r"python -m pytest -v packages/agentveil-mcp-proxy/tests(?:\s|$)",
        text,
    )
    assert len(sdk_commands) == 1
    assert len(proxy_commands) == 1
    assert text.count("--durations=50 --durations-min=1.0") == 2
    assert text.count("-o faulthandler_timeout=120") == 2


def test_process_tests_do_not_block_on_live_child_stderr_eof() -> None:
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in PROXY_TESTS.glob("test_*.py")
        if ".stderr.read()" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
