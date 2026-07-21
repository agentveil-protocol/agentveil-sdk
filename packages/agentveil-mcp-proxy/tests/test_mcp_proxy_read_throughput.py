"""AV-09 read throughput reproduction, localization, and post-fix proof."""

from __future__ import annotations

import io
import json
import os
import queue
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream, run_proxy
from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceStore
from agentveil_mcp_proxy.passthrough import (
    STDIO_DIAGNOSTIC_WORKERS,
    STDIO_MUTATION_PENDING_WORKERS,
    STDIO_READ_CONCURRENCY,
    STDIO_REQUEST_WORKERS,
)
from agentveil_mcp_proxy.quickstart_filesystem import QUICKSTART_READ_POOL_SIZE

WAVE_SIZE = 20
WAVE_COUNT = 5
TOTAL_READS = WAVE_SIZE * WAVE_COUNT
BURST_SIZE = 20
ARTIFICIAL_READ_DELAY_SECONDS = 0.03
POST_FIX_MEDIAN_TOTAL_MAX = 5.0
POST_FIX_MEDIAN_WAVE_MAX = 2.0
SERIAL_BASELINE_MIN_TOTAL = 2.5
MIN_CONCURRENCY_SPEEDUP_RATIO = 0.35
READ_BATCH_TIMEOUT_SECONDS = 30.0
SUBPROCESS_HARD_TIMEOUT_SECONDS = 60.0
LOCAL_PATH_MARKERS = ("/Users/", "/private/var/", "/tmp/")
SECRET = "super-secret-file-body-not-for-evidence"


def _json_line(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _tool_call(tool: str, arguments: dict[str, Any], *, call_id: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })


def _initialize_lines() -> list[str]:
    return [
        _json_line({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "av09-test", "version": "0"},
            },
        }),
        _json_line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"}),
    ]


def _seed_read_target(sandbox: Path) -> Path:
    target = sandbox / "notes.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("bounded read fixture body", encoding="utf-8")
    return target


def _init_quickstart_home(home: Path, sandbox: Path) -> None:
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )


def _configure_downstream_script(home: Path, script: Path) -> None:
    config_path = home / "mcp-proxy" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "filesystem",
        "command": sys.executable,
        "args": [str(script)],
        "response_timeout_seconds": 5.0,
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)


def _write_instrumented_read_downstream(
    tmp_path: Path,
    *,
    serial: bool,
    delay_seconds: float,
) -> Path:
    script = tmp_path / ("serial_read_fixture.py" if serial else "concurrent_read_fixture.py")
    script.write_text(
        f"""
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TOOLS = [{{"name": "read_file", "description": "read", "inputSchema": {{
    "type": "object",
    "properties": {{"path": {{"type": "string"}}}},
    "required": ["path"],
    "additionalProperties": False,
}}}}]
DELAY = {delay_seconds!r}
SERIAL = {serial!r}
POOL = ThreadPoolExecutor(max_workers=20)
LOCK = threading.Lock()
OUT = threading.Lock()

def emit(resp):
    with OUT:
        sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\\n")
        sys.stdout.flush()

def handle(msg):
    time.sleep(DELAY)
    return {{"jsonrpc": "2.0", "id": msg.get("id"), "result": {{
        "content": [{{"type": "text", "text": "fixture-ok"}}],
    }}}}

def dispatch(msg):
    if SERIAL:
        with LOCK:
            emit(handle(msg))
        return
    POOL.submit(lambda message=msg: emit(handle(message)))

for raw in sys.stdin:
    msg = json.loads(raw)
    method = msg.get("method")
    request_id = msg.get("id")
    if method == "initialize":
        emit({{"jsonrpc": "2.0", "id": request_id, "result": {{
            "protocolVersion": "2024-11-05",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "instrumented-fixture", "version": "0"}},
        }}}})
        continue
    if method == "tools/list":
        emit({{"jsonrpc": "2.0", "id": request_id, "result": {{"tools": TOOLS}}}})
        continue
    if method == "tools/call":
        dispatch(msg)
        continue
    if request_id is not None:
        emit({{"jsonrpc": "2.0", "id": request_id, "result": {{}}}})

POOL.shutdown(wait=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


@dataclass(frozen=True)
class LoadMetrics:
    total_seconds: float
    wave_seconds: tuple[float, ...]
    latencies: tuple[float, ...]
    response_count: int
    missing_ids: tuple[str, ...]
    duplicate_ids: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def p50(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0.0

    @property
    def p95(self) -> float:
        if not self.latencies:
            return 0.0
        ordered = sorted(self.latencies)
        index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
        return ordered[index]


class _StdoutReader:
    """Line reader with a bounded timeout independent of blocking readline()."""

    def __init__(self, stdout) -> None:
        self._stdout = stdout
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="av09-stdout-reader", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            line = self._stdout.readline()
            if line == "":
                self._lines.put(None)
                return
            self._lines.put(line)

    def read_until(self, *, expected: int, timeout: float) -> list[str]:
        collected: list[str] = []
        deadline = time.monotonic() + timeout
        while len(collected) < expected:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                break
            if line.strip():
                collected.append(line)
        return collected

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)


class _ProxySubprocess:
    def __init__(self, *, home: Path) -> None:
        env = os.environ.copy()
        env["HOME"] = str(home)
        self._stderr_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agentveil_mcp_proxy.cli",
                "run",
                "--home",
                str(home),
                "--approval-ui-mode",
                "none",
                "--headless",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            text=True,
            bufsize=1,
            env=env,
        )
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        self._reader = _StdoutReader(self._proc.stdout)

    def send(self, line: str) -> None:
        if not line.endswith("\n"):
            line = line + "\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()

    def close_stdin(self) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.close()

    def terminate(self, *, timeout: float = 10.0) -> int:
        self._reader.close()
        if self._proc.poll() is None:
            self.close_stdin()
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5.0)
        self._stderr_file.flush()
        self._stderr_file.seek(0)
        stderr = self._stderr_file.read()
        self._stderr_file.close()
        if self._proc.returncode not in (0, None):
            raise AssertionError(
                f"proxy subprocess failed rc={self._proc.returncode}: {stderr}"
            )
        return int(self._proc.returncode or 0)


def _read_responses(
    reader: _StdoutReader,
    *,
    expected: int,
    timeout: float,
) -> list[dict[str, Any]]:
    lines = reader.read_until(expected=expected, timeout=timeout)
    return [json.loads(line) for line in lines]


def _run_read_burst(
    session: _ProxySubprocess,
    *,
    burst_size: int,
    id_prefix: str,
    path: str = "notes.txt",
) -> tuple[list[dict[str, Any]], list[float]]:
    send_times: dict[str, float] = {}
    for index in range(burst_size):
        call_id = f"{id_prefix}-{index}"
        send_times[call_id] = time.monotonic()
        session.send(_tool_call("read_file", {"path": path}, call_id=call_id))
    responses = _read_responses(
        session._reader,
        expected=burst_size,
        timeout=READ_BATCH_TIMEOUT_SECONDS,
    )
    latencies: list[float] = []
    for response in responses:
        call_id = str(response.get("id"))
        if call_id in send_times:
            latencies.append(time.monotonic() - send_times[call_id])
    return responses, latencies


def _collect_load_metrics(session: _ProxySubprocess) -> LoadMetrics:
    wave_seconds: list[float] = []
    latencies: list[float] = []
    all_responses: list[dict[str, Any]] = []
    expected_ids = [f"read-{wave}-{index}" for wave in range(WAVE_COUNT) for index in range(WAVE_SIZE)]

    total_start = time.monotonic()
    for wave in range(WAVE_COUNT):
        wave_start = time.monotonic()
        responses, wave_latencies = _run_read_burst(
            session,
            burst_size=WAVE_SIZE,
            id_prefix=f"read-{wave}",
        )
        wave_seconds.append(time.monotonic() - wave_start)
        latencies.extend(wave_latencies)
        all_responses.extend(responses)
    total_seconds = time.monotonic() - total_start

    by_id: dict[str, int] = {}
    errors: list[str] = []
    for response in all_responses:
        call_id = str(response.get("id"))
        by_id[call_id] = by_id.get(call_id, 0) + 1
        if "error" in response:
            errors.append(call_id)

    missing = tuple(call_id for call_id in expected_ids if by_id.get(call_id, 0) == 0)
    duplicate = tuple(call_id for call_id, count in by_id.items() if count > 1)
    return LoadMetrics(
        total_seconds=total_seconds,
        wave_seconds=tuple(wave_seconds),
        latencies=tuple(latencies),
        response_count=len(all_responses),
        missing_ids=missing,
        duplicate_ids=duplicate,
        errors=tuple(errors),
    )


def _median_of_runs(runs: list[LoadMetrics], attr: str) -> float:
    return statistics.median(getattr(run, attr) for run in runs)


def _run_load_harness(home: Path) -> list[LoadMetrics]:
    runs: list[LoadMetrics] = []
    for _ in range(3):
        session = _ProxySubprocess(home=home)
        try:
            for line in _initialize_lines():
                session.send(line)
            _read_responses(session._reader, expected=2, timeout=10.0)
            runs.append(_collect_load_metrics(session))
        finally:
            session.terminate()
    return runs


def _assert_no_path_or_secret_leaks(*parts: str) -> None:
    blob = "\n".join(parts)
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in blob, f"unexpected host path marker {marker!r}"
    assert SECRET not in blob


def _wait_until(predicate, *, timeout: float = 2.0, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class _LineStdin:
    def __init__(self) -> None:
        self._lines: queue.Queue[str | None] = queue.Queue()

    def write_line(self, line: str) -> None:
        self._lines.put(line if line.endswith("\n") else line + "\n")

    def close(self) -> None:
        self._lines.put(None)

    def readline(self) -> str:
        line = self._lines.get()
        if line is None:
            return ""
        return line

    def __iter__(self):
        while True:
            line = self._lines.get()
            if line is None:
                return
            yield line


@pytest.fixture()
def av09_env(tmp_path: Path):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _seed_read_target(sandbox)
    _init_quickstart_home(home, sandbox)
    return home, sandbox


def test_worker_budget_is_explicit_for_av09_read_throughput():
    assert STDIO_DIAGNOSTIC_WORKERS == STDIO_READ_CONCURRENCY
    assert STDIO_MUTATION_PENDING_WORKERS == 2
    assert STDIO_REQUEST_WORKERS == STDIO_DIAGNOSTIC_WORKERS + STDIO_MUTATION_PENDING_WORKERS
    assert QUICKSTART_READ_POOL_SIZE == STDIO_READ_CONCURRENCY


def test_quickstart_concurrent_reads_proven_by_test_only_barrier(monkeypatch, tmp_path):
    import agentveil_mcp_proxy.quickstart_filesystem as quickstart

    sandbox = tmp_path / "sandbox"
    _seed_read_target(sandbox)
    original_handle = quickstart.handle_message
    peak = {"value": 0}
    active = {"count": 0}
    probe_lock = threading.Lock()
    entered = threading.Barrier(BURST_SIZE)

    def instrumented_handle(root: Path, message: dict[str, Any]) -> dict[str, Any] | None:
        if (
            isinstance(message, dict)
            and message.get("method") == "tools/call"
            and isinstance(message.get("params"), dict)
            and message["params"].get("name") == "read_file"
        ):
            with probe_lock:
                active["count"] += 1
                peak["value"] = max(peak["value"], active["count"])
            try:
                entered.wait(timeout=3.0)
                return original_handle(root, message)
            finally:
                with probe_lock:
                    active["count"] -= 1
        return original_handle(root, message)

    monkeypatch.setattr(quickstart, "handle_message", instrumented_handle)

    stdin = _LineStdin()
    stdout_buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout_buffer)

    runner = threading.Thread(target=lambda: quickstart.main([str(sandbox)]), daemon=True)
    runner.start()
    try:
        for line in _initialize_lines():
            stdin.write_line(line.rstrip("\n"))
        for index in range(BURST_SIZE):
            stdin.write_line(
                _tool_call("read_file", {"path": "notes.txt"}, call_id=f"qs-{index}").rstrip("\n")
            )
        stdin.close()
        runner.join(timeout=10.0)
        assert not runner.is_alive()
    finally:
        stdin.close()

    responses = [json.loads(line) for line in stdout_buffer.getvalue().splitlines() if line.strip()]
    read_responses = [item for item in responses if str(item.get("id", "")).startswith("qs-")]
    assert len(read_responses) == BURST_SIZE
    assert peak["value"] >= min(BURST_SIZE, QUICKSTART_READ_POOL_SIZE)


def test_quickstart_read_semaphore_overload_and_recovery(monkeypatch, tmp_path):
    import agentveil_mcp_proxy.quickstart_filesystem as quickstart

    sandbox = tmp_path / "sandbox"
    _seed_read_target(sandbox)
    original_handle = quickstart.handle_message
    hold_gate = threading.Event()
    entered_count = {"value": 0}
    probe_lock = threading.Lock()

    def instrumented_handle(root: Path, message: dict[str, Any]) -> dict[str, Any] | None:
        if (
            isinstance(message, dict)
            and message.get("method") == "tools/call"
            and isinstance(message.get("params"), dict)
            and message["params"].get("name") == "read_file"
        ):
            with probe_lock:
                entered_count["value"] += 1
            assert hold_gate.wait(timeout=5.0)
            return original_handle(root, message)
        return original_handle(root, message)

    monkeypatch.setattr(quickstart, "handle_message", instrumented_handle)
    stdin = _LineStdin()
    stdout_buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout_buffer)

    runner = threading.Thread(target=lambda: quickstart.main([str(sandbox)]), daemon=True)
    runner.start()
    try:
        for line in _initialize_lines():
            stdin.write_line(line.rstrip("\n"))
        for index in range(QUICKSTART_READ_POOL_SIZE):
            stdin.write_line(
                _tool_call("read_file", {"path": "notes.txt"}, call_id=f"hold-{index}").rstrip("\n")
            )
        assert _wait_until(
            lambda: entered_count["value"] >= QUICKSTART_READ_POOL_SIZE,
            timeout=5.0,
        )

        stdin.write_line(
            _tool_call("read_file", {"path": "notes.txt"}, call_id="overload-21").rstrip("\n")
        )
        assert _wait_until(lambda: "overload-21" in stdout_buffer.getvalue(), timeout=2.0)
        overload = json.loads(
            next(line for line in stdout_buffer.getvalue().splitlines() if "overload-21" in line)
        )
        assert overload["id"] == "overload-21"
        assert overload["error"]["code"] == -32000
        assert overload["error"]["message"] == "read concurrency limit reached"

        hold_gate.set()
        def held_reads_completed() -> bool:
            responses_by_id = {
                str(json.loads(line).get("id")): json.loads(line)
                for line in stdout_buffer.getvalue().splitlines()
                if line.strip()
            }
            for index in range(QUICKSTART_READ_POOL_SIZE):
                if "result" not in responses_by_id.get(f"hold-{index}", {}):
                    return False
            return True

        assert _wait_until(held_reads_completed, timeout=5.0)
        stdin.write_line(
            _tool_call("read_file", {"path": "notes.txt"}, call_id="recovery-22").rstrip("\n")
        )
        stdin.close()
        runner.join(timeout=10.0)
        assert not runner.is_alive()
    finally:
        hold_gate.set()
        stdin.close()

    responses = [json.loads(line) for line in stdout_buffer.getvalue().splitlines() if line.strip()]
    by_id = {str(item.get("id")): item for item in responses}
    for index in range(QUICKSTART_READ_POOL_SIZE):
        assert "result" in by_id[f"hold-{index}"]
    assert "result" in by_id["recovery-22"]


def test_apples_to_apples_serial_vs_concurrent_instrumented_fixture(av09_env, tmp_path):
    home, _sandbox = av09_env
    delay_seconds = ARTIFICIAL_READ_DELAY_SECONDS

    serial_script = _write_instrumented_read_downstream(
        tmp_path,
        serial=True,
        delay_seconds=delay_seconds,
    )
    _configure_downstream_script(home, serial_script)
    serial_runs = _run_load_harness(home)
    serial_median_total = _median_of_runs(serial_runs, "total_seconds")
    serial_median_wave = statistics.median(
        statistics.mean(run.wave_seconds) for run in serial_runs
    )

    concurrent_script = _write_instrumented_read_downstream(
        tmp_path,
        serial=False,
        delay_seconds=delay_seconds,
    )
    _configure_downstream_script(home, concurrent_script)
    concurrent_runs = _run_load_harness(home)
    concurrent_median_total = _median_of_runs(concurrent_runs, "total_seconds")
    concurrent_median_wave = statistics.median(
        statistics.mean(run.wave_seconds) for run in concurrent_runs
    )

    assert serial_median_total >= SERIAL_BASELINE_MIN_TOTAL
    assert concurrent_median_total <= serial_median_total * MIN_CONCURRENCY_SPEEDUP_RATIO
    assert concurrent_median_total <= POST_FIX_MEDIAN_TOTAL_MAX
    assert concurrent_median_wave <= POST_FIX_MEDIAN_WAVE_MAX
    assert serial_median_wave > concurrent_median_wave


def test_av09_read_load_exact_response_matrix_and_regression_threshold(av09_env):
    home, _sandbox = av09_env
    runs = _run_load_harness(home)
    median_total = _median_of_runs(runs, "total_seconds")
    median_wave = statistics.median(statistics.mean(run.wave_seconds) for run in runs)
    sample = runs[1]

    assert sample.response_count == TOTAL_READS
    assert sample.missing_ids == ()
    assert sample.duplicate_ids == ()
    assert sample.errors == ()
    assert len(sample.wave_seconds) == WAVE_COUNT
    assert sample.p50 > 0
    assert sample.p95 >= sample.p50
    assert median_total <= POST_FIX_MEDIAN_TOTAL_MAX
    assert median_wave <= POST_FIX_MEDIAN_WAVE_MAX
    assert median_total < SUBPROCESS_HARD_TIMEOUT_SECONDS


def test_mixed_load_wave_matches_stress_report(av09_env):
    home, _sandbox = av09_env
    session = _ProxySubprocess(home=home)
    try:
        for line in _initialize_lines():
            session.send(line)
        _read_responses(session._reader, expected=2, timeout=10.0)

        for index in range(10):
            session.send(
                _tool_call("read_file", {"path": "notes.txt"}, call_id=f"mix-read-{index}")
            )
        for index in range(9):
            session.send(
                _tool_call(
                    "read_file",
                    {"path": f"../outside-{index}.txt"},
                    call_id=f"mix-deny-{index}",
                )
            )
        session.send(
            _json_line({
                "jsonrpc": "2.0",
                "id": "mix-proof",
                "method": "tools/call",
                "params": {
                    "name": "local_proof",
                    "arguments": {"last": 1, "verify": False},
                },
            })
        )

        responses = _read_responses(session._reader, expected=20, timeout=READ_BATCH_TIMEOUT_SECONDS)
        by_id = {str(item.get("id")): item for item in responses}
        assert len(by_id) == 20
        for index in range(10):
            assert "result" in by_id[f"mix-read-{index}"]
        for index in range(9):
            assert by_id[f"mix-deny-{index}"]["error"]["data"]["reason"] == "path_outside_workspace"
        assert "result" in by_id["mix-proof"]
    finally:
        session.terminate()


def test_slow_read_does_not_block_independent_fast_reads(av09_env, tmp_path):
    home, sandbox = av09_env
    slow_script = tmp_path / "slow_read_fixture.py"
    slow_script.write_text(
        """
import json, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

TOOLS = [{"name": "read_file", "description": "read", "inputSchema": {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}}]
SLOW = "slow.txt"
GATE = threading.Event()
POOL = ThreadPoolExecutor(max_workers=8)
OUT = threading.Lock()

def emit(resp):
    with OUT:
        sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\\n")
        sys.stdout.flush()

def handle(msg):
    args = (msg.get("params") or {}).get("arguments") or {}
    if args.get("path") == SLOW:
        GATE.wait(timeout=5.0)
        time.sleep(0.05)
    else:
        time.sleep(0.01)
    return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {
        "content": [{"type": "text", "text": "ok"}],
    }}

for raw in sys.stdin:
    msg = json.loads(raw)
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "slow-fixture", "version": "0"},
        }})
        continue
    if method == "tools/list":
        emit({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        continue
    if method == "tools/call":
        POOL.submit(lambda message=msg: emit(handle(message)))
        continue
    if rid is not None:
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})

POOL.shutdown(wait=True)
""".lstrip(),
        encoding="utf-8",
    )
    _configure_downstream_script(home, slow_script)
    (sandbox / "slow.txt").write_text("slow", encoding="utf-8")

    session = _ProxySubprocess(home=home)
    try:
        for line in _initialize_lines():
            session.send(line)
        _read_responses(session._reader, expected=2, timeout=10.0)
        session.send(_tool_call("read_file", {"path": "slow.txt"}, call_id="slow-1"))
        time.sleep(0.05)
        fast_start = time.monotonic()
        for index in range(8):
            session.send(
                _tool_call("read_file", {"path": "notes.txt"}, call_id=f"fast-{index}")
            )
        fast_responses = _read_responses(session._reader, expected=8, timeout=READ_BATCH_TIMEOUT_SECONDS)
        fast_elapsed = time.monotonic() - fast_start
        assert len(fast_responses) == 8
        assert fast_elapsed < 2.0
    finally:
        session.terminate()


def test_eof_shutdown_reaps_stdio_worker_threads(av09_env):
    home, _sandbox = av09_env
    from test_mcp_proxy_approval_nonblocking import (
        _ThreadSafeClientOut,
        _TrackingTextIO,
        _stdio_worker_threads,
    )

    before_ids = {id(thread) for thread in threading.enumerate()}
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    runner = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode="none",
            headless=True,
        ),
        daemon=True,
    )
    runner.start()
    try:
        assert _wait_until(
            lambda: len([
                thread
                for thread in _stdio_worker_threads()
                if id(thread) not in before_ids
            ]) >= STDIO_DIAGNOSTIC_WORKERS,
            timeout=5.0,
        )
        for line in _initialize_lines():
            client_in.write_line(line.rstrip("\n"))
        assert _wait_until(lambda: len(client_out.responses()) >= 2, timeout=5.0)
        proof_snapshot = list(client_out.responses())
        session_workers = [
            thread
            for thread in _stdio_worker_threads()
            if id(thread) not in before_ids
        ]
        assert len(session_workers) == STDIO_REQUEST_WORKERS
        client_in.close()
        runner.join(timeout=10.0)
        assert not runner.is_alive()
        for worker_thread in session_workers:
            assert not worker_thread.is_alive(), worker_thread.name
        assert client_out.responses() == proof_snapshot
    finally:
        client_in.close()


def test_subprocess_eof_exits_cleanly(av09_env):
    home, _sandbox = av09_env
    session = _ProxySubprocess(home=home)
    try:
        for line in _initialize_lines():
            session.send(line)
        proof = _read_responses(session._reader, expected=2, timeout=10.0)
        assert len(proof) == 2
        session.close_stdin()
    finally:
        rc = session.terminate()
        assert rc == 0


def test_read_privacy_no_raw_paths_or_content_in_evidence(av09_env):
    home, sandbox = av09_env
    session = _ProxySubprocess(home=home)
    try:
        for line in _initialize_lines():
            session.send(line)
        _read_responses(session._reader, expected=2, timeout=10.0)
        session.send(_tool_call("read_file", {"path": "notes.txt"}, call_id="privacy-1"))
        responses = _read_responses(session._reader, expected=1, timeout=READ_BATCH_TIMEOUT_SECONDS)
        assert "result" in responses[0]
        response_text = json.dumps(responses[0])
    finally:
        session.terminate()

    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    assert evidence_path.exists()
    with ApprovalEvidenceStore(evidence_path) as store:
        blob = json.dumps([record.__dict__ for record in store.list_records()], default=str)
    _assert_no_path_or_secret_leaks(blob, response_text)
    assert str(sandbox) not in blob
    assert "bounded read fixture body" not in blob
