"""Deterministic symlink TOCTOU races for quickstart filesystem mutations.

Two race windows are modeled explicitly:

* **pre_fd_binding** — swap after ``_resolved_mutation_parts`` and before any
  directory fd is opened. Must return an error; outside/control canaries unchanged.
* **post_fd_binding** — swap after ``_walk_parent_for_mutation`` and before the final
  syscall. The replacement symlink target must remain unchanged.
  Parent-directory replacement may mutate only the previously bound directory
  inode; pathname stability and outside-canary immutability are not claimed.
"""

from __future__ import annotations

import ctypes
import json
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

import agentveil_mcp_proxy.quickstart_filesystem as qfs

LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")
OUTSIDE_MARKER = "OUTSIDE_CANARY_UNCHANGED"
CONTROL_MARKER = "CONTROL_CANARY_UNCHANGED"
DECOY_MARKER = "SYMLINK_TARGET_DECOY_UNCHANGED"
ATTACK_PAYLOAD = "TOCTOU_ATTACK_PAYLOAD"
MUTATION_UNAVAILABLE = "filesystem mutation unavailable on this platform"


def _seed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _call(root: Path, tool: str, arguments: dict, request_id: str = "toctou"):
    return qfs._handle_tools_call(root, request_id, {"name": tool, "arguments": arguments})


def _assert_privacy(blob: str) -> None:
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in blob, f"leaked local path marker {marker!r}"
    assert OUTSIDE_MARKER not in blob
    assert CONTROL_MARKER not in blob
    assert DECOY_MARKER not in blob
    assert "fixture-session-token-not-real" not in blob


def _prepare_canaries(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside-canary.txt"
    outside.write_text(OUTSIDE_MARKER, encoding="utf-8")
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    _seed(outside_dir / "decoy.txt", DECOY_MARKER)
    control_dir = sandbox / ".avp" / "mcp-proxy"
    control_dir.mkdir(parents=True)
    control = control_dir / "approval-center.manifest.json"
    control.write_text(
        json.dumps({"session_token": "fixture-session-token-not-real", "marker": CONTROL_MARKER}),
        encoding="utf-8",
    )
    return sandbox, outside, control, control_dir, outside_dir


def _swap_final_to_outside(target: Path, outside: Path) -> None:
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(outside)


def _swap_final_to_control(target: Path, control: Path) -> None:
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(control)


def _swap_parent_to_symlink(parent: Path, link_target: Path) -> Path:
    """Move the real parent directory aside and leave a symlink at ``parent``."""

    backup = parent.with_name(parent.name + ".bound-toctou")
    if backup.exists():
        raise RuntimeError(f"backup path exists: {backup}")
    if parent.is_symlink() or parent.is_file():
        parent.unlink()
    else:
        parent.rename(backup)
    parent.symlink_to(link_target, target_is_directory=True)
    return backup


def _install_pre_fd_barrier(
    monkeypatch: pytest.MonkeyPatch,
    *,
    swap: Callable[[], None],
    match_requested: str | None = None,
    timeout: float = 5.0,
) -> threading.Thread:
    ready = threading.Event()
    proceed = threading.Event()
    swap_error: list[BaseException] = []
    original = qfs._resolved_mutation_parts

    def _racing_parts(root: Path, requested: str) -> tuple[list[str], Path]:
        result = original(root, requested)
        normalized = requested.replace("\\", "/")
        if match_requested is not None and normalized != match_requested:
            return result
        ready.set()
        assert proceed.wait(timeout=timeout), "timed out waiting for pre-FD TOCTOU swap"
        return result

    def _attacker() -> None:
        try:
            assert ready.wait(timeout=timeout), "timed out waiting for validation"
            swap()
        except BaseException as exc:  # noqa: BLE001
            swap_error.append(exc)
        finally:
            proceed.set()

    monkeypatch.setattr(qfs, "_resolved_mutation_parts", _racing_parts)
    thread = threading.Thread(target=_attacker, name="toctou-pre-fd", daemon=True)
    thread.start()
    monkeypatch.setattr(
        qfs,
        "_toctou_test_finalize",
        lambda: (_assert_no_swap_error(swap_error), thread.join(timeout=timeout)),
        raising=False,
    )
    return thread


def _install_post_fd_barrier(
    monkeypatch: pytest.MonkeyPatch,
    *,
    swap: Callable[[], None],
    walk_index: int = 1,
    timeout: float = 5.0,
) -> threading.Thread:
    ready = threading.Event()
    proceed = threading.Event()
    swap_error: list[BaseException] = []
    seen = {"walks": 0}
    original = qfs._walk_parent_for_mutation

    def _racing_walk(*args, **kwargs):
        result = original(*args, **kwargs)
        seen["walks"] += 1
        if seen["walks"] != walk_index:
            return result
        ready.set()
        assert proceed.wait(timeout=timeout), "timed out waiting for post-FD TOCTOU swap"
        return result

    def _attacker() -> None:
        try:
            assert ready.wait(timeout=timeout), "timed out waiting for fd walk"
            swap()
        except BaseException as exc:  # noqa: BLE001
            swap_error.append(exc)
        finally:
            proceed.set()

    monkeypatch.setattr(qfs, "_walk_parent_for_mutation", _racing_walk)
    thread = threading.Thread(target=_attacker, name="toctou-post-fd", daemon=True)
    thread.start()
    monkeypatch.setattr(
        qfs,
        "_toctou_test_finalize",
        lambda: (_assert_no_swap_error(swap_error), thread.join(timeout=timeout)),
        raising=False,
    )
    return thread


def _assert_no_swap_error(swap_error: list[BaseException]) -> None:
    assert not swap_error, f"swap failed: {swap_error[0]!r}"


def _finalize_barrier() -> None:
    finalizer = getattr(qfs, "_toctou_test_finalize", None)
    if callable(finalizer):
        finalizer()


def _canary_snapshot(outside: Path, control: Path) -> tuple[str, str, int, int]:
    return (
        outside.read_text(encoding="utf-8"),
        control.read_text(encoding="utf-8"),
        outside.stat().st_mtime_ns,
        control.stat().st_mtime_ns,
    )


def _assert_canaries_unchanged(
    outside: Path,
    control: Path,
    before: tuple[str, str, int, int],
) -> None:
    after = _canary_snapshot(outside, control)
    assert after == before


def test_safe_internal_symlink_mutation_still_works(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "ops" / "real").mkdir(parents=True)
    (sandbox / "ops" / "alias").symlink_to(sandbox / "ops" / "real", target_is_directory=True)
    _seed(sandbox / "ops" / "real" / "target.txt", "seed")

    response = _call(
        sandbox,
        "write_file",
        {"path": "ops/alias/target.txt", "content": "updated"},
    )
    assert "error" not in response, response
    assert (sandbox / "ops" / "real" / "target.txt").read_text(encoding="utf-8") == "updated"
    _assert_privacy(json.dumps(response))


def test_race_safe_mutations_unavailable_is_explicit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _seed(sandbox / "seed.txt", "seed")
    monkeypatch.setattr(qfs, "_fd_bound_mutations_available", lambda: False)
    monkeypatch.setattr(qfs.sys, "platform", "linux")

    response = _call(
        sandbox,
        "write_file",
        {"path": "seed.txt", "content": ATTACK_PAYLOAD},
    )
    assert "error" in response
    assert response["error"]["message"] == MUTATION_UNAVAILABLE
    assert (sandbox / "seed.txt").read_text(encoding="utf-8") == "seed"


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows mutation backend")
def test_windows_backend_write_and_delete(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _seed(sandbox / "ops" / "target.txt", "seed")

    write = _call(sandbox, "write_file", {"path": "ops/target.txt", "content": "win-updated"})
    assert "error" not in write, write
    assert (sandbox / "ops" / "target.txt").read_text(encoding="utf-8") == "win-updated"

    deleted = _call(sandbox, "delete_file", {"path": "ops/target.txt"})
    assert "error" not in deleted, deleted
    assert not (sandbox / "ops" / "target.txt").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows reparse-point behavior")
def test_windows_pre_fd_reparse_swap_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox, outside, control, _control_dir, outside_dir = _prepare_canaries(tmp_path)
    _seed(sandbox / "ops" / "target.txt", "seed")
    victim_path = sandbox / "ops" / "target.txt"

    def swap() -> None:
        _swap_final_to_outside(victim_path, outside)

    _install_pre_fd_barrier(monkeypatch, swap=swap)
    response = _call(sandbox, "write_file", {"path": "ops/target.txt", "content": ATTACK_PAYLOAD})
    _finalize_barrier()

    assert "error" in response, response
    assert outside.read_text(encoding="utf-8") == OUTSIDE_MARKER
    assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == DECOY_MARKER


MUTATION_CASES = [
    (
        "write_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt", "content": ATTACK_PAYLOAD},
        "ops/target.txt",
    ),
    (
        "delete_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt"},
        "ops/target.txt",
    ),
    (
        "rmdir_tree",
        lambda sandbox: (
            (sandbox / "ops" / "tree").mkdir(parents=True),
            _seed(sandbox / "ops" / "tree" / "nested.txt", "seed"),
        ),
        {"path": "ops/tree"},
        "ops/tree",
    ),
    (
        "chmod_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt", "mode": 0o777},
        "ops/target.txt",
    ),
    (
        "create_symlink",
        lambda sandbox: (
            (sandbox / "ops").mkdir(parents=True, exist_ok=True),
            _seed(sandbox / "ops" / "seed.txt", "seed"),
        ),
        {"path": "ops/alias.txt", "target": "seed.txt"},
        "ops/alias.txt",
    ),
]


@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), MUTATION_CASES, ids=[c[0] for c in MUTATION_CASES])
@pytest.mark.parametrize("swap_kind", ["final", "parent"])
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_pre_fd_swap_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    swap_kind: str,
    canary_kind: str,
) -> None:
    sandbox, outside, control, control_dir, outside_dir = _prepare_canaries(tmp_path)
    setup(sandbox)
    victim_path = sandbox / Path(victim)
    parent_path = victim_path.parent
    before = _canary_snapshot(outside, control)

    def swap() -> None:
        if swap_kind == "final":
            if canary_kind == "outside":
                if tool == "rmdir_tree":
                    backup = victim_path.rename(victim_path.with_name(victim_path.name + ".bak-toctou"))
                    victim_path.symlink_to(outside_dir / "tree", target_is_directory=True)
                    del backup
                else:
                    _swap_final_to_outside(victim_path, outside)
            elif tool == "rmdir_tree":
                victim_path.rename(victim_path.with_name(victim_path.name + ".bak-toctou"))
                victim_path.symlink_to(control_dir, target_is_directory=True)
            else:
                _swap_final_to_control(victim_path, control)
            return
        link_target = outside_dir if canary_kind == "outside" else control_dir
        _swap_parent_to_symlink(parent_path, link_target)

    _install_pre_fd_barrier(monkeypatch, swap=swap)
    response = _call(sandbox, tool, arguments)
    _finalize_barrier()

    _assert_privacy(json.dumps(response))
    assert "error" in response, response
    assert response["error"]["code"] == -32602
    _assert_canaries_unchanged(outside, control, before)
    assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == DECOY_MARKER


@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), MUTATION_CASES, ids=[c[0] for c in MUTATION_CASES])
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_post_fd_final_swap_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    canary_kind: str,
) -> None:
    if tool == "create_symlink":
        pytest.skip("create_symlink has no pre-existing final component to swap")
    sandbox, outside, control, control_dir, outside_dir = _prepare_canaries(tmp_path)
    setup(sandbox)
    victim_path = sandbox / Path(victim)
    before = _canary_snapshot(outside, control)

    def swap() -> None:
        if canary_kind == "outside":
            if tool == "rmdir_tree":
                victim_path.rename(victim_path.with_name(victim_path.name + ".bak-toctou"))
                victim_path.symlink_to(outside_dir / "tree", target_is_directory=True)
            else:
                _swap_final_to_outside(victim_path, outside)
        elif tool == "rmdir_tree":
            victim_path.rename(victim_path.with_name(victim_path.name + ".bak-toctou"))
            victim_path.symlink_to(control_dir, target_is_directory=True)
        else:
            _swap_final_to_control(victim_path, control)

    _install_post_fd_barrier(monkeypatch, swap=swap)
    response = _call(sandbox, tool, arguments)
    _finalize_barrier()

    _assert_privacy(json.dumps(response))
    assert "error" in response, response
    assert response["error"]["code"] == -32602
    _assert_canaries_unchanged(outside, control, before)
    assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == DECOY_MARKER


@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), MUTATION_CASES, ids=[c[0] for c in MUTATION_CASES])
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_post_fd_parent_swap_never_reaches_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    canary_kind: str,
) -> None:
    sandbox, outside, control, control_dir, outside_dir = _prepare_canaries(tmp_path)
    setup(sandbox)
    victim_path = sandbox / Path(victim)
    parent_path = victim_path.parent
    before = _canary_snapshot(outside, control)
    decoy_before = (outside_dir / "decoy.txt").read_text(encoding="utf-8")

    def swap() -> None:
        link_target = outside_dir if canary_kind == "outside" else control_dir
        _swap_parent_to_symlink(parent_path, link_target)

    _install_post_fd_barrier(monkeypatch, swap=swap)
    response = _call(sandbox, tool, arguments)
    _finalize_barrier()

    _assert_privacy(json.dumps(response))
    _assert_canaries_unchanged(outside, control, before)
    assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == decoy_before == DECOY_MARKER

    bound_parent = sandbox / f"{parent_path.name}.bound-toctou"
    if tool == "write_file":
        assert "error" not in response, response
        assert (bound_parent / victim_path.name).read_text(encoding="utf-8") == ATTACK_PAYLOAD
    elif tool == "delete_file":
        assert "error" not in response, response
        assert not (bound_parent / victim_path.name).exists()
    elif tool == "rmdir_tree":
        assert "error" not in response, response
        assert bound_parent.exists()
        assert not (bound_parent / victim_path.name).exists()
    elif tool == "chmod_file":
        assert "error" not in response, response
        assert (bound_parent / victim_path.name).stat().st_mode & 0o777 == 0o777
    elif tool == "create_symlink":
        assert "error" not in response, response
        assert (bound_parent / victim_path.name).is_symlink()


@pytest.mark.parametrize(
    ("tool", "path_key", "swap_kind", "walk_index"),
    [
        ("move_file", "source", "final", 1),
        ("move_file", "source", "parent", 1),
        ("move_file", "destination", "final", 2),
        ("move_file", "destination", "parent", 2),
        ("copy_file", "source", "final", 1),
        ("copy_file", "source", "parent", 1),
        ("copy_file", "destination", "final", 2),
        ("copy_file", "destination", "parent", 2),
    ],
)
@pytest.mark.parametrize("boundary", ["pre_fd", "post_fd"])
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_move_copy_symlink_race_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path_key: str,
    swap_kind: str,
    walk_index: int,
    boundary: str,
    canary_kind: str,
) -> None:
    sandbox, outside, control, control_dir, outside_dir = _prepare_canaries(tmp_path)
    _seed(sandbox / "ops" / "source.txt", "source-seed")
    _seed(sandbox / "ops" / "destination.txt", "dest-seed")
    arguments = {"source": "ops/source.txt", "destination": "ops/destination.txt"}
    victim = arguments[path_key]
    victim_path = sandbox / Path(victim)
    parent_path = victim_path.parent
    before = _canary_snapshot(outside, control)

    def swap() -> None:
        if swap_kind == "final":
            if canary_kind == "outside":
                _swap_final_to_outside(victim_path, outside)
            else:
                _swap_final_to_control(victim_path, control)
            return
        link_target = outside_dir if canary_kind == "outside" else control_dir
        _swap_parent_to_symlink(parent_path, link_target)

    if boundary == "pre_fd":
        _install_pre_fd_barrier(monkeypatch, swap=swap, match_requested=victim)
    else:
        _install_post_fd_barrier(monkeypatch, swap=swap, walk_index=walk_index)

    response = _call(sandbox, tool, arguments)
    _finalize_barrier()
    _assert_privacy(json.dumps(response))

    if boundary == "pre_fd":
        assert "error" in response, response
        _assert_canaries_unchanged(outside, control, before)
        assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == DECOY_MARKER
        return

    _assert_canaries_unchanged(outside, control, before)
    assert (outside_dir / "decoy.txt").read_text(encoding="utf-8") == DECOY_MARKER
    if swap_kind == "final":
        assert "error" in response, response
        return

    if "error" in response:
        assert response["error"]["code"] == -32602
        return

    bound_parent = sandbox / "ops.bound-toctou"
    if tool == "move_file" and path_key == "source":
        assert not (bound_parent / "source.txt").exists()
    if tool == "copy_file" and path_key == "destination":
        assert (bound_parent / "destination.txt").read_text(encoding="utf-8") == "source-seed"


def test_pre_fix_write_final_swap_reaches_outside_without_hardening(tmp_path: Path) -> None:
    """Unsafe baseline: Path mutation after validation follows a swapped symlink."""

    sandbox, outside, control, _control_dir, _outside_dir = _prepare_canaries(tmp_path)
    target = sandbox / "ops" / "target.txt"
    _seed(target, "seed")
    validated = qfs._safe_child(sandbox, "ops/target.txt")
    target.unlink()
    target.symlink_to(outside)
    validated.write_text(ATTACK_PAYLOAD, encoding="utf-8")
    assert outside.read_text(encoding="utf-8") == ATTACK_PAYLOAD
    assert CONTROL_MARKER in control.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows mutation backend")
def test_windows_write_truncates_long_file_to_short(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    long_content = "A" * 4096
    _seed(sandbox / "ops" / "target.txt", long_content)

    response = _call(
        sandbox,
        "write_file",
        {"path": "ops/target.txt", "content": "short"},
    )
    assert "error" not in response, response
    assert (sandbox / "ops" / "target.txt").read_bytes() == b"short"


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows mutation backend")
def test_windows_chmod_and_create_symlink_functional(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _seed(sandbox / "ops" / "target.txt", "seed")

    chmod = _call(sandbox, "chmod_file", {"path": "ops/target.txt", "mode": 0o444})
    assert "error" not in chmod, chmod
    target = sandbox / "ops" / "target.txt"
    assert not target.stat().st_mode & 0o200

    link = _call(
        sandbox,
        "create_symlink",
        {"path": "ops/alias.txt", "target": "target.txt"},
    )
    assert "error" not in link, link
    alias = sandbox / "ops" / "alias.txt"
    assert alias.is_symlink()
    assert alias.read_text(encoding="utf-8") == "seed"


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows mutation backend")
def test_windows_rmdir_tree_large_directory_exceeds_single_query_buffer(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    tree = sandbox / "ops" / "large-tree"
    tree.mkdir(parents=True)
    # Enough long-name entries to exceed one 64 KiB NtQueryDirectoryFile buffer.
    for index in range(450):
        name = f"entry-{index:04d}-" + ("x" * 96)
        (tree / name).write_text("payload", encoding="utf-8")

    response = _call(sandbox, "rmdir_tree", {"path": "ops/large-tree"})
    assert "error" not in response, response
    assert not tree.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ABI")
def test_windows_open_root_accepts_integer_createfilew_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    original_create = qfs._kernel32.CreateFileW

    def int_createfilew(*args):
        return qfs._win32_handle_value(original_create(*args))

    monkeypatch.setattr(qfs._kernel32, "CreateFileW", int_createfilew)
    root_handle = qfs._win32_open_root(sandbox)
    try:
        assert root_handle > 0
    finally:
        qfs._win32_close(root_handle)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ABI")
def test_windows_query_basic_passes_numeric_information_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    root_handle = qfs._win32_open_root(sandbox)
    original_query = qfs._ntdll.NtQueryInformationFile
    observed: list[object] = []

    def recording_query(*args):
        observed.append(args[4])
        return original_query(*args)

    monkeypatch.setattr(qfs._ntdll, "NtQueryInformationFile", recording_query)
    try:
        qfs._win32_query_basic(root_handle)
    finally:
        qfs._win32_close(root_handle)

    assert observed == [4]
    assert isinstance(observed[0], int)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ABI")
def test_windows_list_directory_handles_signed_status_no_more_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = tmp_path / "sandbox"
    (sandbox / "probe").mkdir(parents=True)
    root_handle = qfs._win32_open_root(sandbox)
    try:
        parent, owned = qfs._walk_parent_for_mutation(root_handle, ["probe"], create_missing=False)
        try:
            signed_no_more = int(ctypes.c_int32(0x80000006).value)

            def fake_ntquery(*args, **kwargs):
                return signed_no_more

            monkeypatch.setattr(qfs._ntdll, "NtQueryDirectoryFile", fake_ntquery)
            assert qfs._win32_list_directory(parent) == []
        finally:
            qfs._win32_close_handles(owned)
    finally:
        qfs._win32_close(root_handle)


WINDOWS_NATIVE_SWAP_CASES = [
    pytest.param(
        "write_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt", "content": ATTACK_PAYLOAD},
        "ops/target.txt",
        id="write_file",
    ),
    pytest.param(
        "delete_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt"},
        "ops/target.txt",
        id="delete_file",
    ),
    pytest.param(
        "rmdir_tree",
        lambda sandbox: (
            (sandbox / "ops" / "tree").mkdir(parents=True),
            _seed(sandbox / "ops" / "tree" / "nested.txt", "seed"),
        ),
        {"path": "ops/tree"},
        "ops/tree",
        id="rmdir_tree",
    ),
    pytest.param(
        "chmod_file",
        lambda sandbox: _seed(sandbox / "ops" / "target.txt", "seed"),
        {"path": "ops/target.txt", "mode": 0o777},
        "ops/target.txt",
        id="chmod_file",
    ),
    pytest.param(
        "create_symlink",
        lambda sandbox: (
            (sandbox / "ops").mkdir(parents=True, exist_ok=True),
            _seed(sandbox / "ops" / "seed.txt", "seed"),
        ),
        {"path": "ops/alias.txt", "target": "seed.txt"},
        "ops/alias.txt",
        id="create_symlink",
    ),
]


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows handle-bound backend")
@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), WINDOWS_NATIVE_SWAP_CASES)
@pytest.mark.parametrize("swap_kind", ["final", "parent"])
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_windows_native_pre_fd_swap_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    swap_kind: str,
    canary_kind: str,
) -> None:
    test_pre_fd_swap_fail_closed(
        tmp_path,
        monkeypatch,
        tool,
        setup,
        arguments,
        victim,
        swap_kind,
        canary_kind,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows handle-bound backend")
@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), WINDOWS_NATIVE_SWAP_CASES)
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_windows_native_post_fd_final_swap_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    canary_kind: str,
) -> None:
    test_post_fd_final_swap_fail_closed(
        tmp_path,
        monkeypatch,
        tool,
        setup,
        arguments,
        victim,
        canary_kind,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows handle-bound backend")
@pytest.mark.parametrize(("tool", "setup", "arguments", "victim"), WINDOWS_NATIVE_SWAP_CASES)
@pytest.mark.parametrize("canary_kind", ["outside", "control"])
def test_windows_native_post_fd_parent_swap_never_reaches_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    setup,
    arguments: dict,
    victim: str,
    canary_kind: str,
) -> None:
    test_post_fd_parent_swap_never_reaches_symlink_target(
        tmp_path,
        monkeypatch,
        tool,
        setup,
        arguments,
        victim,
        canary_kind,
    )
