# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1
"""Explicit, hash-bound local migration for filesystem CA policy rules."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from agentveil_mcp_proxy.policy import ProxyConfig, builtin_policy_pack

MIGRATION_ID = "filesystem_ca_policy_v1"
MAX_CONFIG_BYTES = 1024 * 1024


class CAPolicyMigrationError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CAPolicyMigrationError("duplicate_config_key")
        result[key] = value
    return result


def _candidate(raw: bytes) -> tuple[bytes, list[str]]:
    from agentveil_mcp_proxy.cli import _policy_to_dict

    try:
        original = json.loads(raw, object_pairs_hook=_unique_object)
        config = ProxyConfig.from_dict(original)
    except (ValueError, TypeError) as exc:
        raise CAPolicyMigrationError("invalid_config") from exc
    if config.policy.id != "filesystem" or config.policy.default_decision.value != "ask_backend":
        raise CAPolicyMigrationError("unsupported_policy")
    desired = [rule for rule in _policy_to_dict(builtin_policy_pack("filesystem"))["rules"]
               if rule["id"].startswith("filesystem-ca-")]
    updated = copy.deepcopy(original)
    rules = updated["policy"].setdefault("rules", [])
    ids = [rule["id"] for rule in rules]
    if len(ids) != len(set(ids)):
        raise CAPolicyMigrationError("duplicate_rule_id")
    added = []
    for rule in desired:
        if rule["id"] in ids:
            if rules[ids.index(rule["id"])] != rule:
                raise CAPolicyMigrationError("rule_id_conflict")
        else:
            rules.append(rule)
            added.append(rule["id"])
    ProxyConfig.from_dict(updated)
    return ((json.dumps(updated, indent=2, ensure_ascii=False) + "\n").encode() if added else raw), added


def _open_parent(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise CAPolicyMigrationError("platform_unavailable")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(fd: int, name: str) -> bytes:
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(source, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
            raise CAPolicyMigrationError("invalid_config_file")
        data = stream.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise CAPolicyMigrationError("invalid_config_file")
        return data


def _write_exclusive(fd: int, name: str, data: bytes) -> None:
    dest = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(dest, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def migrate_filesystem_ca_policy(
    config_path: Path, *, apply: bool = False, expected_sha256: str | None = None,
) -> dict[str, object]:
    """Preview by default; apply requires the exact observed config hash."""
    path = config_path.expanduser().absolute()
    if ".." in path.parts:
        raise CAPolicyMigrationError("invalid_config_path")
    parent = None
    locked = False
    temporary = None
    lock = f".{path.name}.ca-policy.lock"
    try:
        parent = _open_parent(path)
        if apply:
            _write_exclusive(parent, lock, b"filesystem_ca_policy_v1\n")
            locked = True
        raw = _read(parent, path.name)
        digest = hashlib.sha256(raw).hexdigest()
        candidate, added = _candidate(raw)
        result = {"migration_id": MIGRATION_ID, "config_sha256": digest,
                  "added_rule_ids": added, "applied": False, "reload_required": False}
        if not apply:
            return result
        if expected_sha256 != digest:
            raise CAPolicyMigrationError("config_changed")
        if not added:
            return result
        backup = f"{path.name}.ca-policy.{digest}.bak"
        try:
            _write_exclusive(parent, backup, raw)
        except FileExistsError:
            if _read(parent, backup) != raw:
                raise CAPolicyMigrationError("backup_conflict")
        temporary = f".{path.name}.ca-policy.{secrets.token_hex(12)}.tmp"
        _write_exclusive(parent, temporary, candidate)
        if _read(parent, path.name) != raw:
            raise CAPolicyMigrationError("config_changed")
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        os.fsync(parent)
        return {**result, "applied": True, "reload_required": True,
                "new_config_sha256": hashlib.sha256(candidate).hexdigest()}
    except OSError as exc:
        raise CAPolicyMigrationError("config_io_error") from exc
    finally:
        if parent is not None:
            try:
                if temporary is not None:
                    os.unlink(temporary, dir_fd=parent)
                if locked:
                    os.unlink(lock, dir_fd=parent)
            finally:
                os.close(parent)
