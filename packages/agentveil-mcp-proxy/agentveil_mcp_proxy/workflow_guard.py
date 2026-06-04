"""T1 Workflow Guard: metadata-only local shell command classifier.

Classifies agent shell commands into privacy-preserving action envelopes. This
module does not execute commands, enforce policy, write evidence, or integrate
with Runtime Gate or Approval Center.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import posixpath
import re
import shlex
from typing import Any

from agentveil_mcp_proxy.classification import HASH_PREFIX, sha256_text
from agentveil_mcp_proxy.package_manager_guard import (
    package_manager_action_reason_from_command,
)

REDACTED_TARGET = "redacted"
_PATH_LIKE = re.compile(r"^(~|/|\./|\.\./|\.env|\.ssh|\.aws)")
_SECRET_FILENAMES = frozenset({
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credential",
    "secret",
    "secrets",
    "token",
    "tokens",
})
_SECRET_SEGMENTS = frozenset({"secrets", ".ssh", ".aws", ".gnupg"})
_SECRET_PREFIXES = (".env.", "credentials.", "credential.", "secret.", "secrets.", "token.", "tokens.")
_SECRET_SUFFIXES = (".env", ".pem", ".key")
_GIT_READ_SUBCOMMANDS = frozenset({
    "branch",
    "diff",
    "fetch",
    "log",
    "rev-parse",
    "show",
    "status",
    "describe",
})
_GH_PR_MUTATION = frozenset({"create", "open", "ready", "merge", "close", "edit", "delete"})
_DEPLOY_WORDS = frozenset({
    "deploy",
    "restart",
    "rollout",
    "migration",
    "migrate",
    "upgrade",
    "apply",
    "recreate",
})
_RELEASE_WORDS = frozenset({"publish", "release", "upload", "tag"})
_READ_VERBS = frozenset({
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "file",
    "stat",
    "ls",
    "pwd",
    "whoami",
    "which",
    "type",
    "grep",
    "rg",
    "find",
    "wc",
    "du",
    "df",
})
_FILE_MUTATION_VERBS = frozenset({
    "rm",
    "rmdir",
    "mv",
    "cp",
    "touch",
    "chmod",
    "chown",
    "truncate",
    "tee",
    "install",
    "sed",
})
_BLOCK_SUBSTRINGS = ("$(", "`", "eval", "exec", "source /dev/", ">/dev/")
_AMBIGUOUS_SHELL = frozenset({"sudo", "su", "doas", "pkexec"})
_CREDENTIAL_DUMP_COMMANDS = frozenset({"env", "printenv"})


class CommandFamily(StrEnum):
    SHELL = "shell"
    GIT = "git"
    GITHUB_CLI = "github_cli"
    SSH = "ssh"
    SCP = "scp"
    PACKAGE_MANAGER = "package_manager"
    TEST_RUNNER = "test_runner"
    FILE_TOOL = "file_tool"
    DEPLOY = "deploy"
    RELEASE = "release"
    UNKNOWN = "unknown"


class WorkflowActionType(StrEnum):
    LOCAL_READ = "local_read"
    LOCAL_TEST = "local_test"
    FILE_MUTATION = "file_mutation"
    REMOTE_SSH = "remote_ssh"
    REMOTE_SCP = "remote_scp"
    GIT_PUSH = "git_push"
    GH_PR_MUTATION = "gh_pr_mutation"
    RELEASE_PUBLISH = "release_publish"
    DEPLOY = "deploy"
    PACKAGE_MANAGER_MUTATION = "package_manager_mutation"
    SECRET_PATH_ACCESS = "secret_path_access"
    APPROVAL_CANDIDATE = "approval_candidate"
    BLOCK_CANDIDATE = "block_candidate"


class WorkflowDisposition(StrEnum):
    ALLOW = "allow"
    APPROVAL_CANDIDATE = "approval_candidate"
    BLOCK_CANDIDATE = "block_candidate"


@dataclass(frozen=True)
class WorkflowActionEnvelope:
    """Metadata-only classification for one shell command intent."""

    role: str
    adapter: str
    command_family: CommandFamily
    action_type: WorkflowActionType
    disposition: WorkflowDisposition
    redacted_target_label: str
    target_hash: str
    payload_hash: str
    risk_hints: tuple[str, ...]

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable envelope without raw command text."""

        return {
            "role": self.role,
            "adapter": self.adapter,
            "command_family": self.command_family.value,
            "action_type": self.action_type.value,
            "disposition": self.disposition.value,
            "redacted_target_label": self.redacted_target_label,
            "target_hash": self.target_hash,
            "payload_hash": self.payload_hash,
            "risk_hints": list(self.risk_hints),
        }


class WorkflowGuardClassifier:
    """Classify shell command strings using deterministic token parsing only."""

    def classify(
        self,
        command: str,
        *,
        role: str = "agent",
        adapter: str = "shell",
    ) -> WorkflowActionEnvelope:
        segments = _parse_pipeline_segments(command)
        if not segments:
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=[],
                family=CommandFamily.UNKNOWN,
                action_type=WorkflowActionType.BLOCK_CANDIDATE,
                disposition=WorkflowDisposition.BLOCK_CANDIDATE,
                target_label="shell:empty",
                risk_hints=("empty_command",),
            )

        if len(segments) > 1 and _pipeline_download_execute(command):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=segments[-1],
                family=CommandFamily.SHELL,
                action_type=WorkflowActionType.BLOCK_CANDIDATE,
                disposition=WorkflowDisposition.BLOCK_CANDIDATE,
                target_label="shell:pipeline-exec",
                risk_hints=("pipeline_execution", "ambiguous_dangerous"),
            )

        ranked: list[tuple[int, WorkflowActionEnvelope]] = []
        for tokens in segments:
            envelope = self._classify_tokens(
                command,
                tokens=tokens,
                role=role,
                adapter=adapter,
            )
            ranked.append((_risk_rank(envelope), envelope))
        _rank, winner = max(ranked, key=lambda item: item[0])
        return winner

    def _classify_tokens(
        self,
        command: str,
        *,
        tokens: list[str],
        role: str,
        adapter: str,
    ) -> WorkflowActionEnvelope:
        lowered = [token.lower() for token in tokens]
        if _has_secret_surface_tokens(tokens):
            return _secret_surface_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                target_label="secret:path-surface",
                risk_hints=("secret_path", "credential_surface"),
            )
        if _is_credential_dump_command(lowered):
            return _secret_surface_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                target_label="secret:environment",
                risk_hints=("credential_surface", "environment_dump"),
            )
        if _is_shell_injection(command, tokens):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.SHELL,
                action_type=WorkflowActionType.BLOCK_CANDIDATE,
                disposition=WorkflowDisposition.BLOCK_CANDIDATE,
                target_label="shell:injection",
                risk_hints=("shell_injection", "ambiguous_dangerous"),
            )
        if lowered and lowered[0] in _AMBIGUOUS_SHELL:
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.SHELL,
                action_type=WorkflowActionType.APPROVAL_CANDIDATE,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="shell:privilege-elevation",
                risk_hints=("privilege_elevation", "ambiguous_dangerous"),
            )

        if lowered and lowered[0] == "ssh":
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.SSH,
                action_type=WorkflowActionType.REMOTE_SSH,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="ssh:remote",
                risk_hints=("remote_execution",),
            )
        if lowered and lowered[0] == "scp":
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.SCP,
                action_type=WorkflowActionType.REMOTE_SCP,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="scp:remote",
                risk_hints=("remote_transfer",),
            )
        if lowered and lowered[0] == "git":
            return _classify_git(command, tokens=tokens, role=role, adapter=adapter)
        if lowered and lowered[0] == "gh":
            return _classify_gh(command, tokens=tokens, role=role, adapter=adapter)

        if package_manager_action_reason_from_command(" ".join(tokens)):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.PACKAGE_MANAGER,
                action_type=WorkflowActionType.PACKAGE_MANAGER_MUTATION,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="package-manager:mutation",
                risk_hints=("dependency_mutation",),
            )

        if _is_test_command(lowered):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.TEST_RUNNER,
                action_type=WorkflowActionType.LOCAL_TEST,
                disposition=WorkflowDisposition.ALLOW,
                target_label="test:focused",
                risk_hints=("local_test",),
            )

        if _is_deploy_command(lowered):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.DEPLOY,
                action_type=WorkflowActionType.DEPLOY,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="deploy:controlled-surface",
                risk_hints=("deploy", "controlled_surface"),
            )
        if _is_release_publish(lowered):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.RELEASE,
                action_type=WorkflowActionType.RELEASE_PUBLISH,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="release:publish",
                risk_hints=("release", "publish"),
            )
        if _is_file_mutation(lowered, tokens):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.FILE_TOOL,
                action_type=WorkflowActionType.FILE_MUTATION,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label="file:mutation",
                risk_hints=("filesystem_mutation",),
            )
        if _is_local_read(lowered):
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.SHELL,
                action_type=WorkflowActionType.LOCAL_READ,
                disposition=WorkflowDisposition.ALLOW,
                target_label="shell:read-check",
                risk_hints=("local_read",),
            )
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.SHELL,
            action_type=WorkflowActionType.APPROVAL_CANDIDATE,
            disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
            target_label="shell:unclassified",
            risk_hints=("ambiguous_dangerous",),
        )


def _classify_git(
    command: str,
    *,
    tokens: list[str],
    role: str,
    adapter: str,
) -> WorkflowActionEnvelope:
    lowered = [token.lower() for token in tokens]
    if "push" in lowered:
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GIT,
            action_type=WorkflowActionType.GIT_PUSH,
            disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
            target_label="git:push",
            risk_hints=("git_push", "remote_mutation"),
        )
    if "tag" in lowered:
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GIT,
            action_type=WorkflowActionType.RELEASE_PUBLISH,
            disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
            target_label="git:tag",
            risk_hints=("release", "tag"),
        )
    subcommand = lowered[1] if len(lowered) > 1 else ""
    if subcommand in _GIT_READ_SUBCOMMANDS:
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GIT,
            action_type=WorkflowActionType.LOCAL_READ,
            disposition=WorkflowDisposition.ALLOW,
            target_label=f"git:{subcommand}",
            risk_hints=("local_read", "git"),
        )
    return _build_envelope(
        role=role,
        adapter=adapter,
        command=command,
        tokens=tokens,
        family=CommandFamily.GIT,
        action_type=WorkflowActionType.APPROVAL_CANDIDATE,
        disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
        target_label="git:unclassified",
        risk_hints=("ambiguous_dangerous", "git"),
    )


def _classify_gh(
    command: str,
    *,
    tokens: list[str],
    role: str,
    adapter: str,
) -> WorkflowActionEnvelope:
    lowered = [token.lower() for token in tokens]
    if len(lowered) >= 2 and lowered[1] == "pr":
        verb = lowered[2] if len(lowered) > 2 else ""
        if verb in _GH_PR_MUTATION:
            return _build_envelope(
                role=role,
                adapter=adapter,
                command=command,
                tokens=tokens,
                family=CommandFamily.GITHUB_CLI,
                action_type=WorkflowActionType.GH_PR_MUTATION,
                disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
                target_label=f"gh:pr:{verb or 'mutation'}",
                risk_hints=("github_pr_mutation",),
            )
    if len(lowered) >= 2 and lowered[1] == "release":
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GITHUB_CLI,
            action_type=WorkflowActionType.RELEASE_PUBLISH,
            disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
            target_label="gh:release",
            risk_hints=("release", "publish"),
        )
    if any(word in lowered for word in _RELEASE_WORDS):
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GITHUB_CLI,
            action_type=WorkflowActionType.RELEASE_PUBLISH,
            disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
            target_label="gh:publish",
            risk_hints=("release", "publish"),
        )
    if any(word in lowered for word in ("view", "status", "list", "check")):
        return _build_envelope(
            role=role,
            adapter=adapter,
            command=command,
            tokens=tokens,
            family=CommandFamily.GITHUB_CLI,
            action_type=WorkflowActionType.LOCAL_READ,
            disposition=WorkflowDisposition.ALLOW,
            target_label="gh:read",
            risk_hints=("local_read",),
        )
    return _build_envelope(
        role=role,
        adapter=adapter,
        command=command,
        tokens=tokens,
        family=CommandFamily.GITHUB_CLI,
        action_type=WorkflowActionType.APPROVAL_CANDIDATE,
        disposition=WorkflowDisposition.APPROVAL_CANDIDATE,
        target_label="gh:unclassified",
        risk_hints=("ambiguous_dangerous",),
    )


def _parse_pipeline_segments(command: str) -> list[list[str]]:
    segments: list[list[str]] = []
    for part in _split_pipes(command):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            segments.append(shlex.split(stripped, posix=True))
        except ValueError:
            segments.append(stripped.split())
    return segments


def _split_pipes(command: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(command):
        char = command[index]
        if char == "'" and not in_double:
            in_single = not in_single
            current.append(char)
        elif char == '"' and not in_single:
            in_double = not in_double
            current.append(char)
        elif char == "|" and not in_single and not in_double:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _pipeline_download_execute(command: str) -> bool:
    lowered = command.lower()
    if "|" not in lowered:
        return False
    return bool(re.search(r"\|\s*(bash|sh|zsh|dash)\b", lowered))


def _is_shell_injection(command: str, tokens: list[str]) -> bool:
    lowered_command = command.lower()
    if any(marker in lowered_command for marker in _BLOCK_SUBSTRINGS):
        return True
    return any(token in {"eval", "exec"} for token in (t.lower() for t in tokens))


def _has_secret_surface_tokens(tokens: list[str]) -> bool:
    for token in tokens:
        if token.startswith("-"):
            continue
        if _looks_like_path(token):
            if _secret_path_reason(token) is not None:
                return True
            continue
        if _secret_basename_reason(token) is not None:
            return True
    return False


def _is_credential_dump_command(lowered: list[str]) -> bool:
    return bool(lowered) and lowered[0] in _CREDENTIAL_DUMP_COMMANDS


def _secret_surface_envelope(
    *,
    role: str,
    adapter: str,
    command: str,
    tokens: list[str],
    target_label: str,
    risk_hints: tuple[str, ...],
) -> WorkflowActionEnvelope:
    return _build_envelope(
        role=role,
        adapter=adapter,
        command=command,
        tokens=tokens,
        family=CommandFamily.FILE_TOOL,
        action_type=WorkflowActionType.SECRET_PATH_ACCESS,
        disposition=WorkflowDisposition.BLOCK_CANDIDATE,
        target_label=target_label,
        risk_hints=risk_hints,
    )


def _secret_path_reason(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    resolved = posixpath.normpath(normalized)
    segments = [
        segment for segment in resolved.split("/") if segment and segment != "."
    ]
    lowered = [segment.lower() for segment in segments]
    if not lowered:
        return None
    if any(segment in _SECRET_SEGMENTS for segment in lowered):
        return "secret"
    basename = lowered[-1]
    if basename in _SECRET_FILENAMES:
        return "secret"
    if basename.startswith(_SECRET_PREFIXES) or basename.endswith(_SECRET_SUFFIXES):
        return "secret"
    return None


def _secret_basename_reason(token: str) -> str | None:
    """Detect secret filenames referenced from the current working directory."""

    basename = token.lower()
    if basename in _SECRET_FILENAMES:
        return "secret"
    if basename.startswith(_SECRET_PREFIXES) or basename.endswith(_SECRET_SUFFIXES):
        return "secret"
    return None


def _looks_like_path(token: str) -> bool:
    if _PATH_LIKE.match(token):
        return True
    return "/" in token or token.startswith("~")


def _is_test_command(lowered: list[str]) -> bool:
    if not lowered:
        return False
    if lowered[0] == "pytest":
        return True
    if lowered[0] == "python" and len(lowered) >= 3 and lowered[1] == "-m" and lowered[2] == "pytest":
        return True
    if lowered[0] == "python3" and len(lowered) >= 3 and lowered[1] == "-m" and lowered[2] == "pytest":
        return True
    return False


def _is_deploy_command(lowered: list[str]) -> bool:
    if not lowered:
        return False
    if lowered[0] in {"kubectl", "terraform", "helm", "systemctl", "service"}:
        return True
    if lowered[0] == "docker" and any(token in lowered for token in ("compose", "up", "restart")):
        return True
    if lowered[0] == "alembic" and "upgrade" in lowered:
        return True
    joined = " ".join(lowered)
    return any(word in joined.split() for word in _DEPLOY_WORDS)


def _is_release_publish(lowered: list[str]) -> bool:
    if not lowered:
        return False
    if lowered[0] in {"twine", "npm", "pnpm", "yarn", "bun"} and "publish" in lowered:
        return True
    if lowered[0] == "docker" and "push" in lowered:
        return True
    return any(word in lowered for word in _RELEASE_WORDS)


def _is_file_mutation(lowered: list[str], tokens: list[str]) -> bool:
    if lowered and lowered[0] in _FILE_MUTATION_VERBS:
        if lowered[0] == "sed":
            return "-i" in tokens or any(part.startswith("-i") for part in tokens)
        return True
    if ">" in tokens or ">>" in tokens:
        return True
    return False


def _is_local_read(lowered: list[str]) -> bool:
    if not lowered:
        return False
    if lowered[0] in _READ_VERBS:
        if lowered[0] == "find":
            return not any(flag in lowered for flag in ("-delete", "-exec", "-execdir"))
        return True
    if lowered[0] == "git":
        return len(lowered) > 1 and lowered[1] in _GIT_READ_SUBCOMMANDS
    return False


def _canonical_tokens(tokens: list[str]) -> list[str]:
    canonical: list[str] = []
    for token in tokens:
        lowered = token.lower()
        if _looks_like_path(token):
            canonical.append("<path>")
            continue
        if "@" in token and not token.startswith("-"):
            canonical.append("<remote-target>")
            continue
        canonical.append(lowered)
    return canonical


def _payload_hash(tokens: list[str]) -> str:
    canonical = "|".join(_canonical_tokens(tokens))
    return sha256_text(canonical)


def _target_hash(label: str) -> str:
    return sha256_text(label)


def _build_envelope(
    *,
    role: str,
    adapter: str,
    command: str,
    tokens: list[str],
    family: CommandFamily,
    action_type: WorkflowActionType,
    disposition: WorkflowDisposition,
    target_label: str,
    risk_hints: tuple[str, ...],
) -> WorkflowActionEnvelope:
    del command  # Raw shell text is intentionally omitted from the envelope.
    return WorkflowActionEnvelope(
        role=role,
        adapter=adapter,
        command_family=family,
        action_type=action_type,
        disposition=disposition,
        redacted_target_label=target_label,
        target_hash=_target_hash(target_label),
        payload_hash=_payload_hash(tokens),
        risk_hints=risk_hints,
    )


def _risk_rank(envelope: WorkflowActionEnvelope) -> int:
    order = {
        WorkflowDisposition.ALLOW: 0,
        WorkflowDisposition.APPROVAL_CANDIDATE: 1,
        WorkflowDisposition.BLOCK_CANDIDATE: 2,
    }
    type_rank = {
        WorkflowActionType.LOCAL_READ: 0,
        WorkflowActionType.LOCAL_TEST: 1,
        WorkflowActionType.FILE_MUTATION: 2,
        WorkflowActionType.PACKAGE_MANAGER_MUTATION: 3,
        WorkflowActionType.GIT_PUSH: 4,
        WorkflowActionType.GH_PR_MUTATION: 4,
        WorkflowActionType.REMOTE_SSH: 5,
        WorkflowActionType.REMOTE_SCP: 5,
        WorkflowActionType.RELEASE_PUBLISH: 6,
        WorkflowActionType.DEPLOY: 7,
        WorkflowActionType.SECRET_PATH_ACCESS: 8,
        WorkflowActionType.BLOCK_CANDIDATE: 9,
        WorkflowActionType.APPROVAL_CANDIDATE: 5,
    }
    return order[envelope.disposition] * 10 + type_rank.get(envelope.action_type, 5)


__all__ = [
    "CommandFamily",
    "WorkflowActionEnvelope",
    "WorkflowActionType",
    "WorkflowDisposition",
    "WorkflowGuardClassifier",
]
