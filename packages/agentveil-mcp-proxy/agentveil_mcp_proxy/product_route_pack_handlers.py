"""In-process pack handlers reused by the composite product route downstream."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

try:
    import tomllib
except ImportError:
    tomllib = None

from agentveil_mcp_proxy.persistence_path_guard import (
    scan_instruction_surfaces,
    summarize_instruction_surface_risk,
)

PACKAGE_RISK_MESSAGE = (
    "Package install risk surface detected; install/update/remove requires approval."
)
GITHUB_RISK_MESSAGE = (
    "Untrusted GitHub text detected; privileged GitHub action requires approval."
)
CI_REPO_RISK_MESSAGE = (
    "Untrusted CI/repo text detected; privileged CI action requires approval."
)
CI_MANIFEST_NAME = ".ci_repo_trust_manifest.json"
_GIT_BASENAME_LIMIT = 8


def _path_to_basename(path: str) -> str:
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    path = path.strip()
    if not path:
        return path
    return path.rsplit("/", 1)[-1]


def _parse_porcelain_status(stdout: str) -> dict[str, Any]:
    staged: list[str] = []
    unstaged: list[str] = []
    for line in stdout.splitlines():
        if len(line) < 4 or not line.strip():
            continue
        index_status, worktree_status = line[0], line[1]
        basename = _path_to_basename(line[3:])
        if not basename:
            continue
        if index_status not in (" ", "?", "!"):
            staged.append(basename)
        if worktree_status not in (" ", "?", "!"):
            unstaged.append(basename)
    status_lines = len([item for item in stdout.splitlines() if item.strip()])
    return {
        "dirty": bool(stdout.strip()),
        "status_lines": status_lines,
        "staged_count": len(staged),
        "unstaged_count": len(unstaged),
        "staged_basenames": staged[:_GIT_BASENAME_LIMIT],
        "unstaged_basenames": unstaged[:_GIT_BASENAME_LIMIT],
    }


def _staged_diff_flag(arguments: Mapping[str, Any]) -> bool:
    staged = arguments.get("staged")
    if staged is True:
        return True
    if isinstance(staged, str) and staged.strip().lower() in {"1", "true", "yes"}:
        return True
    return False


def _diff_stat_basenames(stdout: str) -> list[str]:
    basenames: list[str] = []
    for line in stdout.splitlines():
        if "|" not in line:
            continue
        path_part = line.split("|", 1)[0].strip()
        if path_part:
            basenames.append(_path_to_basename(path_part))
    return basenames[:_GIT_BASENAME_LIMIT]


def _diff_stat_line_count(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if "|" in line)


def _bounded_text_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(dict(payload), sort_keys=True)}]}


class GitRepoPackHandler:
    """Real-git handler for product route git tools."""

    def __init__(self, *, repo_root: Path, outcome_log: Path | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.outcome_log = outcome_log

    def _git(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def _bounded_snapshot(self) -> dict[str, Any]:
        branch = self._git(["rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
        head = self._git(["rev-parse", "--short", "HEAD"]).stdout.strip()
        count = self._git(["rev-list", "--count", "HEAD"]).stdout.strip()
        status = self._git(["status", "--porcelain"]).stdout
        changed = [
            line[3:].split("/", 1)[-1]
            for line in status.splitlines()
            if line.strip()
        ]
        return {
            "branch": branch,
            "head": head,
            "commit_count": int(count or "0"),
            "dirty": bool(status.strip()),
            "changed_basenames": changed[:8],
        }

    def _append_outcome(self, tool: str, *, before: dict[str, Any], after: dict[str, Any], reached: bool) -> None:
        if self.outcome_log is None:
            return
        entry = {"tool": tool, "before": before, "after": after, "target_reached": reached}
        with self.outcome_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

    def _repo_path(self, arguments: Mapping[str, Any]) -> Path:
        repo_path = arguments.get("repo_path")
        if not isinstance(repo_path, str) or not repo_path.strip():
            return self.repo_root
        resolved = Path(repo_path.strip()).resolve()
        if resolved != self.repo_root:
            raise ValueError("repo_path outside configured repository")
        return resolved

    def handle(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._repo_path(arguments)
        before = self._bounded_snapshot()
        reached = False
        payload: dict[str, Any] = {"ok": True, "tool": name}
        if name == "git_status":
            proc = self._git(["status", "--porcelain"])
            reached = proc.returncode == 0
            payload = {"tool": name, **_parse_porcelain_status(proc.stdout)}
        elif name == "git_log":
            proc = self._git(["log", "-1", "--pretty=format:%h"])
            reached = proc.returncode == 0
            payload = {"tool": name, "latest_short_hash": proc.stdout.strip()}
        elif name == "git_diff":
            staged_mode = _staged_diff_flag(arguments)
            diff_args = ["diff", "--cached", "--stat"] if staged_mode else ["diff", "--stat"]
            proc = self._git(diff_args)
            reached = proc.returncode == 0
            changed_basenames = _diff_stat_basenames(proc.stdout)
            payload = {
                "tool": name,
                "diff_stat_lines": _diff_stat_line_count(proc.stdout),
                "staged": staged_mode,
            }
            if changed_basenames:
                payload["changed_basenames"] = changed_basenames
        elif name == "git_show":
            revision = str(arguments.get("revision") or "HEAD")
            proc = self._git(["show", "--quiet", "--pretty=format:%h", revision])
            reached = proc.returncode == 0
            payload = {"tool": name, "revision_short_hash": proc.stdout.strip()}
        elif name == "git_branch":
            proc = self._git(["branch", "--show-current"])
            reached = proc.returncode == 0
            payload = {"tool": name, "branch": proc.stdout.strip()}
        elif name == "git_add":
            files = arguments.get("files") or ["."]
            if not isinstance(files, list):
                files = ["."]
            proc = self._git(["add", "--"] + [str(item) for item in files])
            reached = proc.returncode == 0
            payload = {"tool": name, "staged": reached}
        elif name == "git_commit":
            message = str(arguments.get("message") or "commit")
            proc = self._git(["commit", "-m", message])
            reached = proc.returncode == 0
            payload = {"tool": name, "committed": reached}
        elif name == "git_checkout":
            branch = str(arguments.get("branch_name") or arguments.get("branch") or "main")
            proc = self._git(["checkout", branch])
            reached = proc.returncode == 0
            payload = {"tool": name, "checked_out": branch if reached else None}
        elif name == "git_create_branch":
            branch = str(arguments.get("branch_name") or "feature/test")
            proc = self._git(["checkout", "-b", branch])
            reached = proc.returncode == 0
            payload = {"tool": name, "created_branch": branch if reached else None}
        elif name == "git_reset":
            proc = self._git(["reset", "--hard", "HEAD"])
            reached = proc.returncode == 0
            payload = {"tool": name, "reset": reached}
        elif name == "git_clean":
            proc = self._git(["clean", "-fd"])
            reached = proc.returncode == 0
            payload = {"tool": name, "cleaned": reached}
        elif name == "git_rebase":
            upstream = str(arguments.get("upstream") or "HEAD~1")
            proc = self._git(["rebase", upstream])
            reached = proc.returncode == 0
            payload = {"tool": name, "rebased": reached}
        elif name == "git_push":
            remote = str(arguments.get("remote") or "origin")
            branch = str(arguments.get("branch") or self._bounded_snapshot()["branch"])
            proc = self._git(["push", remote, branch])
            reached = proc.returncode == 0
            payload = {"tool": name, "pushed": reached}
        else:
            raise ValueError(f"unsupported git tool: {name}")
        after = self._bounded_snapshot()
        payload.setdefault("repo_branch", payload.get("branch") or after["branch"])
        self._append_outcome(name, before=before, after=after, reached=reached)
        return _bounded_text_result(payload)


class PackageInstallPackHandler:
    """Real-pip handler for product route package tools."""

    def __init__(
        self,
        *,
        project_root: Path,
        target_venv: Path,
        local_dist: Path,
        outcome_log: Path | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.target_venv = target_venv.resolve()
        self.local_dist = local_dist.resolve()
        self.outcome_log = outcome_log

    def _venv_python(self) -> str:
        name = "Scripts/python.exe" if os.name == "nt" else "bin/python"
        return str(self.target_venv / name)

    def _pip(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self._venv_python(), "-m", "pip", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def _package_installed(self, name: str) -> bool:
        return self._pip(["show", name]).returncode == 0

    def _bounded_snapshot(self, package_name: str | None = None) -> dict[str, Any]:
        payload = {
            "installed_package_count": len([
                line for line in self._pip(["list", "--format=freeze"]).stdout.splitlines() if line.strip()
            ]),
        }
        if package_name:
            payload["target_installed"] = self._package_installed(package_name)
        return payload

    def _append_outcome(self, tool: str, *, before: dict[str, Any], after: dict[str, Any], reached: bool) -> None:
        if self.outcome_log is None:
            return
        entry = {"tool": tool, "before": before, "after": after, "target_reached": reached}
        with self.outcome_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

    def _project_path(self, arguments: Mapping[str, Any]) -> Path:
        project_path = arguments.get("project_path")
        if not isinstance(project_path, str) or not project_path.strip():
            return self.project_root
        resolved = Path(project_path.strip()).resolve()
        if resolved != self.project_root:
            raise ValueError("project_path outside configured project root")
        return resolved

    def _dependency_count(self, project_path: Path) -> int:
        manifest = project_path / "pyproject.toml"
        if tomllib is not None:
            manifest_text = manifest.read_text(encoding="utf-8")
            try:
                data = tomllib.loads(manifest_text.encode("utf-8"))
            except TypeError:
                data = tomllib.loads(manifest_text)
            return len(data.get("project", {}).get("dependencies", []))
        count = 0
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith('"') or line.strip().startswith("'"):
                count += 1
        return count

    def handle(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        project_path = self._project_path(arguments)
        package_name = str(arguments.get("package_name") or "agentveil-route-test-pkg")
        before = self._bounded_snapshot(package_name)
        reached = False
        payload: dict[str, Any] = {"ok": True, "tool": name}
        if name == "package_list_manifest":
            reached = True
            payload = {"tool": name, "dependency_count": self._dependency_count(project_path)}
        elif name == "package_inspect_state":
            reached = True
            payload = {"tool": name, **self._bounded_snapshot(package_name)}
        elif name == "package_risk_status":
            surfaces = scan_instruction_surfaces(project_path)
            script_markers = (project_path / "pyproject.toml").is_file() and "[project.scripts]" in (
                project_path / "pyproject.toml"
            ).read_text(encoding="utf-8")
            reached = True
            payload = {
                "tool": name,
                "instruction_surfaces_detected": bool(surfaces),
                "package_script_markers_present": script_markers,
                "package_install_risk_message": PACKAGE_RISK_MESSAGE if (surfaces or script_markers) else None,
                "instruction_surface_count": len(surfaces),
            }
        elif name == "pip_install":
            if not self.local_dist.is_dir():
                raise ValueError("local dist directory required for pip_install")
            proc = self._pip(["install", "--no-index", f"--find-links={self.local_dist}", package_name])
            reached = proc.returncode == 0
            payload = {
                "tool": name,
                "installed": reached,
                "target_installed": self._package_installed(package_name),
            }
        elif name == "pip_uninstall":
            proc = self._pip(["uninstall", "-y", package_name])
            reached = proc.returncode == 0
            payload = {
                "tool": name,
                "removed": reached,
                "target_installed": self._package_installed(package_name),
            }
        elif name == "pip_update":
            if not self.local_dist.is_dir():
                raise ValueError("local dist directory required for pip_update")
            proc = self._pip(["install", "--no-index", f"--find-links={self.local_dist}", "--upgrade", package_name])
            reached = proc.returncode == 0
            payload = {
                "tool": name,
                "updated": reached,
                "target_installed": self._package_installed(package_name),
            }
        elif name == "pip_run_script":
            marker = project_path / ".postinstall-ran"
            if marker.exists():
                marker.unlink()
            proc = subprocess.run(
                [
                    self._venv_python(),
                    "-c",
                    f"import agentveil_route_pkg; agentveil_route_pkg.mark_postinstall({project_path!r})",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            reached = proc.returncode == 0 and marker.exists()
            payload = {"tool": name, "script_ran": reached, "marker_present": marker.exists()}
        else:
            raise ValueError(f"unsupported package tool: {name}")
        after = self._bounded_snapshot(package_name)
        self._append_outcome(name, before=before, after=after, reached=reached)
        return _bounded_text_result(payload)


class GitHubCiPackHandler:
    """Local GitHub/CI state handler for product route github tools."""

    def __init__(
        self,
        *,
        state_dir: Path,
        content_root: Path,
        outcome_log: Path | None = None,
    ) -> None:
        self.state_dir = state_dir.resolve()
        self.content_root = content_root.resolve()
        self.state_path = self.state_dir / "state.json"
        self.outcome_log = outcome_log

    def _ci_repo_manifest_present(self) -> bool:
        manifest = self.content_root / CI_MANIFEST_NAME
        if not manifest.is_file():
            return False
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return isinstance(payload, dict) and payload.get("untrusted_ci_text_surface_present") is True

    def _load_state(self) -> dict[str, Any]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save_state(self, state: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    def _bounded_snapshot(self) -> dict[str, Any]:
        state = self._load_state()
        comments = state.get("comments", {})
        issues = state.get("issues", {})
        pull_requests = state.get("pull_requests", {})
        return {
            "owner": state.get("owner"),
            "name": state.get("name"),
            "default_branch": state.get("default_branch"),
            "branch_count": len(state.get("branches", [])),
            "issue_comment_counts": {
                key: len(comments.get(f"issue-{key}", []))
                for key in sorted(issues, key=lambda item: int(item))
            },
            "pull_comment_counts": {
                key: len(comments.get(f"pr-{key}", []))
                for key in sorted(pull_requests, key=lambda item: int(item))
            },
            "release_count": len(state.get("releases", [])),
            "secret_names_count": len(state.get("secret_names", [])),
            "visibility": state.get("visibility"),
            "merged_pull_requests": sum(
                1 for item in pull_requests.values() if item.get("merged") is True
            ),
            "closed_issues": sum(
                1 for item in issues.values() if item.get("closed") is True
            ),
            "workflow_run_count": len(state.get("workflow_runs", [])),
            "workflow_count": len(state.get("workflows", [])),
            "ci_job_count": len(state.get("ci_jobs", [])),
            "deploy_active": state.get("deploy_state", {}).get("active"),
            "published_package_count": len(state.get("package_publish_state", {}).get("published_versions", [])),
            "remote_completed_commands": state.get("remote_execution_state", {}).get("completed_commands", 0),
            "env_secret_names_count": len(state.get("env_secrets", {})),
        }

    def _append_outcome(self, tool: str, *, before: dict[str, Any], after: dict[str, Any], reached: bool) -> None:
        if self.outcome_log is None:
            return
        entry = {"tool": tool, "before": before, "after": after, "target_reached": reached}
        with self.outcome_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

    def _validate_repo(self, arguments: Mapping[str, Any], state: dict[str, Any]) -> None:
        configured_owner = state.get("owner")
        configured_repo = state.get("name")
        owner = arguments.get("owner")
        repo = arguments.get("repo")
        if isinstance(owner, str) and owner.strip():
            if owner != configured_owner:
                raise ValueError("owner/repo mismatch")
        if isinstance(repo, str) and repo.strip():
            if repo != configured_repo:
                raise ValueError("owner/repo mismatch")

    def _repo_root(self, arguments: Mapping[str, Any]) -> Path:
        repo_root = arguments.get("repo_root")
        if isinstance(repo_root, str) and repo_root.strip():
            resolved = Path(repo_root.strip()).resolve()
            if resolved != self.content_root:
                raise ValueError("repo_root outside configured content root")
            return resolved
        return self.content_root

    def handle(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        state = self._load_state()
        self._validate_repo(arguments, state)
        self._repo_root(arguments)
        before = self._bounded_snapshot()
        reached = False
        payload: dict[str, Any] = {"ok": True, "tool": name, "provider_family": "github"}
        comments = state.setdefault("comments", {})
        issues = state.setdefault("issues", {})
        pull_requests = state.setdefault("pull_requests", {})
        if name in {"github_target_snapshot", "ci_repo_target_snapshot"}:
            reached = True
            payload = {"tool": name, "provider_family": "github", **before}
        elif name == "untrusted_context_status":
            summary = summarize_instruction_surface_risk(scan_instruction_surfaces(self.content_root))
            reached = True
            risk_message = CI_REPO_RISK_MESSAGE if self._ci_repo_manifest_present() else GITHUB_RISK_MESSAGE
            payload = {
                "tool": name,
                "provider_family": "github",
                "instruction_surfaces_detected": summary.get("instruction_surfaces_detected"),
                "instruction_surface_count": summary.get("instruction_surface_count"),
                "untrusted_text_surface_present": True,
                "instruction_surface_present": summary.get("instruction_surfaces_detected"),
                "instruction_surface_risk_message": risk_message,
                "ci_repo_trust_surface_present": self._ci_repo_manifest_present(),
            }
        elif name == "get_repository":
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "owner": state["owner"],
                "name": state["name"],
                "default_branch": state["default_branch"],
                "visibility": state["visibility"],
            }
        elif name == "list_issues":
            reached = True
            payload = {"tool": name, "provider_family": "github", "issue_count": len(issues)}
        elif name == "get_issue":
            issue_number = str(int(arguments.get("issue_number", 0)))
            issue = issues.get(issue_number)
            if issue is None:
                raise ValueError("issue not found")
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "issue_number": int(issue_number),
                "comment_count": issue.get("comment_count", 0),
                "closed": issue.get("closed", False),
            }
        elif name == "list_pull_requests":
            reached = True
            payload = {"tool": name, "provider_family": "github", "pull_request_count": len(pull_requests)}
        elif name == "get_pull_request":
            pull_number = str(int(arguments.get("pull_number", 0)))
            pull = pull_requests.get(pull_number)
            if pull is None:
                raise ValueError("pull request not found")
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "pull_number": int(pull_number),
                "comment_count": pull.get("comment_count", 0),
                "merged": pull.get("merged", False),
            }
        elif name == "list_comments":
            issue_number = arguments.get("issue_number")
            pull_number = arguments.get("pull_number")
            if issue_number is not None:
                key = f"issue-{int(issue_number)}"
            elif pull_number is not None:
                key = f"pr-{int(pull_number)}"
            else:
                raise ValueError("issue_number or pull_number required")
            reached = True
            payload = {"tool": name, "provider_family": "github", "comment_count": len(comments.get(key, []))}
        elif name == "list_branches":
            reached = True
            payload = {"tool": name, "provider_family": "github", "branch_count": len(state.get("branches", []))}
        elif name == "list_files":
            reached = True
            payload = {"tool": name, "provider_family": "github", "file_count": len(state.get("files", []))}
        elif name == "list_secret_names":
            reached = True
            payload = {"tool": name, "provider_family": "github", "secret_names_count": len(state.get("secret_names", []))}
        elif name == "get_repository_settings":
            reached = True
            payload = {"tool": name, "provider_family": "github", "visibility": state.get("visibility")}
        elif name == "list_workflow_runs":
            reached = True
            payload = {"tool": name, "provider_family": "github", "workflow_run_count": len(state.get("workflow_runs", []))}
        elif name == "list_workflows":
            reached = True
            payload = {"tool": name, "provider_family": "github", "workflow_count": len(state.get("workflows", []))}
        elif name == "get_workflow":
            reached = True
            payload = {"tool": name, "provider_family": "github", "workflow_count": len(state.get("workflows", []))}
        elif name == "list_ci_jobs":
            reached = True
            payload = {"tool": name, "provider_family": "github", "ci_job_count": len(state.get("ci_jobs", []))}
        elif name == "get_ci_job":
            reached = True
            payload = {"tool": name, "provider_family": "github", "ci_job_count": len(state.get("ci_jobs", []))}
        elif name == "get_package_metadata":
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "published_package_count": len(
                    state.get("package_publish_state", {}).get("published_versions", [])
                ),
            }
        elif name == "create_comment":
            issue_number = arguments.get("issue_number")
            pull_number = arguments.get("pull_number")
            if issue_number is not None:
                key = f"issue-{int(issue_number)}"
                issue = issues.get(str(int(issue_number)))
                if issue is None:
                    raise ValueError("issue not found")
            elif pull_number is not None:
                key = f"pr-{int(pull_number)}"
                pull = pull_requests.get(str(int(pull_number)))
                if pull is None:
                    raise ValueError("pull request not found")
            else:
                raise ValueError("issue_number or pull_number required")
            body = str(arguments.get("comment_body") or "approved-comment")
            bucket = comments.setdefault(key, [])
            bucket.append(body)
            if issue_number is not None:
                issue["comment_count"] = len(bucket)
            else:
                pull["comment_count"] = len(bucket)
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "comment_count": len(bucket)}
        elif name == "create_issue":
            next_id = str(max((int(key) for key in issues), default=0) + 1)
            issues[next_id] = {"title": "new issue", "comment_count": 0, "labels": [], "closed": False}
            comments[f"issue-{next_id}"] = []
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "issue_number": int(next_id)}
        elif name == "update_issue":
            issue_number = str(int(arguments.get("issue_number", 0)))
            issue = issues.get(issue_number)
            if issue is None:
                raise ValueError("issue not found")
            issue["title"] = "updated"
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "issue_number": int(issue_number), "updated": True}
        elif name == "add_labels":
            issue_number = str(int(arguments.get("issue_number", 0)))
            issue = issues.get(issue_number)
            if issue is None:
                raise ValueError("issue not found")
            labels = issue.setdefault("labels", [])
            labels.append("approved-label")
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "label_count": len(labels)}
        elif name == "remove_labels":
            issue_number = str(int(arguments.get("issue_number", 0)))
            issue = issues.get(issue_number)
            if issue is None:
                raise ValueError("issue not found")
            labels = issue.setdefault("labels", [])
            if labels:
                labels.pop()
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "label_count": len(labels)}
        elif name == "request_review":
            pull_number = str(int(arguments.get("pull_number", 0)))
            if pull_number not in pull_requests:
                raise ValueError("pull request not found")
            reached = True
            payload = {"tool": name, "provider_family": "github", "review_requested": True, "pull_number": int(pull_number)}
        elif name == "merge_pull_request":
            pull_number = str(int(arguments.get("pull_number", 0)))
            pull = pull_requests.get(pull_number)
            if pull is None:
                raise ValueError("pull request not found")
            pull["merged"] = True
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "merged": True, "pull_number": int(pull_number)}
        elif name == "close_issue":
            issue_number = str(int(arguments.get("issue_number", 0)))
            issue = issues.get(issue_number)
            if issue is None:
                raise ValueError("issue not found")
            issue["closed"] = True
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "closed": True, "issue_number": int(issue_number)}
        elif name == "delete_branch":
            branch = str(arguments.get("branch") or "feature/other")
            branches = state.setdefault("branches", [])
            if branch in branches:
                branches.remove(branch)
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "deleted_branch": branch}
        elif name == "create_release":
            tag = str(arguments.get("tag_name") or "v9.9.9")
            releases = state.setdefault("releases", [])
            releases.append(tag)
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "release_count": len(releases)}
        elif name == "update_repository_settings":
            visibility = str(arguments.get("visibility") or "public")
            state["visibility"] = visibility
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "visibility": visibility}
        elif name == "manage_secret":
            secret_name = str(arguments.get("secret_name") or "DEPLOY_KEY")
            secret_values = state.setdefault("secret_values", {})
            secret_values[secret_name] = "rotated-secret-value"
            if secret_name not in state.setdefault("secret_names", []):
                state["secret_names"].append(secret_name)
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "secret_names_count": len(state["secret_names"])}
        elif name in {"rerun_workflow", "dispatch_workflow"}:
            runs = state.setdefault("workflow_runs", [])
            runs.append({"id": len(runs) + 1, "status": "queued", "conclusion": None})
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "workflow_run_count": len(runs)}
        elif name == "cancel_workflow":
            runs = state.setdefault("workflow_runs", [])
            for item in runs:
                if item.get("status") == "queued":
                    item["status"] = "cancelled"
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "workflow_run_count": len(runs)}
        elif name == "publish_package":
            versions = state.setdefault("package_publish_state", {}).setdefault("published_versions", [])
            versions.append("9.9.9")
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "published_package_count": len(versions)}
        elif name == "deploy_release":
            deploy_state = state.setdefault("deploy_state", {})
            deploy_state["active"] = True
            self._save_state(state)
            reached = True
            payload = {"tool": name, "provider_family": "github", "deploy_active": True}
        elif name == "run_remote_command":
            remote_state = state.setdefault("remote_execution_state", {})
            remote_state["completed_commands"] = int(remote_state.get("completed_commands", 0)) + 1
            self._save_state(state)
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "remote_completed_commands": remote_state["completed_commands"],
            }
        elif name == "get_secret":
            # Raw downstream capability only. Product route proxy must block before reach (Phase 3).
            secret_name = str(arguments.get("secret_name") or "DEPLOY_KEY")
            secret_values = state.get("secret_values", {})
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "secret_value": secret_values.get(secret_name),
            }
        elif name == "get_env_secret":
            # Raw downstream capability only. Product route proxy must block before reach (Phase 3).
            secret_name = str(arguments.get("secret_name") or "DEPLOY_TOKEN")
            secret_values = state.get("env_secrets", {})
            reached = True
            payload = {
                "tool": name,
                "provider_family": "github",
                "secret_value": secret_values.get(secret_name),
            }
        else:
            raise ValueError(f"unsupported github tool: {name}")
        after = self._bounded_snapshot()
        self._append_outcome(name, before=before, after=after, reached=reached)
        return _bounded_text_result(payload)


__all__ = [
    "GitHubCiPackHandler",
    "GitRepoPackHandler",
    "PackageInstallPackHandler",
]
