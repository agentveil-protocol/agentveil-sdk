"""Copy-paste runnable starter templates for Level 2 MCP proxy agents."""

from __future__ import annotations

from dataclasses import dataclass
import shlex
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.client_config import DEFAULT_PROXY_COMMAND, build_run_args
from agentveil_mcp_proxy.role_presets import ROLE_PRESET_NAMES, normalize_role_preset_name


class AgentTemplateError(ValueError):
    """Raised when an agent template name or path input is invalid."""


AGENT_TEMPLATE_NAMES: tuple[str, ...] = ("review", "build", "readonly")
_DEFAULT_HOME_PLACEHOLDER = "${AVP_TEMPLATE_HOME}"
_DEFAULT_SANDBOX_PLACEHOLDER = "${AVP_TEMPLATE_SANDBOX}"


@dataclass(frozen=True)
class AgentTemplateSpec:
    """One user-facing starter template mapped to a role preset."""

    template_id: str
    role_preset: str
    title: str
    summary: str
    home_dir_name: str
    sandbox_dir_name: str

    def validate(self) -> None:
        normalize_role_preset_name(self.role_preset)


_AGENT_TEMPLATES: dict[str, AgentTemplateSpec] = {
    "review": AgentTemplateSpec(
        template_id="review",
        role_preset="reviewer",
        title="Review Agent",
        summary="Read and inspect tools; writes are denied by reviewer role authority.",
        home_dir_name="avp-review-agent",
        sandbox_dir_name="avp-review-sandbox",
    ),
    "build": AgentTemplateSpec(
        template_id="build",
        role_preset="implementer",
        title="Build Agent",
        summary="Write-capable implementer preset for allowed quickstart filesystem changes.",
        home_dir_name="avp-build-agent",
        sandbox_dir_name="avp-build-sandbox",
    ),
    "readonly": AgentTemplateSpec(
        template_id="readonly",
        role_preset="readonly",
        title="Read-only Agent",
        summary="Read-only preset that blocks mutation actions before downstream execution.",
        home_dir_name="avp-readonly-agent",
        sandbox_dir_name="avp-readonly-sandbox",
    ),
}


@dataclass(frozen=True)
class TemplateCommand:
    """One bounded runnable CLI step in a starter template."""

    step: int
    description: str
    argv: tuple[str, ...]

    def render(self, *, proxy_command: str) -> str:
        parts = [proxy_command, *self.argv]
        return " ".join(shlex.quote(part) for part in parts)


@dataclass(frozen=True)
class AgentTemplatePlan:
    """Structured starter plan with concrete or placeholder paths."""

    spec: AgentTemplateSpec
    home: Path
    sandbox_root: Path
    config_path: Path
    commands: tuple[TemplateCommand, ...]


def normalize_agent_template_name(name: str) -> str:
    """Return a validated template id."""

    trimmed = name.strip().lower()
    if trimmed not in _AGENT_TEMPLATES:
        supported = ", ".join(AGENT_TEMPLATE_NAMES)
        raise AgentTemplateError(f"unsupported agent template {name!r}; expected one of: {supported}")
    return trimmed


def resolve_agent_template(name: str) -> AgentTemplateSpec:
    """Return the template definition for ``name``."""

    spec = _AGENT_TEMPLATES[normalize_agent_template_name(name)]
    spec.validate()
    return spec


def default_template_paths(
    template_id: str,
    *,
    base_dir: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Return ``(home, sandbox_root, config_path)`` for one template."""

    spec = resolve_agent_template(template_id)
    root = (base_dir or Path.home()).expanduser()
    home = root / spec.home_dir_name
    sandbox_root = root / spec.sandbox_dir_name
    config_path = home / "mcp-proxy" / "config.json"
    return home, sandbox_root, config_path


def _resolve_template_paths(
    template_id: str,
    *,
    home: Path | None,
    sandbox_root: Path | None,
    base_dir: Path | None,
) -> tuple[Path, Path, Path]:
    if home is not None and sandbox_root is not None:
        resolved_home = home.expanduser()
        resolved_sandbox = sandbox_root.expanduser()
        return resolved_home, resolved_sandbox, resolved_home / "mcp-proxy" / "config.json"
    if home is not None or sandbox_root is not None:
        raise AgentTemplateError("pass both home and sandbox_root, or neither for placeholder paths")
    spec = resolve_agent_template(template_id)
    if base_dir is not None:
        return default_template_paths(template_id, base_dir=base_dir)
    placeholder_home = Path(_DEFAULT_HOME_PLACEHOLDER)
    placeholder_sandbox = Path(_DEFAULT_SANDBOX_PLACEHOLDER)
    return (
        placeholder_home,
        placeholder_sandbox,
        placeholder_home / "mcp-proxy" / "config.json",
    )


def build_template_commands(
    template_id: str,
    *,
    home: Path | None = None,
    sandbox_root: Path | None = None,
    base_dir: Path | None = None,
    proxy_command: str = DEFAULT_PROXY_COMMAND,
) -> AgentTemplatePlan:
    """Return bounded init/client-config/explain/run commands for one template."""

    spec = resolve_agent_template(template_id)
    resolved_home, resolved_sandbox, config_path = _resolve_template_paths(
        template_id,
        home=home,
        sandbox_root=sandbox_root,
        base_dir=base_dir,
    )
    home_text = str(resolved_home)
    sandbox_text = str(resolved_sandbox)
    config_text = str(config_path)
    commands = (
        TemplateCommand(
            step=1,
            description="Create local proxy identity, role preset, and quickstart filesystem sandbox",
            argv=(
                "init",
                "--role",
                spec.role_preset,
                "--home",
                home_text,
                "--quickstart-filesystem",
                sandbox_text,
                "--plaintext",
            ),
        ),
        TemplateCommand(
            step=2,
            description="Render copy-paste MCP client config for desktop clients",
            argv=(
                "client-config",
                "print",
                "--home",
                home_text,
                "--config",
                config_text,
            ),
        ),
        TemplateCommand(
            step=3,
            description="Explain allowed, approval-required, and denied action families",
            argv=(
                "explain",
                "role",
                "--home",
                home_text,
                "--config",
                config_text,
            ),
        ),
        TemplateCommand(
            step=4,
            description="Run stdio MCP passthrough for the configured downstream",
            argv=(
                *build_run_args(home=resolved_home, config_path=config_path),
                "--approval-ui-mode",
                "terminal",
            ),
        ),
    )
    return AgentTemplatePlan(
        spec=spec,
        home=resolved_home,
        sandbox_root=resolved_sandbox,
        config_path=config_path,
        commands=commands,
    )


def format_agent_template_text(
    plan: AgentTemplatePlan,
    *,
    proxy_command: str = DEFAULT_PROXY_COMMAND,
) -> str:
    """Render user-facing starter commands."""

    lines = [
        f"# {plan.spec.title}",
        f"# Role preset: {plan.spec.role_preset}",
        f"# Home: {plan.home}",
        f"# Config: {plan.config_path}",
        f"# Sandbox: {plan.sandbox_root}",
        f"# {plan.spec.summary}",
        "",
    ]
    for command in plan.commands:
        lines.append(f"# {command.step}. {command.description}")
        lines.append(command.render(proxy_command=proxy_command))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_agent_template_report(
    *,
    template_id: str | None = None,
    home: Path | None = None,
    sandbox_root: Path | None = None,
    base_dir: Path | None = None,
    proxy_command: str = DEFAULT_PROXY_COMMAND,
) -> dict[str, Any]:
    """Return JSON-serializable template output for one template or the template set."""

    if template_id is not None:
        plan = build_template_commands(
            template_id,
            home=home,
            sandbox_root=sandbox_root,
            base_dir=base_dir,
            proxy_command=proxy_command,
        )
        return {
            "template_id": plan.spec.template_id,
            "role_preset": plan.spec.role_preset,
            "title": plan.spec.title,
            "summary": plan.spec.summary,
            "home": str(plan.home),
            "config_path": str(plan.config_path),
            "sandbox_root": str(plan.sandbox_root),
            "commands": [
                {
                    "step": command.step,
                    "description": command.description,
                    "argv": list(command.argv),
                    "command": command.render(proxy_command=proxy_command),
                }
                for command in plan.commands
            ],
        }
    return {
        "templates": [
            build_agent_template_report(
                template_id=name,
                home=home,
                sandbox_root=sandbox_root,
                base_dir=base_dir,
                proxy_command=proxy_command,
            )
            for name in AGENT_TEMPLATE_NAMES
        ],
    }


def run_agent_template_init(
    template_id: str,
    *,
    home: Path,
    sandbox_root: Path,
    force: bool = False,
) -> Any:
    """Run the same init path as the template's step 1 command."""

    spec = resolve_agent_template(template_id)
    from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream

    return init_proxy(
        home=home,
        role_preset=spec.role_preset,
        policy_pack="filesystem",
        plaintext=True,
        downstream_config=quickstart_filesystem_downstream(sandbox_root),
        force=force,
    )


def assert_template_output_is_privacy_safe(text: str) -> None:
    """Reject template output that could embed secrets or private key material."""

    lowered = text.lower()
    forbidden_markers = (
        "private_key",
        "secret_",
        "api_key",
        "ssh-rsa",
        "begin private key",
    )
    for marker in forbidden_markers:
        if marker in lowered:
            raise AgentTemplateError(f"template output must not include {marker!r}")


__all__ = [
    "AGENT_TEMPLATE_NAMES",
    "AgentTemplateError",
    "AgentTemplatePlan",
    "AgentTemplateSpec",
    "ROLE_PRESET_NAMES",
    "TemplateCommand",
    "assert_template_output_is_privacy_safe",
    "build_agent_template_report",
    "build_template_commands",
    "default_template_paths",
    "format_agent_template_text",
    "normalize_agent_template_name",
    "resolve_agent_template",
    "run_agent_template_init",
]
