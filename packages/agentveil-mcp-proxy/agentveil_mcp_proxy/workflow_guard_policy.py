"""T2 Workflow Guard: role policy and redirect playbooks over T1 envelopes.

Evaluates ``WorkflowActionEnvelope`` metadata with deterministic role profiles.
Does not execute commands, mutate envelopes, write evidence, or integrate with
Runtime Gate, Approval Center, or MCP Proxy enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
try:
    from enum import StrEnum
except ImportError:  # Python < 3.11
    from enum import Enum

    class StrEnum(str, Enum):
        pass
from typing import Any

from agentveil_mcp_proxy.workflow_guard import (
    WorkflowActionEnvelope,
    WorkflowActionType,
    WorkflowDisposition,
)

_LOCAL_SAFE_ACTIONS = frozenset({
    WorkflowActionType.LOCAL_READ,
    WorkflowActionType.LOCAL_TEST,
})
_REMOTE_ACTIONS = frozenset({
    WorkflowActionType.REMOTE_SSH,
    WorkflowActionType.REMOTE_SCP,
})
_PUSH_RELEASE_ACTIONS = frozenset({
    WorkflowActionType.GIT_PUSH,
    WorkflowActionType.RELEASE_PUBLISH,
    WorkflowActionType.GH_PR_MUTATION,
})
_INFRA_ACTIONS = frozenset({
    WorkflowActionType.DEPLOY,
    WorkflowActionType.REMOTE_SSH,
    WorkflowActionType.REMOTE_SCP,
})


class RoleProfile(StrEnum):
    REVIEWER = "reviewer"
    IMPLEMENTER = "implementer"
    OPS = "ops"
    RELEASE = "release"


class PolicyDecisionType(StrEnum):
    ALLOW = "allow"
    APPROVAL_REQUIRED = "approval_required"
    BLOCK = "block"
    BLOCK_AND_REDIRECT = "block_and_redirect"


@dataclass(frozen=True)
class RedirectPlaybook:
    """Compact, copy-ready redirect text for a redirected workflow."""

    playbook_id: str
    title: str
    workflow_text: str

    def to_metadata_dict(self) -> dict[str, str]:
        return {
            "playbook_id": self.playbook_id,
            "title": self.title,
            "workflow_text": self.workflow_text,
        }


@dataclass(frozen=True)
class WorkflowPolicyContext:
    """Optional markers that refine deterministic role policy."""

    role_profile: RoleProfile
    implementation_scope_allowed: bool = False
    release_approval_marker: bool = False
    ops_infra_approved: bool = False


@dataclass(frozen=True)
class WorkflowPolicyResult:
    """Role policy outcome for one T1 envelope."""

    decision: PolicyDecisionType
    role_profile: RoleProfile
    policy_rule_id: str
    action_metadata: dict[str, Any]
    redirect: RedirectPlaybook | None = None

    def to_metadata_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision": self.decision.value,
            "role_profile": self.role_profile.value,
            "policy_rule_id": self.policy_rule_id,
            "action_metadata": self.action_metadata,
        }
        if self.redirect is not None:
            payload["redirect"] = self.redirect.to_metadata_dict()
        return payload


PLAYBOOK_DEV_OPS_TASK = RedirectPlaybook(
    playbook_id="dev_ops_remote_task",
    title="Dev / ops remote task",
    workflow_text=(
        "Owner: Dev A / Dev B (ops)\n"
        "Task: Run the approved remote or VPS step from the operator acceptance artifact.\n"
        "Scope: Named host/ref from acceptance marker only; no ad-hoc remote shell.\n"
        "Stop: Missing VPS acceptance, wrong role profile, or reviewer attempting remote execution."
    ),
)
PLAYBOOK_IMPLEMENTER_SLICE = RedirectPlaybook(
    playbook_id="implementer_slice_task",
    title="Implementer slice from review",
    workflow_text=(
        "Owner: Dev A / Dev B\n"
        "Task: Implement the scoped slice from the review finding or Codex return.\n"
        "Scope: Allowed files from the task block only; dedicated worktree and branch.\n"
        "Stop: Reviewer role cannot mutate product files without implementer handoff."
    ),
)
PLAYBOOK_ACCEPTANCE_PUSH = RedirectPlaybook(
    playbook_id="acceptance_marker_push",
    title="Acceptance marker before push",
    workflow_text=(
        "Owner: Codex (integrator)\n"
        "Task: Push only via guarded_push after VPS/user-path acceptance.\n"
        "Checklist: ALLOW_PUSH_<branch> marker matches HEAD; slice_guard green; operator approved.\n"
        "Stop: Reviewer role must not push; missing acceptance marker or wrong commit."
    ),
)
PLAYBOOK_RELEASE_GATE = RedirectPlaybook(
    playbook_id="release_gate_checklist",
    title="Release gate checklist",
    workflow_text=(
        "Owner: Release operator + Codex\n"
        "Task: Run the release gate checklist before publish or tag.\n"
        "Checklist: CI green, acceptance marker present, version verified, privacy scan clean.\n"
        "Stop: Missing release_approval_marker metadata or publish without gate sign-off."
    ),
)
PLAYBOOK_SECRET_SURFACE = RedirectPlaybook(
    playbook_id="secret_surface_block",
    title="Secret or credential surface",
    workflow_text=(
        "Owner: Operator\n"
        "Task: Stop and rotate or redact if a secret may have been exposed.\n"
        "Scope: Use approved metadata-only audit paths; do not paste raw credentials.\n"
        "Stop: Secret-path or environment-dump classification; rerun with reviewed wrappers only."
    ),
)
PLAYBOOK_DANGEROUS_APPROVAL = RedirectPlaybook(
    playbook_id="dangerous_action_approval",
    title="Dangerous action approval",
    workflow_text=(
        "Owner: Operator + Codex\n"
        "Task: Obtain explicit approval for the classified dangerous action.\n"
        "Scope: Document smallest product-path proof required before retry.\n"
        "Stop: Unclassified shell intent or block-candidate disposition without approval."
    ),
)


class WorkflowGuardPolicyEvaluator:
    """Map T1 envelope metadata to role policy decisions and redirect playbooks."""

    def evaluate(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> WorkflowPolicyResult:
        action_metadata = envelope.to_metadata_dict()
        rule_id, decision, redirect = self._decide(envelope, context)
        return WorkflowPolicyResult(
            decision=decision,
            role_profile=context.role_profile,
            policy_rule_id=rule_id,
            action_metadata=action_metadata,
            redirect=redirect,
        )

    def _decide(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> tuple[str, PolicyDecisionType, RedirectPlaybook | None]:
        action = envelope.action_type
        profile = context.role_profile

        if action == WorkflowActionType.SECRET_PATH_ACCESS:
            return (
                "secret_surface_block",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_SECRET_SURFACE,
            )
        if envelope.disposition == WorkflowDisposition.BLOCK_CANDIDATE:
            if profile == RoleProfile.IMPLEMENTER:
                return (
                    "classifier_block_candidate",
                    PolicyDecisionType.APPROVAL_REQUIRED,
                    PLAYBOOK_DANGEROUS_APPROVAL,
                )
            return (
                "classifier_block_candidate",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_DANGEROUS_APPROVAL,
            )

        if profile == RoleProfile.REVIEWER:
            return self._reviewer_decision(envelope, context)
        if profile == RoleProfile.IMPLEMENTER:
            return self._implementer_decision(envelope, context)
        if profile == RoleProfile.OPS:
            return self._ops_decision(envelope, context)
        if profile == RoleProfile.RELEASE:
            return self._release_decision(envelope, context)
        return (
            "unknown_role_profile",
            PolicyDecisionType.BLOCK,
            None,
        )

    def _reviewer_decision(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> tuple[str, PolicyDecisionType, RedirectPlaybook | None]:
        action = envelope.action_type
        if action in _LOCAL_SAFE_ACTIONS:
            return ("reviewer_local_allow", PolicyDecisionType.ALLOW, None)
        if action in _REMOTE_ACTIONS or action == WorkflowActionType.DEPLOY:
            return (
                "reviewer_remote_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_DEV_OPS_TASK,
            )
        if action in _PUSH_RELEASE_ACTIONS:
            if action == WorkflowActionType.GIT_PUSH:
                return (
                    "reviewer_git_push_redirect",
                    PolicyDecisionType.BLOCK_AND_REDIRECT,
                    PLAYBOOK_ACCEPTANCE_PUSH,
                )
            return (
                "reviewer_release_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_RELEASE_GATE,
            )
        if action == WorkflowActionType.FILE_MUTATION:
            if context.implementation_scope_allowed:
                return ("reviewer_scoped_file_mutation", PolicyDecisionType.ALLOW, None)
            return (
                "reviewer_file_mutation_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_IMPLEMENTER_SLICE,
            )
        if action == WorkflowActionType.PACKAGE_MANAGER_MUTATION:
            return (
                "reviewer_package_mutation_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_IMPLEMENTER_SLICE,
            )
        return (
            "reviewer_dangerous_redirect",
            PolicyDecisionType.BLOCK_AND_REDIRECT,
            PLAYBOOK_DANGEROUS_APPROVAL,
        )

    def _implementer_decision(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> tuple[str, PolicyDecisionType, RedirectPlaybook | None]:
        del context
        action = envelope.action_type
        if action in _LOCAL_SAFE_ACTIONS:
            return ("implementer_local_allow", PolicyDecisionType.ALLOW, None)
        if action == WorkflowActionType.FILE_MUTATION:
            return ("implementer_file_mutation", PolicyDecisionType.ALLOW, None)
        if action in _REMOTE_ACTIONS or action in _PUSH_RELEASE_ACTIONS:
            return (
                "implementer_remote_or_release",
                PolicyDecisionType.APPROVAL_REQUIRED,
                PLAYBOOK_DEV_OPS_TASK if action in _REMOTE_ACTIONS else PLAYBOOK_RELEASE_GATE,
            )
        if action == WorkflowActionType.DEPLOY:
            return (
                "implementer_deploy_approval",
                PolicyDecisionType.APPROVAL_REQUIRED,
                PLAYBOOK_DEV_OPS_TASK,
            )
        if action == WorkflowActionType.PACKAGE_MANAGER_MUTATION:
            return (
                "implementer_package_mutation",
                PolicyDecisionType.APPROVAL_REQUIRED,
                None,
            )
        return (
            "implementer_dangerous_approval",
            PolicyDecisionType.APPROVAL_REQUIRED,
            PLAYBOOK_DANGEROUS_APPROVAL,
        )

    def _ops_decision(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> tuple[str, PolicyDecisionType, RedirectPlaybook | None]:
        action = envelope.action_type
        if action in _LOCAL_SAFE_ACTIONS:
            return ("ops_local_allow", PolicyDecisionType.ALLOW, None)
        if action in _INFRA_ACTIONS and context.ops_infra_approved:
            return ("ops_infra_approved_allow", PolicyDecisionType.ALLOW, None)
        if action in _INFRA_ACTIONS:
            return (
                "ops_infra_approval_required",
                PolicyDecisionType.APPROVAL_REQUIRED,
                PLAYBOOK_DEV_OPS_TASK,
            )
        if action in _PUSH_RELEASE_ACTIONS:
            return (
                "ops_release_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_RELEASE_GATE,
            )
        if action == WorkflowActionType.FILE_MUTATION:
            return (
                "ops_file_mutation_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_IMPLEMENTER_SLICE,
            )
        return (
            "ops_dangerous_redirect",
            PolicyDecisionType.BLOCK_AND_REDIRECT,
            PLAYBOOK_DANGEROUS_APPROVAL,
        )

    def _release_decision(
        self,
        envelope: WorkflowActionEnvelope,
        context: WorkflowPolicyContext,
    ) -> tuple[str, PolicyDecisionType, RedirectPlaybook | None]:
        action = envelope.action_type
        if action in _LOCAL_SAFE_ACTIONS:
            return ("release_local_allow", PolicyDecisionType.ALLOW, None)
        if action == WorkflowActionType.RELEASE_PUBLISH:
            if context.release_approval_marker:
                return ("release_publish_allowed", PolicyDecisionType.ALLOW, None)
            return (
                "release_publish_gate",
                PolicyDecisionType.APPROVAL_REQUIRED,
                PLAYBOOK_RELEASE_GATE,
            )
        if action in _PUSH_RELEASE_ACTIONS or action == WorkflowActionType.DEPLOY:
            return (
                "release_remote_or_deploy",
                PolicyDecisionType.APPROVAL_REQUIRED,
                PLAYBOOK_RELEASE_GATE,
            )
        if action in _REMOTE_ACTIONS:
            return (
                "release_remote_redirect",
                PolicyDecisionType.BLOCK_AND_REDIRECT,
                PLAYBOOK_DEV_OPS_TASK,
            )
        return (
            "release_dangerous_redirect",
            PolicyDecisionType.BLOCK_AND_REDIRECT,
            PLAYBOOK_DANGEROUS_APPROVAL,
        )


__all__ = [
    "PLAYBOOK_ACCEPTANCE_PUSH",
    "PLAYBOOK_DEV_OPS_TASK",
    "PLAYBOOK_DANGEROUS_APPROVAL",
    "PLAYBOOK_IMPLEMENTER_SLICE",
    "PLAYBOOK_RELEASE_GATE",
    "PLAYBOOK_SECRET_SURFACE",
    "PolicyDecisionType",
    "RedirectPlaybook",
    "RoleProfile",
    "WorkflowGuardPolicyEvaluator",
    "WorkflowPolicyContext",
    "WorkflowPolicyResult",
]
