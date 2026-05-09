"""Local smoke for MCP proxy evidence export and offline verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceStore,
    ApprovalStatus,
    PendingApproval,
    export_evidence_bundle,
    verify_evidence_bundle_file,
)


PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64
POLICY_CONTEXT_HASH = "c" * 64
APPROVAL_TOKEN_HASH = "sha256:" + "d" * 64
RESULT_HASH = "sha256:" + "e" * 64
SECRET = "SECRET_PROOF_SMOKE"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-proof-smoke-") as tmp:
        root = Path(tmp)
        db_path = root / "evidence.sqlite"
        bundle_path = root / "evidence-bundle.json"
        with ApprovalEvidenceStore(db_path) as store:
            store.write_pending(
                PendingApproval(
                    request_id="proof-smoke-request",
                    session_id="proof-smoke-session",
                    client_id="proof-smoke-client",
                    downstream_server="github",
                    tool_name="create_issue",
                    action_class="write",
                    risk_class="write",
                    resource_hash=RESOURCE_HASH,
                    payload_hash=PAYLOAD_HASH,
                    policy_id="proof-smoke-policy",
                    policy_rule_id="proof-smoke-rule",
                    policy_context_hash=POLICY_CONTEXT_HASH,
                    status=ApprovalStatus.PENDING.value,
                    created_at=1_700_000_000,
                    expires_at=1_700_000_300,
                )
            )
            store.transition(
                "proof-smoke-request",
                ApprovalStatus.APPROVED.value,
                approval_token_hash=APPROVAL_TOKEN_HASH,
                approval_decided_by="local-user",
            )
            store.transition(
                "proof-smoke-request",
                ApprovalStatus.EXECUTED.value,
                result_hash=RESULT_HASH,
            )
            export_evidence_bundle(
                store,
                bundle_path,
                proxy_identity_did="did:key:z6MkproofSmoke",
                trusted_signer_dids=["did:key:z6MktrustedSigner"],
            )

        result = verify_evidence_bundle_file(bundle_path)
        rendered = bundle_path.read_text(encoding="utf-8")
        assert SECRET not in rendered
        assert "raw_args" not in rendered
        assert json.loads(rendered)["records"][0]["request_id"] == "proof-smoke-request"
        print(
            "P7B_PROOF_SMOKE: ok "
            f"records={result.record_count} receipts={result.signed_receipt_count} "
            f"bundle={bundle_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
