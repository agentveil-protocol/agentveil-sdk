"""
AVP Proof Pack — orchestrator.

Runs the full story arc end-to-end against a LOCAL AVP stack:

    register -> trust-check (allow) -> issue DelegationReceipt
    -> negative attestation -> recompute -> trust-check (deny)
    -> webhook alert -> audit trail -> offline chain verification

Prerequisites:
    1. A local AVP backend up via docker compose, with
       ENVIRONMENT=development so /v1/alerts accepts http:// webhooks.
    2. python webhook_receiver.py running on port 8765 (another terminal).
    3. pip install agentveil httpx pynacl base58

Run:
    python run_demo.py
    python run_demo.py --server http://localhost:8000 --compose-service api

Writes one JSON artifact per scene to ./artifacts/. See README.md.

Notes:
  - Local docker-compose only — the hosted instance does not accept http://
    webhooks, so this walkthrough requires a development-mode backend.
  - Real degradation + real recompute + real dispatcher (only the webhook
    transport is local).
  - Container names are not hardcoded — uses `docker compose exec <service>`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from agentveil import AVPAgent

ART = Path(__file__).parent / "artifacts"
ART.mkdir(exist_ok=True)


def save(name: str, data: Any) -> Path:
    path = ART / name
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  -> artifacts/{name}")
    return path


def section(n: int, title: str) -> None:
    print(f"\n{'=' * 60}\n[{n}] {title}\n{'=' * 60}")


def wait_for_receiver(url: str, timeout: float = 5.0) -> None:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"webhook receiver not reachable at {url} within {timeout}s")


def run_recompute(
    mode: str,
    compose_service: str,
    compose_project_dir: str | None,
    avp_repo_dir: str | None,
    python_exec: str,
) -> dict:
    """
    Trigger reputation recompute.

    mode="docker" : `docker compose exec <service> python -m app.jobs.reputation_compute`
                    (service name from compose — never hardcoded container names).
    mode="local"  : run the job directly in a python interpreter with `avp_repo_dir`
                    on PYTHONPATH. Use when the backend runs as a plain Python
                    process on the host (Вариант 1).
    """
    if mode == "docker":
        cmd = ["docker", "compose"]
        if compose_project_dir:
            cmd += ["-f", str(Path(compose_project_dir) / "docker-compose.yml")]
        cmd += [
            "exec", "-T", compose_service,
            "python", "-m", "app.jobs.reputation_compute",
        ]
        env = None
    elif mode == "local":
        if not avp_repo_dir:
            raise RuntimeError("--avp-repo-dir is required when --recompute-mode=local")
        cmd = [python_exec, "-m", "app.jobs.reputation_compute"]
        env = os.environ.copy()
        env["PYTHONPATH"] = avp_repo_dir + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
    else:
        raise ValueError(f"unknown recompute mode: {mode}")

    print(f"  exec: {' '.join(cmd)}  (mode={mode})")
    start = time.time()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=avp_repo_dir if mode == "local" else None,
        env=env,
    )
    elapsed = round(time.time() - start, 2)
    return {
        "command": cmd,
        "mode": mode,
        "returncode": proc.returncode,
        "elapsed_sec": elapsed,
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=os.environ.get("AVP_URL", "http://localhost:8000"))
    ap.add_argument("--webhook-url", default="http://avp-demo.localtest.me:8765/hook",
                    help="URL the AVP dispatcher posts to. Uses localtest.me (public DNS "
                         "record → 127.0.0.1) to pass the backend's literal-IP SSRF check "
                         "while still hitting the local receiver.")
    ap.add_argument("--webhook-health", default="http://127.0.0.1:8765/health")
    ap.add_argument("--compose-service", default="api")
    ap.add_argument("--compose-dir", default=None,
                    help="Path to the avp/ directory containing docker-compose.yml. "
                         "Defaults to running `docker compose` in the current cwd.")
    ap.add_argument("--recompute-mode", choices=("local", "docker"), default="local",
                    help="local = run reputation job as a host Python process (Вариант 1); "
                         "docker = exec into a running compose service.")
    ap.add_argument("--avp-repo-dir", default=None,
                    help="Path to the avp/ repo (required for --recompute-mode=local).")
    ap.add_argument("--python-exec", default=sys.executable,
                    help="Python interpreter to run the reputation job "
                         "(use the avp venv when --recompute-mode=local).")
    ap.add_argument("--threshold", type=float, default=0.99,
                    help="Alert fires when score drops below this. 0.99 ensures any negative "
                         "attestation trips it for demo purposes.")
    args = ap.parse_args()

    print(f"AVP server: {args.server}")
    print(f"Webhook receiver: {args.webhook_health}")
    wait_for_receiver(args.webhook_health)

    # ── Scene 1: register two agents ───────────────────────────────────
    section(1, "Register two agents (Alice = orchestrator, Bob = worker)")
    suffix = datetime.now().strftime("%H%M%S")
    # SDK v0.6.0: register() returns as soon as verify succeeds; onboarding
    # runs in the background. We can pass capabilities directly without the
    # old "register + separate publish_card" workaround.
    alice = AVPAgent.create(args.server, name=f"proofpack_alice_{suffix}", save=False)
    alice_reg = alice.register(
        display_name=f"Alice (orchestrator) {suffix}",
        capabilities=["orchestration"],
        provider="proof_pack_demo",
    )
    bob = AVPAgent.create(args.server, name=f"proofpack_bob_{suffix}", save=False)
    bob_reg = bob.register(
        display_name=f"Bob (worker) {suffix}",
        capabilities=["code_review"],
        provider="proof_pack_demo",
    )
    print(f"  alice onboarding_pending={alice_reg.get('onboarding_pending')} "
          f"bob onboarding_pending={bob_reg.get('onboarding_pending')}")
    save("01_registration.json", {
        "alice": {"did": alice.did, "name": f"proofpack_alice_{suffix}"},
        "bob": {"did": bob.did, "name": f"proofpack_bob_{suffix}"},
    })

    # ── Scene 2: initial trust check — expect allow/basic or better ───
    section(2, "Initial trust check (Alice asks: can I trust Bob?)")
    check_before = alice.can_trust(bob.did, min_tier="newcomer")
    print(json.dumps(check_before, indent=2))
    save("02_initial_trust_check.json", check_before)

    # ── Scene 3: delegation receipt for the controlled-action path ─────
    section(3, "DelegationReceipt: Alice authorizes Bob for controlled action")
    delegation = alice.issue_delegation_receipt(
        agent_did=bob.did,
        allowed_categories=["infrastructure"],
        valid_for=timedelta(hours=1),
        purpose="Proof Pack controlled-action delegation",
    )
    delegation_check = alice.verify_delegation_receipt(delegation)
    save("03_delegation_receipt.json", {
        "delegation_receipt": delegation,
        "verification": delegation_check,
    })

    # ── Scene 4: Alice subscribes to alert + issues negative attestation
    section(4, "Alice subscribes to alert, then gives Bob a NEGATIVE attestation")
    sub = alice.set_alert(webhook_url=args.webhook_url, threshold=args.threshold)
    # Bob subscribes too so the dispatcher fires on *Bob's* score drop.
    bob_sub = bob.set_alert(webhook_url=args.webhook_url, threshold=args.threshold)
    import hashlib
    evidence = hashlib.sha256(
        f"proofpack:bob_missed_requirements:{bob.did}".encode()
    ).hexdigest()
    neg = alice.attest(
        bob.did,
        outcome="negative",
        weight=1.0,
        context="code_review",
        evidence_hash=evidence,
    )
    save("04_negative_attestation.json", {
        "alice_alert_subscription": sub,
        "bob_alert_subscription": bob_sub,
        "negative_attestation": neg,
    })

    # ── Scene 5: trigger real recompute via docker compose exec ───────
    section(5, "Trigger reputation recompute via docker compose exec")
    score_before = alice.get_reputation(bob.did)
    recompute_result = run_recompute(
        mode=args.recompute_mode,
        compose_service=args.compose_service,
        compose_project_dir=args.compose_dir,
        avp_repo_dir=args.avp_repo_dir,
        python_exec=args.python_exec,
    )
    if recompute_result["returncode"] != 0:
        print("recompute failed:", recompute_result["stderr_tail"])
        save("05_score_drop.json", {
            "before": score_before,
            "recompute": recompute_result,
            "after": None,
            "error": "recompute_failed",
        })
        return 2
    # Small settle window for alert dispatch + DB commit to complete
    time.sleep(2.0)
    score_after = alice.get_reputation(bob.did)
    save("05_score_drop.json", {
        "before": score_before,
        "recompute": recompute_result,
        "after": score_after,
    })

    # ── Scene 6: re-check trust — expect deny or lower tier ───────────
    section(6, "Re-check trust after drop (same question, new answer)")
    check_after = alice.can_trust(bob.did, min_tier="basic")
    print(json.dumps(check_after, indent=2))
    save("06_trust_check_denied.json", {
        "before": check_before,
        "after": check_after,
    })

    # ── Scene 7: pick up whatever the receiver captured ───────────────
    section(7, "Webhook alert payload (captured by local receiver)")
    time.sleep(1.0)
    alert_path = ART / "07_webhook_alert.json"
    if alert_path.exists():
        with open(alert_path) as f:
            alert = json.load(f)
        print(json.dumps(alert["payload"], indent=2))
    else:
        print("  (no alert captured — dispatcher may not have fired; "
              "check threshold or recompute logs)")
        save("07_webhook_alert.json", {"captured": False,
                                        "note": "no alert fired during this run"})

    # ── Scene 8: fetch audit trail for Bob ────────────────────────────
    section(8, "Fetch full audit trail for Bob")
    r = httpx.get(f"{args.server}/v1/audit/{bob.did}", params={"limit": 100}, timeout=15)
    r.raise_for_status()
    trail = r.json()
    save("08_audit_trail.json", trail)
    print(f"  {len(trail)} audit entries")

    # ── Scene 9: verify the chain offline ─────────────────────────────
    # Two complementary checks:
    #   (a) CLIENT-SIDE subset integrity: verify_chain.py recomputes every
    #       entry in the per-DID trail. Proves tamper resistance without
    #       trusting the server. Cannot prove global chain completeness.
    #   (b) SERVER-SIDE global integrity: GET /v1/audit/verify walks the full
    #       chain on the backend. Reference check, trusts the server.
    section(9, "Audit integrity: client subset + server full-chain reference")
    verify_cmd = [
        sys.executable, str(Path(__file__).parent / "verify_chain.py"),
        str(ART / "08_audit_trail.json"),
        "--out", str(ART / "09_chain_verification.json"),
        "--verbose",
    ]
    proc = subprocess.run(verify_cmd, capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print("subset integrity FAILED:", proc.stderr)
        return 3

    # (b) reference: server's full-chain verify endpoint
    r = httpx.get(f"{args.server}/v1/audit/verify", timeout=10)
    r.raise_for_status()
    save("09b_server_full_chain_reference.json", r.json())

    print(f"\n{'=' * 60}\nPROOF PACK DEMO COMPLETE\n{'=' * 60}")
    print(f"Artifacts: {ART}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
