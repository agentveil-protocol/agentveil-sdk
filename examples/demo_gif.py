#!/usr/bin/env python3
"""
Terminal demo for GIF recording — shows the AgentVeil SDK control loop.

The GIF is public-facing and intentionally uses placeholders. It shows real
SDK surface names without calling a backend, exposing secrets, or printing
deployment internals.

Record with asciinema:
    asciinema rec /tmp/agentveil-demo.cast -c "python examples/demo_gif.py" --overwrite
Convert to GIF:
    agg /tmp/agentveil-demo.cast docs/demo.gif --cols 72 --rows 28 --speed 1
"""

import time

# ANSI colors
G = "\033[32m"    # green
R = "\033[31m"    # red
Y = "\033[33m"    # yellow
B = "\033[34m"    # blue
C = "\033[36m"    # cyan
W = "\033[1;37m"  # bold white
D = "\033[2m"     # dim
RST = "\033[0m"   # reset


def p(text: str = "", delay: float = 0.42) -> None:
    print(text, flush=True)
    time.sleep(delay)


def header(num: str, title: str) -> None:
    print(flush=True)
    p(f"{W}{'=' * 60}{RST}", 0.12)
    p(f"{W}  [{num}/5] {title}{RST}", 0.12)
    p(f"{W}{'=' * 60}{RST}", 0.36)


def code(text: str, delay: float = 0.24) -> None:
    p(f"{D}>>> {text}{RST}", delay)


def kv(key: str, value: str, color: str = G, comma: bool = True) -> None:
    tail = "," if comma else ""
    p(f'{Y}    "{key}"{RST}: {color}{value}{RST}{D}{tail}{RST}', 0.15)


print(flush=True)
p(f"{C}  AgentVeil SDK{RST}", 0.28)
p(f"{D}  posture checks, runtime gates, signed receipts{RST}", 0.18)
p(f"{D}  for risky AI agent actions{RST}", 0.72)

# Scene 1: Preflight
header("1", "Preflight before runtime")

code("from agentveil import AVPAgent, verify_proof_packet", 0.22)
code('agent = AVPAgent.load("https://agentveil.dev", "releasebot")', 0.24)
code("report = agent.integration_preflight()", 0.24)
p(f"{D}  {{")
kv("api", '"reachable"')
kv("identity", '"verified"')
kv("signed_request", '"ok"')
kv("ready", "true", G, comma=False)
p(f"{D}  }}{RST}", 0.42)
p(f"{G}  READY{RST}  the agent can make signed AVP requests", 0.68)

# Scene 2: Risky action request
header("2", "Risky action request")

code('action = "deploy.release"', 0.2)
code('resource = "service:critical-workflow"', 0.2)
code('environment = "production"', 0.2)
p(f"{D}  {{")
kv("actor", '"ReleaseBot"')
kv("scope", '"production release"', G)
kv("capabilities", '["write", "deploy", "prod"]', Y)
kv("receipt", '"required"', G, comma=False)
p(f"{D}  }}{RST}", 0.42)
p(f"{Y}  HIGH RISK{RST}  this should not execute without an explicit gate", 0.68)

# Scene 3: Runtime Gate
header("3", "Runtime Gate pauses execution")

code("outcome = agent.controlled_action(...)", 0.24)
p(f"{D}  {{")
kv("status", '"approval_required"', Y)
kv("decision", '"WAITING_FOR_HUMAN_APPROVAL"', Y)
kv("execute_called", "false", R)
kv("approval_id", '"appr_7a91..."', G, comma=False)
p(f"{D}  }}{RST}", 0.42)
p(f"{Y}  PAUSED{RST}  AgentVeil gates the action before it runs", 0.68)

# Scene 4: Approval + controlled execution
header("4", "Approval unlocks execution")

code("approval = owner.approve(outcome.approval['approval_id'])", 0.24)
code("outcome = agent.execute_after_approval(...)", 0.24)
p(f"{D}  {{")
kv("approval", '"operator_approved"', G)
kv("execution", '"recorded"', G)
kv("receipt", '"signed"', G)
kv("status", '"executed"', G, comma=False)
p(f"{D}  }}{RST}", 0.42)
p(f"{G}  EXECUTED{RST}  only after approval, with signed proof", 0.68)

# Scene 5: Proof packet + offline verification
header("5", "Signed proof clients can verify")

code("packet = agent.build_proof_packet(...)", 0.22)
code("verify_proof_packet(packet)", 0.24)
p(f"{D}  {{")
kv("signatures", '"valid"', G)
kv("gate_decision", '"matched"', G)
kv("receipt", '"verified"', G)
kv("offline", "true", G, comma=False)
p(f"{D}  }}{RST}", 0.42)
p(f"{G}  VERIFIED{RST}  reviewer does not need your dashboard", 0.52)
print(flush=True)
p(f"{W}  preflight -> gate -> approval -> execution -> proof{RST}", 0.48)

print(flush=True)
p(f"{W}{'=' * 60}{RST}", 0.12)
p(f"{G}  https://agentveil.dev{RST}", 0.24)
p(f"{G}  pip install agentveil{RST}", 0.24)
p(f"{W}{'=' * 60}{RST}", 0.45)
print(flush=True)
