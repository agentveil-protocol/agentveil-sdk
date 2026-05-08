#!/usr/bin/env python3
"""Create an agent and show registration state.

Defaults to mock mode, so it runs without a backend. To create a real backend
registration record, set AVP_REGISTRATION_LIVE=1, AVP_BASE_URL, and
AVP_AGENT_PASSPHRASE.
"""

import os

import httpx

from agentveil import AVPAgent, AVPError


def main() -> int:
    live = os.getenv("AVP_REGISTRATION_LIVE") == "1"
    base_url = os.getenv("AVP_BASE_URL", "https://agentveil.dev")
    passphrase = os.getenv("AVP_AGENT_PASSPHRASE")

    if live and not passphrase:
        print("configuration_error: set AVP_AGENT_PASSPHRASE for live mode")
        return 2

    if live:
        agent = AVPAgent.create(base_url, name="registration-demo", save=False)
    else:
        agent = AVPAgent.create(mock=True, name="registration-demo")

    try:
        result = agent.register(
            display_name="Registration Demo Agent",
            capabilities=["demo", "controlled_action"],
            provider="demo",
        )
        if live:
            agent.save(passphrase=passphrase)
        onboarding = agent.wait_for_onboarding(timeout=5.0, poll_interval=0.5)
    except (AVPError, httpx.RequestError, TimeoutError, ValueError) as exc:
        print("registration_error:", type(exc).__name__, str(exc))
        return 1

    print("did:", agent.did)
    print("registered:", agent.is_registered)
    print("verified:", agent.is_verified)
    print("onboarding_pending:", result.get("onboarding_pending", False))
    print("onboarding_status:", onboarding.get("status"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
