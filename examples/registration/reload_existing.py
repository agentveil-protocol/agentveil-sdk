#!/usr/bin/env python3
"""Save an encrypted local agent key, reload it, and inspect setup state.

This example uses a temporary HOME so it does not touch your real
~/.avp/agents directory. No backend is required.
"""

import os
import tempfile
import logging


def main() -> int:
    with tempfile.TemporaryDirectory() as home:
        os.environ["HOME"] = home

        from agentveil import AVPAgent

        logging.getLogger("agentveil").setLevel(logging.ERROR)

        passphrase = "example-passphrase-change-me"
        base_url = "https://agentveil.dev"

        agent = AVPAgent.create(base_url, name="reload-demo", save=False)
        saved_path = agent.save(passphrase=passphrase)
        loaded = AVPAgent.load(base_url, name="reload-demo", passphrase=passphrase)

        print("saved_path:", saved_path)
        print("same_did:", loaded.did == agent.did)
        print("registered:", loaded.is_registered)
        print("verified:", loaded.is_verified)
        print("next_step: register this DID before controlled_action(...)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
