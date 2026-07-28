# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Allow running as: python -m agentveil_mcp_proxy"""
from agentveil_mcp_proxy.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
