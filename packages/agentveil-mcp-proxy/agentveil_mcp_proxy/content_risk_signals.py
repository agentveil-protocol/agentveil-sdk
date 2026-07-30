# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Local, bounded content-risk signal bridge for optional paid packages.

The public proxy never imports private policy code.  An installed optional
provider may inspect transient MCP arguments locally and return exactly four
booleans.  Raw arguments never enter classification metadata, evidence, or the
Runtime Gate wire request.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any, Mapping

from agentveil.runtime_content_risk_signals import validate_content_risk_signals
from agentveil.exceptions import AVPValidationError


CONTENT_RISK_SIGNAL_PROVIDER_ENTRYPOINT_GROUP = (
    "agentveil_mcp_proxy.content_risk_signal_providers"
)


def derive_content_risk_signals(arguments: Any) -> dict[str, bool] | None:
    """Ask an installed optional provider for bounded local findings only.

    Provider failure or absence is intentionally indistinguishable from no
    paid signal bridge.  Core behavior remains unchanged.
    """

    if not isinstance(arguments, Mapping):
        return None
    try:
        try:
            providers = entry_points(group=CONTENT_RISK_SIGNAL_PROVIDER_ENTRYPOINT_GROUP)
        except TypeError:
            providers = entry_points().get(CONTENT_RISK_SIGNAL_PROVIDER_ENTRYPOINT_GROUP, ())
        for entry in providers:
            try:
                loaded = entry.load()
                provider = loaded() if callable(loaded) else loaded
                derive = getattr(provider, "derive_content_risk_signals", None)
                if not callable(derive):
                    continue
                result = derive(dict(arguments))
                return validate_content_risk_signals(result)
            except (AVPValidationError, TypeError, ValueError):
                return None
            except Exception:
                return None
    except Exception:
        return None
    return None
