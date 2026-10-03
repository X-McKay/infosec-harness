"""Nested inference waits; provider work stays bounded independently of HTTP inactivity."""

from __future__ import annotations

import math
import time

from .protocol import BrokerError

LEDGER_TIMEOUT_S = 30.0
# Successful direct model activities reached 104.23 s. Double that observed
# maximum, add 30 s, and round up: 240 s. Keep the outer worker below 600 s.
# See docs/validation/CREDENTIAL_BROKER_TIMEOUTS.md for the finite timing sample.
PROVIDER_TIMEOUT_S = 240.0
# Candidate startup controls each allow 60 s; retain a bounded 120 s total
# preparation wall. See the retained pre-inference failure and rationale.
PREPARATION_TIMEOUT_S = 120.0
# Claim/verification and completion both have their own ledger-hop allowance.
EXECUTOR_TIMEOUT_S = LEDGER_TIMEOUT_S + PROVIDER_TIMEOUT_S + LEDGER_TIMEOUT_S
RECONCILIATION_TIMEOUT_S = 45.0
CONTROLLER_TIMEOUT_S = PREPARATION_TIMEOUT_S + EXECUTOR_TIMEOUT_S + RECONCILIATION_TIMEOUT_S
SERVER_TIMEOUT_S = CONTROLLER_TIMEOUT_S + RECONCILIATION_TIMEOUT_S + 15.0
WORKER_TIMEOUT_S = SERVER_TIMEOUT_S + 15.0


def remaining_timeout(expires_at: float, ceiling: float, *, now: float | None = None) -> float:
    if not math.isfinite(ceiling) or ceiling <= 0:
        raise BrokerError("policy")
    remaining = expires_at - (time.time() if now is None else now)
    if not math.isfinite(remaining) or remaining <= 0:
        raise BrokerError("expired")
    return min(ceiling, remaining)
