"""Small compare-and-swap ledger for a single batch's concurrent agent invocations.

Reserve before execution; settle exactly once. An interrupted call retains its reservation
as an upper bound until it can be reconciled, rather than pretending it cost nothing.
"""
from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from pydantic_ai.exceptions import UsageLimitExceeded
from sqlalchemy import update

from infosec_harness.domain.canonical import SHA256_PATTERN, canonical_bytes, is_sha256, sha256_hex
from infosec_harness.persistence import db

FIELDS = ("requests", "tokens", "cost_usd")
EXTENDED_FIELDS = ("tool_calls", "agent_runs", "execution_seconds")


def _validate_usage(values: dict[str, float]) -> None:
    if (any(key not in values for key in FIELDS)
            or any(key not in (*FIELDS, *EXTENDED_FIELDS) or not isfinite(value) or value < 0
                   for key, value in values.items())):
        raise ValueError("Budget values must include finite non-negative requests, tokens, and cost_usd")


def initial_state(limits: dict[str, float], *, elapsed_seconds: float | None = None) -> dict:
    _validate_usage(limits)
    if any(key in limits for key in EXTENDED_FIELDS) and not all(key in limits for key in EXTENDED_FIELDS):
        raise ValueError("Extended root dimensions must be provided together")
    state = {"version": 2 if any(key in limits for key in EXTENDED_FIELDS) else 1,
             "limits": limits, "used": dict.fromkeys(limits, 0), "operations": {}}
    if elapsed_seconds is not None:
        if not isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise ValueError("Elapsed budget must be finite and positive")
        now = datetime.now(UTC)
        state.update(started_at=now.isoformat(),
                     deadline_at=(now + timedelta(seconds=elapsed_seconds)).isoformat())
    return state


async def remaining_time(root_id: str) -> float | None:
    """Read the persisted acceptance-time deadline; restart never renews it."""
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, root_id)
        if ledger is None:
            raise MissingLedger(f"No budget ledger exists for root {root_id!r}")
        deadline = ledger.state.get("deadline_at")
    return _remaining_time(deadline)


def _remaining_time(deadline: str | None) -> float | None:
    if deadline is None:
        return None
    remaining = (datetime.fromisoformat(deadline) - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        raise UsageLimitExceeded("Root elapsed-time budget exhausted")
    return remaining


class MissingLedger(LookupError):
    """An operation named a root that has no budget ledger: it cannot be accounted."""


# Compare-and-set attempts against one root before contention is reported, for every writer of
# the root ledger (budget reservations here, the broker's request ledger and admission).
CAS_ATTEMPTS = 20


class _Retry:
    """Sentinel: the compare-and-set lost its race and the session was rolled back."""


RETRY = _Retry()


class ContentionExhausted(RuntimeError):
    """Every bounded compare-and-set attempt lost its race."""


async def cas_retry[T](body: Callable[[Any], Awaitable[T | _Retry]], *,
                       exhausted: Callable[[], BaseException] = lambda: ContentionExhausted(
                           "Root budget contention exceeded bounded retry count")) -> T:
    """Run ``body`` in a fresh session until it stops returning :data:`RETRY`, boundedly.

    ``exhausted`` builds the error raised when every attempt lost; callers with their own
    failure vocabulary (the broker's ``unavailable``) supply it.
    """
    for _ in range(CAS_ATTEMPTS):
        async with db.session() as session:
            outcome = await body(session)
            if not isinstance(outcome, _Retry):
                return outcome
    raise exhausted()


async def cas_root(session, root: db.BudgetLedger, state: dict) -> bool:
    """Compare-and-set one root state at its read revision; on a lost race roll back."""
    won = await session.execute(update(db.BudgetLedger).where(
        db.BudgetLedger.root_id == root.root_id, db.BudgetLedger.revision == root.revision
    ).values(state=state, revision=root.revision + 1))
    if won.rowcount != 1:
        await session.rollback()
        return False
    return True


async def _mutate(root_id: str, change: Callable[[dict], dict]) -> dict:
    async def attempt(session) -> dict | _Retry:
        ledger = await session.get(db.BudgetLedger, root_id)
        if ledger is None:
            raise MissingLedger(f"No budget ledger exists for root {root_id!r}")
        state = deepcopy(ledger.state)
        result = change(state)
        if state == ledger.state:
            return result
        if not await cas_root(session, ledger, state):
            return RETRY
        await session.commit()
        return result
    return await cas_retry(attempt)


# ---------------------------------------------------------------------------
# Closed-unknown accounting: the audit a reservation re-verifies before it excludes an
# operator-closed envelope from held capacity. ``persistence.reconciliation`` writes these
# markers; both read them through the definitions here.
# ---------------------------------------------------------------------------

_MARKER_KEYS = {"version", "authorization", "charged", "accounting_basis", "closed_operation_sha256"}


def _canonical(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def reconciliation_digest(value) -> str:
    """FROZEN encoding of persisted closure markers and operator-supplied snapshot hashes.

    ASCII-escaped canonical JSON of UTC-normalized values. Stored ``closed_operation_sha256``
    markers and operator dry-run inputs depend on these exact bytes; never change it to the
    default canonical encoding.
    """
    return sha256_hex(canonical_bytes(_canonical(value), ascii_only=True))


class ClosureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    root_id: str = Field(min_length=1, max_length=512)
    operation_id: str = Field(min_length=1, max_length=512)
    expected_root_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_root_revision: StrictInt = Field(ge=0)
    expected_request_sha256: dict[str, str]
    unknown_request_ids: list[str]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    evidence_sha256: dict[str, str]
    reason: Literal["loss_accepted"]

    @model_validator(mode="after")
    def closed_allowlist(self):
        for mapping in (self.expected_request_sha256, self.evidence_sha256):
            if not mapping or any(not key or len(key) > 512 or not is_sha256(value)
                                  for key, value in mapping.items()):
                raise ValueError("Exact nonempty hash mappings required")
        if (not self.unknown_request_ids or self.unknown_request_ids != sorted(set(self.unknown_request_ids))
                or not set(self.unknown_request_ids) <= set(self.expected_request_sha256)):
            raise ValueError("Exact sorted unknown request allowlist required")
        return self


def _dimensions(values, keys):
    if not isinstance(values, dict) or set(values) != keys:
        raise ValueError("Missing or extra accounting dimension")
    if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
           for value in values.values()):
        raise ValueError("Accounting must be finite non-negative numbers, never booleans")


def _check_bounds(state) -> set[str]:
    """The root's accounting dimensions: complete, finite, and with usage within limits."""
    keys = set(state["limits"])
    allowed = set(FIELDS) | set(EXTENDED_FIELDS)
    if not set(FIELDS) <= keys or not keys <= allowed:
        raise ValueError("Invalid root accounting bounds")
    if keys & set(EXTENDED_FIELDS) and not set(EXTENDED_FIELDS) <= keys:
        raise ValueError("Incomplete extended root accounting bounds")
    _dimensions(state["limits"], keys)
    _dimensions(state.get("used"), keys)
    if any(state["used"][key] > state["limits"][key] for key in keys):
        raise ValueError("Root usage exceeds accounting bounds")
    return keys


def _operation_hash(operation):
    clean = deepcopy(operation)
    clean.pop("unknown_reconciliation", None)
    return reconciliation_digest(clean)


def _marker_is_valid(operation) -> bool:
    """The exact version-1 closure marker of a ``closed_unknown`` operation, unchanged since."""
    marker = operation.get("unknown_reconciliation")
    return (isinstance(marker, dict) and set(marker) == _MARKER_KEYS
            and type(marker["version"]) is int and marker["version"] == 1
            and marker["accounting_basis"] == "full_reserved_envelope_estimate"
            and operation.get("status") == "closed_unknown"
            and marker["charged"] == operation.get("reserved")
            and marker["closed_operation_sha256"] == _operation_hash(operation))


def _charged_floor(state):
    keys = set(state["limits"])
    totals = {key: [] for key in keys}
    for identity, operation in state["operations"].items():
        if operation.get("status") == "closed_unknown":
            marker = operation["unknown_reconciliation"]
            audit = ClosureRequest.model_validate(marker["authorization"])
            if (not _marker_is_valid(operation) or audit.operation_id != identity
                    or operation.get("broker_overrun")):
                raise ValueError("Invalid existing closure audit")
            _dimensions(operation["reserved"], keys)
            binding = operation["broker_binding"]
            if (operation.get("broker_owned") is not True or operation.get("broker_revoked") is not True
                    or binding.get("root_id") != audit.root_id or binding.get("operation_id") != identity
                    or operation.get("run_id") != binding.get("run_id")
                    or operation.get("run_id") not in state.get("broker_revoked_runs", [])):
                raise ValueError("Invalid existing closure ownership")
            values = marker["charged"]
        elif operation.get("status") == "settled":
            values = operation["observed"]
        else:
            continue
        _dimensions(values, keys)
        for key in keys:
            totals[key].append(values[key])
    if any(state["used"][key] < math.fsum(totals[key]) for key in keys):
        raise ValueError("Root usage no longer covers conservative charges")


def validate_closed_accounting(state: dict) -> None:
    """Verify closed envelopes before excluding them from held capacity; no I/O."""
    _check_bounds(state)
    try:
        _charged_floor(state)
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError("Malformed closed accounting audit") from error


async def reserve(root_id: str, operation_id: str, requested: dict[str, float], agent: str,
                  configuration_digest: str | None = None,
                  operation_kind: Literal["agent", "execution"] = "agent",
                  run_id: str | None = None, invocation_id: str | None = None,
                  fingerprint: str | None = None) -> dict:
    """Reserve ``requested`` for one operation, idempotently per ``operation_id``.

    ``fingerprint`` names the finding the operation is spent on, so results are attributed by
    an explicit field rather than by reading identifiers.
    """
    _validate_usage(requested)
    if operation_kind not in {"agent", "execution"}:
        raise ValueError("Unknown budget operation kind")
    if operation_kind == "execution" and any(requested.get(key, 0) for key in
            ("requests", "tokens", "tool_calls", "agent_runs")):
        raise ValueError("Execution reservations cannot bypass agent configuration checks")

    def change(state: dict) -> dict:
        _remaining_time(state.get("deadline_at"))
        if run_id is not None and run_id in state.get("broker_revoked_runs", []):
            raise ValueError("Broker run admission has been revoked")
        if operation_kind == "agent":
            accepted_configs = state.get("agent_config_digests")
            if not isinstance(accepted_configs, dict):
                # A ledger that pins no configuration cannot show which agent ran.
                raise ValueError("Root ledger does not pin the accepted agent configurations")
            accepted_config = accepted_configs.get(agent)
            if accepted_config is None or configuration_digest != accepted_config:
                raise ValueError(f"Worker configuration for {agent} differs from the accepted batch")
        fields = tuple(state["limits"])
        if any(key not in requested for key in fields):
            raise ValueError("Reservation omits a configured root budget dimension")
        demand = {key: requested[key] for key in fields}
        operations = state["operations"]
        if operation_id in operations:
            operation = operations[operation_id]
            if (operation["agent"] != agent or operation["reserved"] != demand
                    or operation["kind"] != operation_kind
                    or operation.get("fingerprint") != fingerprint
                    or (run_id is not None and operation.get("run_id") != run_id)
                    or (invocation_id is not None and operation.get("invocation_id") != invocation_id)):
                raise ValueError("Operation already reserved with different budget or agent")
            return operation
        if any(o.get("status") == "closed_unknown" for o in operations.values()):
            validate_closed_accounting(state)
        held = {key: sum(o["reserved"].get(key, 0) for o in operations.values()
                         if o["status"] not in {"settled", "closed_unknown"}) for key in fields}
        remaining = {key: state["limits"][key] - state["used"][key] - held[key] for key in fields}
        if any(demand[key] > remaining[key] for key in fields):
            raise UsageLimitExceeded(f"Root budget cannot reserve invocation for {agent}; remaining={remaining}")
        operation = {"agent": agent, "kind": operation_kind, "fingerprint": fingerprint,
                     "status": "reserved", "reserved": demand}
        if run_id is not None or invocation_id is not None:
            if not run_id or not invocation_id:
                raise ValueError("Broker invocation ownership requires both run and invocation")
            operation.update(run_id=run_id, invocation_id=invocation_id)
        operations[operation_id] = operation
        return operation
    return await _mutate(root_id, change)


async def settle(root_id: str, operation_id: str, observed: dict[str, float] | None,
                 record: dict[str, Any]) -> dict:
    if observed is not None:
        _validate_usage(observed)

    def change(state: dict) -> dict:
        operation = state["operations"][operation_id]
        if operation["status"] in {"settled", "closed_unknown"}:
            return operation
        operation["record"] = record
        if operation.get("broker_owned"):
            # Only the controller can reconcile broker dispatches, including lost results.
            # Worker-observed usage cannot release possible spend from another attempt.
            operation["status"] = "uncertain"
            if observed is not None:
                operation["worker_observed"] = observed
        elif observed is None or any(key not in observed for key in state["limits"]):
            operation["status"] = "uncertain"
        else:
            for key in state["limits"]:
                if observed.get(key, 0) < 0:
                    raise ValueError("Observed usage must be non-negative")
                state["used"][key] += observed.get(key, 0)
            operation.update(status="settled", observed=observed)
            operation["overrun"] = {key: observed[key] - operation["reserved"].get(key, 0)
                for key in state["limits"]
                if observed[key] > operation["reserved"].get(key, 0)}
        return operation
    return await _mutate(root_id, change)
