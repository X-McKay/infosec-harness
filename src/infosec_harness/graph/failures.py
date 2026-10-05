"""How a pipeline failure is classified: which ``InconclusiveReason`` an exception deserves.

Shared by the in-process and durable paths; it must not depend on Temporal, so serialized
Temporal failures are recognised by their recorded type names.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
from pydantic_ai.exceptions import ModelAPIError, UsageLimitExceeded

from infosec_harness.domain.models import InconclusiveReason
from infosec_harness.inference.wire.protocol import BrokerError


def _failure_chain(e: BaseException) -> Iterator[BaseException]:
    """Yield wrapper causes once, including Temporal's serialized failure chain."""
    seen: set[int] = set()
    current: BaseException | None = e
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "cause", None) or current.__cause__


def _application_error_type(e: BaseException) -> str | None:
    """The serialized type name of a Temporal ``ApplicationError``, without importing Temporal.

    Classification runs on both paths, and the in-process one must not depend on Temporal.
    """
    if any(cls.__name__ == "ApplicationError" for cls in type(e).__mro__):
        value = getattr(e, "type", None)
        return value if isinstance(value, str) else None
    return None


def is_infrastructure_failure(e: BaseException) -> bool:
    """True when the harness's own dependencies failed, rather than the work failing.

    A provider outage, a transport error or a run timeout says nothing about the repository or
    the finding, so it must not be recorded as `environment_unbuildable` -- an eval reading
    that cannot tell an endpoint being down from a pipeline regression.
    """
    serialized_types = {"ModelAPIError", "ModelHTTPError", "APIConnectionError", "APITimeoutError",
                        "ConnectError", "ReadTimeout", "TimeoutError", "BrokerError"}
    return any(isinstance(cause, ModelAPIError | httpx.TransportError | TimeoutError | BrokerError)
        or _application_error_type(cause) in serialized_types
        for cause in _failure_chain(e))


def classify_pipeline_failure(e: BaseException) -> InconclusiveReason:
    """Which ``InconclusiveReason`` an exception escaping a pipeline stage deserves.

    Classified by exception *type*, extending :func:`is_infrastructure_failure` rather than
    matching on message text: a provider's or a library's wording is not a contract, and a
    taxonomy built on strings silently reclassifies itself when one of them is reworded.

    Three outcomes the pipeline used to file under one reason, each with a different fix:

    - ``budget_exhausted`` -- a ceiling *we* set stopped the run; it was not answered. The fix
      is ours: raise the limit, or find the loop that burned it (which is what the per-agent
      ``repeated_tool_calls`` record exists to show). ``UsageLimitExceeded`` means exactly this,
      and the enum member already existed while nothing on this path ever produced it, so a
      budget breach during preparation was indistinguishable from a repository that will not
      build.
    - ``infrastructure_error`` -- our own dependency failed (provider outage, transport error,
      run timeout). Says nothing about the finding at all.
    - ``error`` -- the harness fell over some other way, which is a bug report, not a triage
      result.

    ``environment_unbuildable`` is deliberately *not* reachable from here. It is a claim about
    the repository -- "preparation ran to completion and produced no usable environment" -- and
    a completed ``run_prepare`` makes that claim itself by returning ``status != "ready"``. An
    exception is not that claim: a preparation that crashed never reached a verdict on the
    repository, so recording one put the blame on a stage that had not finished being tried.
    """
    if any(isinstance(cause, UsageLimitExceeded)
           or _application_error_type(cause) == "UsageLimitExceeded"
           for cause in _failure_chain(e)):
        return InconclusiveReason.budget_exhausted
    if is_infrastructure_failure(e):
        return InconclusiveReason.infrastructure_error
    return InconclusiveReason.error


def failure_cause(exc: BaseException) -> BaseException:
    """The underlying failure; Temporal wraps a child/activity failure's cause."""
    return getattr(exc, "cause", None) or exc


def describe_failure(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"
