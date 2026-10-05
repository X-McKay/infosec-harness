"""The activity timeout and retry vocabularies every workflow schedules with.

Temporal's default retry policy is *unlimited* attempts. A deterministic programming error in an
activity (a bad signature, a validation failure, a record that was never accepted) would then
retry forever and the workflow would hang rather than fail, silently holding a worker slot. So
every policy bounds its attempts or names the error classes that cannot succeed on a retry.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

NON_RETRYABLE = ["TypeError", "ValueError", "AttributeError", "KeyError", "ValidationError",
                 "UsageLimitExceeded", "MissingDurableRecord", "MissingLedger"]

RETRY = RetryPolicy(maximum_attempts=3, non_retryable_error_types=NON_RETRYABLE)

# Short deterministic activities: discovery, location, recipes, progress, broker issuance.
SHORT = dict(start_to_close_timeout=timedelta(minutes=5), retry_policy=RETRY)

# Root-ledger reservation and settlement.
LEDGER = dict(start_to_close_timeout=timedelta(seconds=30), retry_policy=RETRY)

# Terminal writes retry transient failures until durable: a result that is never persisted is a
# lost assessment. A deterministic failure still fails, rather than retrying forever.
TERMINAL = dict(start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(maximum_attempts=0, maximum_interval=timedelta(seconds=30),
                                         non_retryable_error_types=NON_RETRYABLE))

# Long workloads heartbeat so cancellation reaches them and their cleanup completes.
HEARTBEAT = dict(heartbeat_timeout=timedelta(seconds=30),
                 cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED)

CHECKOUT = {**SHORT, **HEARTBEAT}
