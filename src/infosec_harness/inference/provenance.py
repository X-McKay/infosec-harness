"""Controller-corroborated request observations, separated from behavior identity."""
from __future__ import annotations

from infosec_harness.inference.protocol import (
    BrokerError,
    ImageDigest,
    LogicalName,
    NativeName,
    Sha256,
    StrictModel,
)


class TrustedBrokerProvenance(StrictModel):
    """Exactly the native observations the controller attaches after verifying its lease."""

    native_id: NativeName
    policy_digest: Sha256
    executor_image: ImageDigest
    supervisor_image: ImageDigest
    profile: LogicalName
    credential_revision: NativeName
    contract_digest: Sha256
    lease_id: NativeName


# The worker adds the request disposition to the corroborated observations.
_ALLOWED = frozenset(TrustedBrokerProvenance.model_fields) | {"state", "request_id"}


def runtime_evidence(messages) -> list[dict]:
    records = []
    for message in messages:
        metadata = getattr(message, "metadata", None)
        value = metadata.get("harness_broker") if isinstance(metadata, dict) else None
        if value is None:
            continue
        if not isinstance(value, dict) or set(value) - _ALLOWED:
            raise BrokerError("invalid_response", "Unexpected broker provenance fields")
        if any(not isinstance(v, (str, int)) for v in value.values()):
            raise BrokerError("invalid_response", "Invalid broker provenance")
        records.append(dict(value))
    return records
