"""Controller-corroborated request observations, separated from behavior identity."""
from __future__ import annotations

from typing import Literal

from infosec_harness.inference.wire.protocol import (
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


class CompletedBrokerProvenance(TrustedBrokerProvenance):
    """The complete observation record that the worker stores in response metadata."""

    state: Literal["completed"]
    request_id: Sha256


def runtime_evidence(messages) -> list[dict]:
    records = []
    for message in messages:
        metadata = getattr(message, "metadata", None)
        value = metadata.get("harness_broker") if isinstance(metadata, dict) else None
        if value is None:
            continue
        try:
            records.append(CompletedBrokerProvenance.model_validate(value).model_dump(mode="json"))
        except ValueError:
            raise BrokerError("invalid_response", "Invalid broker provenance") from None
    return records
