"""Controller-corroborated request observations, separated from behavior identity."""
from infosec_harness.inference.protocol import BrokerError

_ALLOWED = {"native_id", "policy_digest", "executor_image", "supervisor_image", "profile",
            "credential_revision", "contract_digest", "lease_id", "request_id", "disposition",
            "openshell_version", "protocol", "provider_retries", "state"}


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
