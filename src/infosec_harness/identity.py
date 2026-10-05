"""Content identity of the trusted worker and its explicit isolation configuration."""

import hashlib
import json
from importlib.metadata import version
from pathlib import Path

from .models import WorkerIdentity


def worker_identity(settings) -> WorkerIdentity:
    root = Path(__file__).parent
    source = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yaml", ".md"}:
            data = path.read_bytes()
            source.update(path.relative_to(root).as_posix().encode() + b"\0")
            source.update(len(data).to_bytes(8, "big") + data)
    dependencies = {
        name: version(name)
        for name in ("infosec-harness", "pydantic-ai-slim", "pydantic", "temporalio", "openshell")
    }
    raw = settings.openshell_config.read_bytes()
    runtime = json.loads(raw)
    # Paths alone do not identify the policy that the gateway will enforce.
    policies = {
        name: hashlib.sha256(Path(profile["policy"]).read_bytes()).hexdigest()
        for name, profile in runtime.get("profiles", {}).items()
    }
    configuration = settings.model_dump(
        mode="json",
        exclude={
            "temporal_api_key",
            "temporal_api_key_file",
            "temporal_tls_client_key",
            "temporal_tls_client_cert",
            "temporal_tls_ca_file",
            "openshell_config",
        },
    )
    encoded = json.dumps(
        {
            "settings": configuration,
            "openshell_sha256": hashlib.sha256(raw).hexdigest(),
            "policy_sha256": policies,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    fields = {
        "code_sha256": source.hexdigest(),
        "config_sha256": hashlib.sha256(encoded).hexdigest(),
        "dependencies": dependencies,
    }
    fingerprint = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()
    return WorkerIdentity(fingerprint=fingerprint, **fields)
