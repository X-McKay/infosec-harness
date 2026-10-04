"""CLI for the shared, read-only qualification assessor."""

from infosec_harness.qualification.ledger import (
    EvidenceUnavailable,
    InventoryUnavailable,
    artifact,
    assess,
    dependencies,
    digest,
    is_hash,
    main,
    require,
)

__all__ = [
    "EvidenceUnavailable",
    "InventoryUnavailable",
    "artifact",
    "assess",
    "dependencies",
    "digest",
    "is_hash",
    "main",
    "require",
]

if __name__ == "__main__":
    main()
