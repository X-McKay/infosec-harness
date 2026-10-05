"""Stored digests keep their exact historical encodings after canonical-helper consolidation.

The expected literals were computed with the pre-consolidation implementations
(``inference.protocol.digest`` and ``persistence.reconciliation._sha``), so an encoding
change that would orphan persisted ledger identities or closure markers fails here.
"""
from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from infosec_harness.domain.canonical import canonical_bytes, digest, is_sha256
from infosec_harness.inference import protocol
from infosec_harness.persistence import reconciliation

VALUE = {"b": [1, 2.5, None, True], "a": "é <x>", "z": {"y": "ü"}}
# hashlib.sha256(json.dumps(VALUE, sort_keys=True, separators=(",", ":"),
#                ensure_ascii=False, allow_nan=False).encode()).hexdigest()
WIRE_DIGEST = "ad072ab571b0845615c6d1bb0fdbbb9693847917c034c1844147fa9862a99da9"
# The former reconciliation._sha: UTC-normalized datetimes, ensure_ascii=True.
RECONCILIATION_DIGEST = "58285f190db8e3015b18ddc7a9e4f726d11664fbfe5958e6fb484f5c7e75dfdd"


def test_wire_and_ledger_identities_keep_their_encoding():
    assert digest(VALUE) == protocol.digest(VALUE) == WIRE_DIGEST
    assert protocol.canonical_bytes is canonical_bytes


def test_reconciliation_markers_keep_their_frozen_encoding():
    value = {**VALUE, "when": datetime(2026, 10, 4, 12, 0, tzinfo=timezone(timedelta(hours=2))),
             "naive": datetime(2026, 1, 1)}
    assert reconciliation.reconciliation_digest(value) == RECONCILIATION_DIGEST
    assert reconciliation.reconciliation_digest(VALUE) != WIRE_DIGEST  # Different, by design.


def test_canonical_bytes_rejects_non_finite_numbers():
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("nan")})


@pytest.mark.parametrize("value,expected", [
    ("a" * 64, True), ("0123456789abcdef" * 4, True), ("A" * 64, False), ("a" * 63, False),
    ("a" * 64 + "\n", False), ("g" * 64, False), (b"a" * 64, False), (None, False),
])
def test_is_sha256_is_exact(value, expected):
    assert is_sha256(value) is expected


def test_canonical_module_stays_inside_the_executor_closure():
    """The isolated executor image copies only stdlib-importing modules besides its own set."""
    source = Path(__file__).parents[2] / "src/infosec_harness/domain/canonical.py"
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [ast.alias(node.module or "")])
    }
    assert imported <= {"__future__", "hashlib", "json", "re", "typing"}


def test_executor_image_context_contains_every_imported_harness_module():
    """deploy/openshell/build_context.py copies a fixed module list into the executor image."""
    root = Path(__file__).parents[2]
    context = (root / "deploy/openshell/build_context.py").read_text()
    pending = ["infosec_harness.inference.executor"]
    seen: set[str] = set()
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        seen.add(module)
        path = root / "src" / (module.replace(".", "/") + ".py")
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.level:
                base = module.rsplit(".", node.level)[0]
                pending.append(f"{base}.{node.module}" if node.module else base)
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("infosec_harness."):
                pending.append(node.module)
    for module in sorted(seen):
        relative = module.removeprefix("infosec_harness.").replace(".", "/") + ".py"
        name = relative.rsplit("/", 1)[-1].removesuffix(".py")
        assert f'"{name}"' in context or relative in context, (
            f"{module} is imported by the executor but not copied into its image context")
