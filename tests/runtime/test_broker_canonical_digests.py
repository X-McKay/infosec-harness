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


# Computed with the pre-consolidation sources (git HEAD 53a7663) before the shared field types,
# the ProviderAdaptation mixin and the backend-object contract resolution: every persisted
# contract and profile identity must survive that refactor unchanged.
CONTRACT_DIGESTS = {
    "plain": "b3e84f222b45e91b138500bb8ed3662f433dfd58277842c0de89d24c36bcb6d3",
    "strict": "dae3b19857e843807ca06d97712ca01cf79d2cadef8428d2feb84ed926583dff",
    "think": "d00c6a0e660ac9d6868826687abc2e8cdf7cebcd5785c7ea3c2e96620012b9cf",
    "nothink": "6b0eb45b3453f9ab01bab10513ecdda5b032792c77484a24b8395ae7d871a3a6",
    "intake": "a17e1a81a5c1119e410f0ff64e4e898aaaa7f3350094ebdbf9be4b8e456cfc43",
}
PROFILE_DIGESTS = {
    "plain": "bcbf9745a0f0b211cba9b4956763ac2cb8c770e7b057eed883b7a5b6e9816292",
    "thinking": "5d660bc65b87a548985fbd68dd0165750cafebbe58b8d98d03f955b8a8eadcba",
    "strict_bounded": "a12a78e9f390c226217404cf91631e11daa23aae3dd1148f16649ee146fb12f2",
}


def test_contract_and_profile_identities_are_unchanged_by_the_shared_field_vocabulary():
    from infosec_harness.inference.profiles import ExecutorProfile

    base = dict(backend="mock", model="m", profile="inference-only", profile_digest="a" * 64,
                endpoint="https://provider.test/v1/", provider_binding="p",
                executor_image="sha256:" + "b" * 64, supervisor_image="sha256:" + "c" * 64,
                policy_digest="d" * 64, model_settings={"max_tokens": 64})
    contracts = {"plain": {}, "strict": {"strict_closed_output_tools": True},
                 "think": {"enable_thinking": True, "thinking_token_budget": 8},
                 "nothink": {"enable_thinking": False},
                 "intake": {"atomic_intake": True, "min_max_tokens": 32}}
    assert {name: protocol.ExecutorContract(**base, **extra).digest
            for name, extra in contracts.items()} == CONTRACT_DIGESTS
    profile = dict(backend_name="gateway", endpoint="https://provider.example/v1",
                   provider_binding="provider-v1", provider_env="OPENAI_API_KEY",
                   ledger_origin="https://broker.example", ledger_profile="ledger-v1",
                   executor_image="sha256:" + "1" * 64, supervisor_image="sha256:" + "2" * 64,
                   approved_policy={"version": 1, "network_policies": {}})
    profiles = {"plain": {}, "thinking": {"enable_thinking": True, "thinking_token_budget": 4},
                "strict_bounded": {"strict_closed_output_tools": True,
                                   "max_input_tokens_per_request": 100}}
    assert {name: ExecutorProfile.model_validate({**profile, **extra}).profile_digest
            for name, extra in profiles.items()} == PROFILE_DIGESTS
