from __future__ import annotations

from copy import deepcopy

import pytest
import yaml

from infosec_harness.inference.catalog.profiles import (
    BrokerConfig,
    ExecutorProfile,
    InvocationBounds,
    load_broker_config,
)
from infosec_harness.inference.models import BackendConfig
from infosec_harness.resources import package_root
from infosec_harness.runtime.registry import BINDINGS

AGENTS = tuple(BINDINGS)


def backend(endpoint: str = "https://provider.example/v1", **adaptations) -> BackendConfig:
    """The operator backend a contract is resolved against."""
    return BackendConfig(kind="openai_compatible", transport="brokered", base_url=endpoint,
                         **adaptations)


def _bounds() -> dict:
    return {
        "max_requests": 5,
        "max_input_tokens": 50000,
        "max_output_tokens": 10000,
        "max_cost_usd": 0.5,
        "max_duration_seconds": 600.0,
    }


def _profile(**overrides) -> dict:
    value = {
        "backend_name": "gateway",
        "endpoint": "https://provider.example/v1",
        "provider_binding": "provider-v1",
        "provider_env": "OPENAI_API_KEY",
        "ledger_origin": "https://broker.example",
        "ledger_profile": "ledger-v1",
        "executor_image": "sha256:" + "1" * 64,
        "supervisor_image": "sha256:" + "2" * 64,
        "approved_policy": {"version": 1, "network_policies": {}},
    }
    value.update(overrides)
    return value


def _config(**overrides) -> dict:
    names = list(AGENTS)
    value = {
        "version": 1,
        "enabled": True,
        "controller": {
            "url": "https://broker.example",
            "hmac_env": "HARNESS_BROKER_HMAC_KEY",
            "ca_file": "/etc/harness/broker-ca.pem",
        },
        "profiles": {"inference-only": _profile()},
        "agent_profiles": {agent: "inference-only" for agent in names},
        "root_limits": _bounds(),
        "agent_limits": {agent: _bounds() for agent in names},
    }
    value.update(overrides)
    return value


def test_packaged_catalog_is_disabled_and_maps_every_agent() -> None:
    catalog = load_broker_config(agents=AGENTS)
    assert catalog.enabled is False
    assert set(catalog.agent_profiles) == set(AGENTS)
    assert set(catalog.agent_limits) == set(AGENTS)
    assert set(catalog.agent_profiles.values()) == {"inference-only"}
    assert catalog.profiles["inference-only"].endpoint is None
    assert catalog.profiles["inference-only"].approved_policy is None


def test_resolve_contract_uses_fixed_profile_and_exact_effective_settings() -> None:
    catalog = BrokerConfig.model_validate(_config())
    for agent in AGENTS:
        contract = catalog.resolve_contract(
            agent,
            "gateway",
            "model-v1",
            {"max_tokens": 2048, "temperature": 0.2},
            backend=backend(),
            atomic_intake=agent == "intake",
        )
        assert contract.endpoint == "https://provider.example/v1"
        assert contract.provider_retries == 0
        assert contract.credential_driver == "native"
        assert contract.inspection == ()
        assert contract.model_settings == {"max_tokens": 2048, "temperature": 0.2}
        assert contract.atomic_intake == (agent == "intake")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["agent_profiles"].pop("verdict"),
        lambda value: value["agent_profiles"].update({"surprise": "inference-only"}),
        lambda value: value["agent_limits"].pop("recon"),
        lambda value: value["agent_limits"].update({"surprise": _bounds()}),
        lambda value: value["profiles"]["inference-only"].update(
            {"endpoint": "https://provider.example/v1?key=secret"}
        ),
        lambda value: value["profiles"]["inference-only"].update({"headers": {"X-Any": "x"}}),
        lambda value: value["profiles"]["inference-only"].update({"remote_content": True}),
        lambda value: value["profiles"]["inference-only"].update({"credential_driver": "custom"}),
        lambda value: value["profiles"]["inference-only"].update(
            {"inspection": [{"implementation": "inspect", "version": "1", "required": True}]}
        ),
    ],
)
def test_catalog_rejects_incomplete_unknown_or_unsupported_configuration(mutation) -> None:
    value = deepcopy(_config())
    mutation(value)
    with pytest.raises(ValueError):
        BrokerConfig.model_validate(value)


def test_catalog_rejects_bounds_above_root_and_literal_secret_fields() -> None:
    value = _config()
    value["agent_limits"]["intake"]["max_cost_usd"] = 2.0
    with pytest.raises(ValueError):
        BrokerConfig.model_validate(value)

    value = _config()
    value["controller"]["hmac_key"] = "literal-secret"
    with pytest.raises(ValueError):
        BrokerConfig.model_validate(value)


def test_contract_resolution_rejects_endpoint_adaptation_and_output_limit_drift() -> None:
    catalog = BrokerConfig.model_validate(_config())
    common = ("intake", "gateway", "model-v1", {"max_tokens": 2048})
    with pytest.raises(ValueError):
        catalog.resolve_contract(
            *common, backend=backend("https://other.example/v1"), atomic_intake=True
        )
    with pytest.raises(ValueError):
        catalog.resolve_contract(*common, backend=backend(), atomic_intake=False)
    with pytest.raises(ValueError):
        catalog.resolve_contract(
            *common, backend=backend(merge_system_messages=False), atomic_intake=True
        )
    with pytest.raises(ValueError):
        catalog.resolve_contract(*common, backend=backend(min_max_tokens=16), atomic_intake=True)
    with pytest.raises(ValueError):
        catalog.resolve_contract(
            "recon",
            "gateway",
            "model-v1",
            {"max_tokens": 10001},
            backend=backend(),
        )


def test_generated_provider_label_rotation_keeps_contract_identity_but_permissions_do_not() -> None:
    policy_a = {
        "version": 1,
        "network_policies": {
            "_provider_lease-111": {
                "name": "_provider_lease-111",
                "allowed_ips": ["198.51.100.7/32"],
                "methods": ["POST"],
                "path": "/v1/chat/completions",
                "tls": {"terminate": True},
            }
        },
    }
    policy_b = {
        "version": 1,
        "network_policies": {
            "_provider_lease-222": {
                "name": "_provider_lease-222",
                "allowed_ips": ["198.51.100.7/32"],
                "methods": ["POST"],
                "path": "/v1/chat/completions",
                "tls": {"terminate": True},
            }
        },
    }
    first = ExecutorProfile.model_validate(_profile(approved_policy=policy_a))
    rotated = ExecutorProfile.model_validate(_profile(approved_policy=policy_b))
    assert first.policy_digest == rotated.policy_digest
    assert first.profile_digest == rotated.profile_digest

    def contract_for(policy: dict):
        catalog = BrokerConfig.model_validate(
            _config(profiles={"inference-only": _profile(approved_policy=policy)})
        )
        return catalog.resolve_contract(
            "recon", "gateway", "model-v1", {"max_tokens": 2048}, backend=backend()
        )

    assert contract_for(policy_a).digest == contract_for(policy_b).digest

    restricted_policy = {
        **policy_b,
        "network_policies": {
            "_provider_lease-333": {
                **policy_b["network_policies"]["_provider_lease-222"],
                "name": "_provider_lease-333",
                "allowed_ips": ["198.51.100.8/32"],
            }
        },
    }
    restricted = ExecutorProfile.model_validate(_profile(approved_policy=restricted_policy))
    assert restricted.policy_digest != rotated.policy_digest
    assert restricted.profile_digest != rotated.profile_digest
    assert contract_for(restricted_policy).digest != contract_for(policy_b).digest


def test_controller_accepts_only_operator_https_references_and_tls_pair() -> None:
    for bad in (
        "http://broker.example",
        "https://user:pass@broker.example",
        "https://broker.example/path",
        "https://broker.example?x=1",
    ):
        value = _config()
        value["controller"]["url"] = bad
        with pytest.raises(ValueError):
            BrokerConfig.model_validate(value)

    value = _config()
    value["controller"]["client_cert"] = "/etc/harness/client.pem"
    with pytest.raises(ValueError):
        BrokerConfig.model_validate(value)


def test_operator_yaml_is_strict_and_secret_free() -> None:
    raw = yaml.safe_load(
        (package_root() / "config" / "credential-broker.yaml").read_text(encoding="utf-8")
    )
    assert "hmac_env" in raw["controller"]
    assert "hmac_key" not in raw["controller"]
    assert isinstance(InvocationBounds.model_validate(_bounds()), InvocationBounds)


@pytest.mark.parametrize(
    "inspection", [[], [{"implementation": "inspect", "version": "1", "required": True}]]
)
def test_operator_yaml_loads_tuple_shape_then_rejects_required_inspection(
    tmp_path, inspection
) -> None:
    value = _config()
    value["profiles"]["inference-only"]["inspection"] = inspection
    path = tmp_path / "broker.yaml"
    path.write_text(yaml.safe_dump(value), encoding="utf-8")

    if inspection:
        with pytest.raises(ValueError, match="invalid"):
            load_broker_config(path, agents=AGENTS)
    else:
        assert load_broker_config(path, agents=AGENTS).profiles["inference-only"].inspection == ()


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_catalog_must_cover_exactly_the_registered_agents(tmp_path, change) -> None:
    """An internally consistent catalog still fails if it differs from the registry."""
    value = _config()
    for mapping in (value["agent_profiles"], value["agent_limits"]):
        if change == "missing":
            del mapping["verdict"]
        else:
            mapping["surprise"] = deepcopy(mapping["recon"])
    BrokerConfig.model_validate(value)  # Consistent on its own.
    path = tmp_path / "broker.yaml"
    path.write_text(yaml.safe_dump(value), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        load_broker_config(path, agents=AGENTS)


@pytest.mark.parametrize("value", [[{}], (None,), ["inspection"], {"implementation": "inspect"}])
def test_inspection_is_exactly_empty_in_contract_and_profile(value):
    from infosec_harness.inference.catalog.profiles import ExecutorProfile
    from infosec_harness.inference.wire.protocol import ExecutorContract

    catalog = BrokerConfig.model_validate(_config())
    contract = catalog.resolve_contract("recon", "gateway", "model-v1", {"max_tokens": 2048},
                                        backend=backend())
    for cls, fields in ((ExecutorProfile, {}),
                        (ExecutorContract, contract.model_dump(mode="python"))):
        with pytest.raises(ValueError):
            cls.model_validate({**fields, "inspection": value})
        schema = cls.model_json_schema()["properties"]["inspection"]
        assert schema["type"] == "array" and schema["maxItems"] == schema["minItems"] == 0
    assert ExecutorContract.model_validate_json(contract.model_dump_json()).digest == contract.digest
