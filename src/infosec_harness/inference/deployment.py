"""Concrete opt-in controller factory and secret-free contract inventory.

Native admin configuration is operator-owned and is never accepted over the wire.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import yaml

from infosec_harness.inference.admission import ReservationPolicy
from infosec_harness.inference.controller import Controller
from infosec_harness.inference.http_service import JsonChannel
from infosec_harness.inference.invocations import (
    build_reservation_policy,
    issue_invocation,
    trusted_config,
)
from infosec_harness.inference.openshell import NativeDeploymentConfig
from infosec_harness.inference.policy import canonical_policy
from infosec_harness.inference.profiles import REGISTERED_AGENTS
from infosec_harness.inference.protocol import BrokerError, InvocationRequest


def contracts(*, durable: bool = True):
    return {name: trusted_config(name, durable=durable) for name in REGISTERED_AGENTS}


def controller_factory() -> Controller:
    from infosec_harness.agents import models
    path = Path(os.environ.get("HARNESS_BROKER_NATIVE_CONFIG", ""))
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise BrokerError("policy", "A native operator deployment file is required")
    try:
        native = NativeDeploymentConfig.model_validate(yaml.safe_load(path.read_text()))
    except (ValueError, OSError, yaml.YAMLError):
        raise BrokerError("policy", "Native deployment configuration is invalid") from None
    catalog = models.broker_catalog()
    key = os.environ.get(catalog.controller.hmac_env or "", "").encode()
    adapter = native.build()
    policies: dict[tuple[str, str], ReservationPolicy] = {}
    for name, config in contracts().items():
        contract = config.model.broker_contract
        if contract is None:
            continue
        reference = InvocationRequest(mode="temporal", root_id="catalog", run_id="catalog",
            invocation_id="catalog", operation_id="catalog", agent=name,
            configuration_digest=config.digest, contract=contract)
        policy = build_reservation_policy(reference)
        spec = adapter.spec(contract)
        profile = catalog.profiles[contract.profile]
        if (canonical_policy(spec.approved_policy) != canonical_policy(profile.approved_policy)
                or spec.ledger_origin != profile.ledger_origin
                or spec.ledger_profile != profile.ledger_profile
                or spec.provider_env != profile.provider_env
                or spec.max_input_tokens < policy.max_input_tokens
                or spec.max_output_tokens < policy.max_output_tokens):
            raise BrokerError("policy", "Native deployment differs from approved access catalog")
        policies[(name, contract.digest)] = policy
    if not policies:
        raise BrokerError("policy", "No brokered models were explicitly selected")
    return Controller(adapter=adapter, policies=policies, worker_key=key,
        issue_invocation=issue_invocation,
        executor_channel=JsonChannel(gateway_origin=native.gateway, service_domain=native.service_domain,
            ca_file=str(native.gateway_ca),
            cert=(str(native.gateway_client_certificate), str(native.gateway_client_key))))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-contracts", action="store_true", required=True)
    args = parser.parse_args()
    if args.print_contracts:
        values = {}
        for name, config in contracts().items():
            contract = config.model.broker_contract
            values[name] = {"configuration_digest": config.digest,
                "transport": "brokered" if contract else "direct",
                "contract_digest": contract.digest if contract else None,
                "contract": contract.model_dump(mode="json") if contract else None}
        print(json.dumps(values, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
