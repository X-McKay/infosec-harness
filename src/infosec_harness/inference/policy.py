"""Native effective-policy identity, preserving every permission and default.

OpenShell generates provider-composed map labels from ephemeral resource names.
Those labels are redundant presentation identifiers; attachment/profile/resource identity
is verified independently. Authored labels and all rule content retain their exact shape.
"""
from copy import deepcopy

from infosec_harness.inference.protocol import BrokerError, canonical_bytes, digest


def canonical_policy(policy: dict) -> dict:
    value = deepcopy(policy)
    policies = value.get("network_policies")
    if not isinstance(policies, dict):
        raise BrokerError("policy", "Effective network policy map is required")
    authored = {}
    composed = []
    for name, rule in policies.items():
        if not isinstance(name, str) or not isinstance(rule, dict):
            raise BrokerError("policy", "Invalid effective network policy entry")
        if name.startswith("_provider_"):
            if rule.get("name") != name:
                raise BrokerError("policy", "Generated provider policy identity is inconsistent")
            composed.append({key: item for key, item in rule.items() if key != "name"})
        else:
            authored[name] = rule
    value["network_policies"] = {"authored": authored,
        "provider_composed": sorted(composed, key=canonical_bytes)}
    return value


def policy_digest(policy: dict) -> str:
    return digest(canonical_policy(policy))
