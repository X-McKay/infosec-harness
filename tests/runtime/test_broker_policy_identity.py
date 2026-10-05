from copy import deepcopy

import pytest

from infosec_harness.inference.catalog.policy import policy_digest
from infosec_harness.inference.wire.protocol import BrokerError


def policy():
    return {
        "network_policies": {
            "_provider_lease_a": {
                "name": "_provider_lease_a",
                "endpoints": [
                    {
                        "host": "provider.test",
                        "port": 443,
                        "rules": [{"method": "POST", "path": "/v1/chat/completions"}],
                        "tls": "terminate",
                    }
                ],
                "binaries": ["/usr/local/bin/python3.12"],
            },
            "ledger": {
                "name": "ledger",
                "endpoints": [
                    {
                        "host": "controller.test",
                        "port": 443,
                        "rules": [{"method": "POST", "path": "/v1/ledger/claim"}],
                    }
                ],
            },
        },
        "landlock": {"compatibility": "hard_requirement"},
        "filesystem": {"read_only": ["/opt"]},
    }


def test_only_redundant_generated_labels_are_ignored():
    first = policy()
    second = deepcopy(first)
    second["network_policies"]["_provider_lease_b"] = second["network_policies"].pop(
        "_provider_lease_a"
    )
    second["network_policies"]["_provider_lease_b"]["name"] = "_provider_lease_b"
    assert policy_digest(first) == policy_digest(second)
    second["network_policies"]["ledger"]["name"] = "another-authored-name"
    assert policy_digest(first) != policy_digest(second)


@pytest.mark.parametrize(
    "mutation", ["host", "method", "extra", "duplicates", "filesystem", "landlock"]
)
def test_permission_changes_never_disappear(mutation):
    first = policy()
    second = deepcopy(first)
    rule = second["network_policies"]["_provider_lease_a"]
    if mutation == "host":
        rule["endpoints"][0]["host"] = "metadata.test"
    elif mutation == "method":
        rule["endpoints"][0]["rules"][0]["method"] = "*"
    elif mutation == "extra":
        rule["endpoints"].append({"host": "evil.test", "port": 443})
    elif mutation == "duplicates":
        second["network_policies"]["_provider_other"] = deepcopy(rule)
        second["network_policies"]["_provider_other"]["name"] = "_provider_other"
    elif mutation == "filesystem":
        second["filesystem"]["read_write"] = ["/"]
    else:
        second["landlock"]["compatibility"] = "best_effort"
    assert policy_digest(first) != policy_digest(second)


def test_inconsistent_generated_name_is_rejected():
    value = policy()
    value["network_policies"]["_provider_lease_a"]["name"] = "authored"
    with pytest.raises(BrokerError):
        policy_digest(value)
