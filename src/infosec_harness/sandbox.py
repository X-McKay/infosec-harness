"""No-exec sandbox admission. This release never executes target-controlled code."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityReport:
    admitted: bool
    backend: str
    reason: str
    network_observer: str


class NoExecSandbox:
    name = "no-exec-controller-tools"

    def self_test(self) -> CapabilityReport:
        # The normal path never forks a worker, mounts a repository, or runs target code.
        return CapabilityReport(True, self.name, "target execution is refused; reads stay in controller", "not required")

    def execute(self, *_: object) -> None:
        raise PermissionError("target-code execution is outside this release's no-exec policy")


def network_self_test() -> CapabilityReport:
    # There is no independent host-side collector in this local implementation. A networked
    # worker is therefore not admitted, while controller-side replay remains safe and useful.
    return CapabilityReport(
        False,
        "network-capability",
        "independent host-side network observer unavailable; networked workers are prohibited",
        "observer_unavailable",
    )
