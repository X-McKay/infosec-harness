"""The controller's execution record for one probe run, kept beside the run's output.

The record separates what the controller observed from what the probe claims, by origin:

- ``process`` (origin ``controller``): exit code, timeout and duration, observed by the
  harness's own process runner.
- ``observations`` (origin ``self_reported_marker``): precondition reached, sink returned and
  oracle fired, read from marker text the probe printed. Self-reported, so never upgraded into
  controller evidence.
- ``runner`` (origin ``parsed_untrusted_output``): the runner's own zero-test phrase, or None
  when its output contained none (``output.no_tests_executed``).

Each section is a mapping that carries its ``origin``; that is the exported shape.
"""

from __future__ import annotations

from typing import Any

from infosec_harness.domain.canonical import canonical_bytes, sha256_hex

EXECUTION_RECORD_PREFIX = "HARNESS_EXECUTION_RECORD::"
# v2: the runner section no longer carries discovered/executed counts that were always None,
# and its origin no longer varies with whether a zero-test phrase was found.
EXECUTION_PROTOCOL = "unit-probe-execution/v2"
PROCESS_ORIGIN = "controller"
OBSERVATIONS_ORIGIN = "self_reported_marker"
RUNNER_ORIGIN = "parsed_untrusted_output"


def execution_record(*, image_tag: str, test_file_path: str, test_command: str, content: str,
                     nonce: str, attempt: int, exit_code: int | None, timed_out: bool,
                     duration_s: float, oracle_fired: bool, precondition_reached: bool,
                     sink_returned: bool, no_tests: str | None) -> dict[str, Any]:
    """Build the controller's record without upgrading marker text into trusted evidence."""
    identity = "\0".join((image_tag, test_file_path, nonce, str(attempt)))
    return {
        "version": EXECUTION_PROTOCOL,
        "execution_id": sha256_hex(identity)[:24],
        "attempt": attempt,
        "probe_digest": sha256_hex(content),
        "test_file_path": test_file_path,
        "test_command": test_command,
        "process": {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_s": duration_s,
            "origin": PROCESS_ORIGIN,
        },
        "observations": {
            "precondition_reached": precondition_reached,
            "sink_returned": sink_returned,
            "oracle_fired": oracle_fired,
            "origin": OBSERVATIONS_ORIGIN,
        },
        "runner": {
            "zero_test_signal": no_tests,
            "origin": RUNNER_ORIGIN,
        },
    }


def encode_execution_record(record: dict[str, Any]) -> str:
    return EXECUTION_RECORD_PREFIX + canonical_bytes(record).decode()
