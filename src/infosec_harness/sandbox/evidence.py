"""Controller-authored execution records for the legacy marker probe adapter."""

from __future__ import annotations

from typing import Any

from infosec_harness.domain.canonical import canonical_bytes, sha256_hex

EXECUTION_RECORD_PREFIX = "HARNESS_EXECUTION_RECORD::"
EXECUTION_PROTOCOL = "unit-probe-execution/v1"


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
            "origin": "controller",
        },
        "observations": {
            "precondition_reached": precondition_reached,
            "sink_returned": sink_returned,
            "oracle_fired": oracle_fired,
            "origin": "self_reported_marker",
        },
        "runner": {
            "discovered_count": None,
            "executed_count": None,
            "zero_test_signal": no_tests,
            "origin": "parsed_untrusted_output" if no_tests else "not_available",
        },
    }


def encode_execution_record(record: dict[str, Any]) -> str:
    return EXECUTION_RECORD_PREFIX + canonical_bytes(record).decode()
