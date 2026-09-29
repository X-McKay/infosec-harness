"""Controller-authored execution records for the legacy marker probe adapter."""

from __future__ import annotations

import hashlib
import json
from typing import Any

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
        "execution_id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "attempt": attempt,
        "probe_digest": hashlib.sha256(content.encode()).hexdigest(),
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
    return EXECUTION_RECORD_PREFIX + json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_execution_record(text: str) -> dict[str, Any] | None:
    for line in reversed((text or "").splitlines()):
        if not line.startswith(EXECUTION_RECORD_PREFIX):
            continue
        try:
            value = json.loads(line.removeprefix(EXECUTION_RECORD_PREFIX))
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) and value.get("version") == EXECUTION_PROTOCOL else None
    return None
