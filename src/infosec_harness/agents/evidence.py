"""Probe observation parsing and verdict feedback over tool-returned evidence."""

import json

from infosec_harness.contracts import PROBE_FIELDS, PROBE_PREREQUISITES, Evidence, Verdict

PROBE_PREFIX = "HARNESS_PROBE "
# The whole final line, prefix included.
MAX_PROBE_LINE_CHARS = 4096


def final_probe_line(stdout: str) -> str | None:
    """The final stdout line when it carries the HARNESS_PROBE prefix, parsed or not."""
    lines = stdout.rstrip("\r\n").splitlines()
    return lines[-1] if lines and lines[-1].startswith(PROBE_PREFIX) else None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("HARNESS_PROBE object repeats a field")
    return values


def parse_probe_observations(stdout: str) -> dict[str, bool | str]:
    """Parse the probe's self-reported claims; they never become an independent oracle.

    The final stdout line must be the prefix and one JSON object of at most
    ``MAX_PROBE_LINE_CHARS`` (whole line) with exactly the ``PROBE_FIELDS``, each a JSON
    boolean and none repeated. Anything else yields ``{}``.
    """
    line = final_probe_line(stdout)
    if line is None or len(line) > MAX_PROBE_LINE_CHARS:
        return {}
    try:
        values = json.loads(line[len(PROBE_PREFIX) :], object_pairs_hook=_unique_object)
    except ValueError:
        return {}
    if (
        not isinstance(values, dict)
        or set(values) != set(PROBE_FIELDS)
        or any(type(value) is not bool for value in values.values())
    ):
        return {}
    return {**values, "origin": "self_reported"}


def retry_reasons(verdict: Verdict, evidence: list[Evidence]) -> list[str]:
    """Name every deficiency of the cited evidence; one format problem must not mask another."""
    expected = verdict.label == "potentially_exploitable"
    reasons = [] if verdict.citations else ["No source citations"]
    probes = [item for item in evidence if item.id in verdict.evidence_ids and item.kind == "probe"]
    if not probes:
        reasons.append(
            "No run_probe evidence cited; workspace execute ids cannot support a definitive verdict"
        )
    for item in probes:
        observed = item.observations
        if item.exit_code != 0:
            reasons.append(f"{item.id} is not a complete probe: exit code {item.exit_code}")
        elif item.output_truncated:
            reasons.append(f"{item.id} is not a complete probe: output was truncated")
        if observed.get("source_verified") is not True:
            reasons.append(f"{item.id} is not source-verified (see its integrity_feedback)")
        if "vulnerability_observed" not in observed:
            if observed.get("probe_line_rejected") is True:
                reasons.append(
                    f"{item.id} printed a final HARNESS_PROBE line that did not parse: after the "
                    "prefix it must be one JSON object of exactly the five fields "
                    + ", ".join(PROBE_FIELDS)
                    + ", each the JSON boolean true or false (numbers such as 1/0, strings, "
                    "null, duplicate or extra fields are rejected; the whole line is at most "
                    f"{MAX_PROBE_LINE_CHARS} characters)"
                )
            else:
                reasons.append(
                    f"{item.id} has no parsed HARNESS_PROBE line: the prefix and exactly the five "
                    "boolean JSON fields must share the final stdout line"
                )
            continue
        for field in PROBE_PREREQUISITES:
            if observed.get(field) is not True:
                note = (
                    "; target_reached is true when the real target entry point ran with the "
                    "finding's input, even if its guard rejected it"
                    if field == "target_reached"
                    else ""
                )
                reasons.append(f"{item.id} reports {field}=false{note}")
        if item.complete_verified_probe and observed["vulnerability_observed"] is not expected:
            reasons.append(
                f"{item.id} reports vulnerability_observed={observed['vulnerability_observed']}, "
                f"which does not match {verdict.label}"
            )
    return reasons
