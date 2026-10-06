"""Probe observation parsing and verdict feedback over tool-returned evidence."""

import json

from infosec_harness.contracts import PROBE_FIELDS, PROBE_PREREQUISITES, Evidence, Verdict


def final_probe_line(stdout: str) -> str | None:
    """The final stdout line when it carries the HARNESS_PROBE prefix, parsed or not."""
    lines = stdout.rstrip("\r\n").splitlines()
    return lines[-1] if lines and lines[-1].startswith("HARNESS_PROBE ") else None


def parse_probe_observations(stdout: str) -> dict[str, bool | str]:
    """Parse declared claims, never elevate probe-authored text into an independent oracle."""
    line = final_probe_line(stdout)
    if line is None or len(line) > 4096:
        return {}
    try:
        pairs = json.loads(line[len("HARNESS_PROBE ") :], object_pairs_hook=lambda value: value)
        if not isinstance(pairs, list) or len(pairs) != len(PROBE_FIELDS):
            return {}
        values = dict(pairs)
        if set(values) != set(PROBE_FIELDS) or any(
            type(value) is not bool for value in values.values()
        ):
            return {}
        return {**values, "origin": "self_reported"}
    except (ValueError, TypeError):
        return {}


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
                    "null, duplicate or extra fields are rejected; at most 4096 characters)"
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
