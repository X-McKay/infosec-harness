"""Preservation-oriented SARIF 2.1 importer with stable finding IDs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .domain import Finding, Location
from .policy import digest
from .stores import ArtifactStore


class SarifError(ValueError):
    pass


def _locations(items: list[dict[str, Any]]) -> list[Location]:
    result: list[Location] = []
    for item in items:
        physical = item.get("physicalLocation", item.get("location", {}).get("physicalLocation", {}))
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})
        uri, start = artifact.get("uri"), region.get("startLine")
        if isinstance(uri, str) and isinstance(start, int):
            result.append(Location(path=uri, start_line=start, end_line=region.get("endLine", start)))
    return result


def import_sarif(path: Path, artifacts: ArtifactStore) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        payload = json.loads(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise SarifError(f"invalid SARIF: {exc}") from exc
    if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list):
        raise SarifError("expected SARIF 2.1.0 with runs")
    full_sarif_artifact = artifacts.put_text(source)
    imported: list[Finding] = []
    for run_index, run in enumerate(payload["runs"]):
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            raise SarifError("SARIF run lacks tool.driver.name")
        revision = next(
            (item.get("revisionId") for item in run.get("versionControlProvenance", []) if item.get("revisionId")), None
        )
        scanner = {
            "name": driver["name"],
            "version": driver.get("version"),
            "rules": driver.get("rules", []),
            "invocations": run.get("invocations", []),
            "automation_details": run.get("automationDetails", {}),
            "full_sarif_artifact": full_sarif_artifact,
        }
        for result in run.get("results", []):
            locations = _locations(result.get("locations", []))
            if not locations:
                raise SarifError("SARIF result lacks a physical location")
            flow_locations: list[Location] = []
            for flow in result.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    flow_locations.extend(_locations(thread.get("locations", [])))
            raw_hash = artifacts.put_json({"run": run_index, "result": result, "scanner": scanner})
            fingerprints = {str(key): str(value) for key, value in result.get("partialFingerprints", {}).items()}
            stable = fingerprints.get("primaryLocationLineHash") or digest(
                f"{scanner['name']}|{result.get('ruleId')}|{locations[0].path}|{locations[0].start_line}"
            )
            imported.append(
                Finding(
                    finding_id=f"finding-{digest(stable)[7:23]}",
                    rule_id=result.get("ruleId", "unknown"),
                    level=result.get("level", "none"),
                    message=result.get("message", {}).get("text", ""),
                    locations=locations,
                    code_flow=flow_locations,
                    fingerprints=fingerprints,
                    suppressions=result.get("suppressions", []),
                    scanner=scanner,
                    revision=revision,
                    raw_artifact=raw_hash,
                )
            )
    # Keep every occurrence as an immutable artifact, while investigation uses one stable representative.
    deduplicated: dict[str, Finding] = {}
    for finding in imported:
        if existing := deduplicated.get(finding.finding_id):
            existing.occurrence_count += 1
            existing.occurrence_artifacts.append(finding.raw_artifact)
            existing.suppressions.extend(finding.suppressions)
            continue
        finding.occurrence_artifacts.append(finding.raw_artifact)
        deduplicated[finding.finding_id] = finding
    return list(deduplicated.values())
