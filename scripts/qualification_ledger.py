"""Assess Git-reviewed component evidence; no evals, scoring, promotion, or runtime calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def is_hash(value):
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


class EvidenceUnavailable(ValueError):
    pass


def artifact(ref):
    require(set(ref) == {"file", "sha256"} and is_hash(ref["sha256"]), "artifact reference invalid")
    p = Path(ref["file"])
    if not p.is_file() or p.is_symlink():
        raise EvidenceUnavailable("artifact unavailable")
    if hashlib.sha256(p.read_bytes()).hexdigest() != ref["sha256"]:
        raise EvidenceUnavailable("artifact drift")


class InventoryUnavailable(ValueError):
    pass


def dependencies(value, current=False):
    require(isinstance(value, dict) and bool(value), "dependency inventory missing")
    result = {}
    for group, entries in value.items():
        require(
            isinstance(group, str) and isinstance(entries, dict) and bool(entries),
            "dependency group invalid",
        )
        if current and "files" in entries:
            require(set(entries) <= {"files", "identities"}, "file inventory fields invalid")
            values = dict(entries.get("identities", {}))
            for name, path in entries["files"].items():
                require(name not in values, "duplicate inventory identity")
                file = Path(path)
                if not file.is_file() or file.is_symlink():
                    raise InventoryUnavailable("inventory file unavailable")
                values[name] = hashlib.sha256(file.read_bytes()).hexdigest()
            require(values and all(is_hash(v) for v in values.values()), "inventory digest invalid")
            entries = {"inventory": digest(values)}
        result[group] = {}
        for name, identity in entries.items():
            require(isinstance(name, str) and bool(name), "dependency identity missing")
            if current and isinstance(identity, dict):
                require(set(identity) == {"file"}, "current file identity invalid")
                p = Path(identity["file"])
                if not p.is_file() or p.is_symlink():
                    raise InventoryUnavailable("current dependency unavailable")
                identity = hashlib.sha256(p.read_bytes()).hexdigest()
            require(is_hash(identity), "dependency digest invalid")
            result[group][name] = identity
    return result


def assess(ledger, current, reviews=None):
    require(
        set(ledger) == {"version", "records"} and ledger["version"] == 1, "ledger format invalid"
    )
    require(
        set(current) == {"qualification_candidate_commit", "components"},
        "current inventory invalid",
    )
    commit = current["qualification_candidate_commit"]
    require(
        isinstance(commit, str)
        and len(commit) == 40
        and all(c in "0123456789abcdef" for c in commit),
        "candidate commit invalid",
    )
    snapshots = {}
    for component, inventory in current["components"].items():
        try:
            snapshots[component] = dependencies(inventory, current=True)
        except InventoryUnavailable:
            snapshots[component] = None
    reviews = {} if reviews is None else reviews
    ids = [row["id"] for row in ledger["records"]]
    require(
        len(ids) == len(set(ids)) and set(reviews) <= set(ids), "duplicate/unknown review record"
    )
    rows = []
    for row in ledger["records"]:
        require(
            row["id"] == digest({k: v for k, v in row.items() if k != "id"}),
            "record identity drift",
        )
        require(
            row["measured_status"] in {"passed", "failed", "not_checked", "not_applicable"},
            "measured status invalid",
        )
        before = dependencies(row["dependencies"])
        require(bool(row["evidence"]), "retained evidence missing")
        evidence_valid = True
        for ref in row["evidence"].values():
            try:
                artifact(ref)
            except EvidenceUnavailable:
                evidence_valid = False
        after = snapshots.get(row["component"])
        changes = (
            []
            if after is None
            else sorted(
                f"{g}:{k}"
                for g in set(before) | set(after)
                for k in set(before.get(g, {})) | set(after.get(g, {}))
                if before.get(g, {}).get(k) != after.get(g, {}).get(k)
            )
        )
        review = reviews.get(row["id"])
        review_applicable = False
        if review is not None:
            require(
                set(review)
                == {"scope", "before_sha256", "after_sha256", "reviewer", "reason", "evidence"},
                "review fields invalid",
            )
            require(
                review["scope"] == row["scope"] and review["before_sha256"] == digest(before),
                "review identity mismatch",
            )
            require(
                all(
                    isinstance(review[k], str) and review[k].strip() for k in ("reviewer", "reason")
                ),
                "review signoff missing",
            )
            try:
                artifact(review["evidence"])
            except EvidenceUnavailable:
                evidence_valid = False
            require(
                row["measured_status"] == "passed",
                "review cannot promote failed/unchecked evidence",
            )
            review_applicable = after is not None and review["after_sha256"] == digest(after)
        reusable = evidence_valid and after is not None and (not changes or review_applicable)
        rows.append(
            {
                "record_id": row["id"],
                "component": row["component"],
                "scope": row["scope"],
                "measured_source_commit": row["measured_source_commit"],
                "qualification_candidate_commit": commit,
                "status": row["measured_status"] if reusable else "not_checked",
                "disposition": "evidence_unavailable"
                if not evidence_valid
                else "inventory_missing"
                if after is None
                else "reviewed_equivalence"
                if review_applicable
                else "unchanged"
                if not changes
                else "retest_or_review_required",
                "changed_dependencies": changes,
            }
        )
    return {
        "scope": "assembled component evidence assessment",
        "fresh_full118": "not_checked",
        "system_release": "not_checked",
        "results": rows,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ledger", required=True)
    p.add_argument("--current", required=True)
    p.add_argument("--reviews")
    p.add_argument("--output", required=True)
    args = p.parse_args()

    def read(path):
        return json.loads(Path(path).read_text())

    result = assess(
        read(args.ledger), read(args.current), read(args.reviews) if args.reviews else None
    )
    with os.fdopen(
        os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w"
    ) as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
