"""Contract rules: evidence ids, probe qualification and definitive verdict admission."""

import itertools

import pytest
from pydantic import ValidationError

from infosec_harness.contracts import (
    PROBE_PREREQUISITES,
    Citation,
    Evidence,
    Support,
    Verdict,
    definitive_support,
    probe_step,
)

CITED = [Citation(path="sink.py", start_line=1, end_line=1)]


def probe(identity, observed, **changes):
    fields = {"exit_code": 0, "timed_out": False, "output_truncated": False}
    fields.update({key: changes.pop(key) for key in tuple(changes) if key in fields})
    return Evidence(
        id=identity,
        kind="probe",
        command="probe",
        sandbox_id="probe",
        source_digest="digest",
        observations={
            **dict.fromkeys(PROBE_PREREQUISITES, True),
            "vulnerability_observed": observed,
            "workspace_digest": "workspace-digest",
            "source_verified": True,
            **changes,
        },
        **fields,
    )


def verdict(label="potentially_exploitable", cited=(), superseded=(), citations=CITED):
    return Verdict(
        label=label,
        summary="s",
        evidence_ids=list(cited),
        superseded_evidence_ids=list(superseded),
        citations=citations,
    )


def test_definitive_support_requires_citations_cited_match_and_no_contrary():
    matching, contrary = probe("probe:1:a", True), probe("probe:2:b", False)
    incomplete = probe("probe:3:c", False, negative_control=False)
    uncited = verdict(cited=["probe:1:a"], citations=[])
    assert definitive_support(uncited, [matching]) == Support(False, [], [])
    proposed = verdict(cited=["probe:1:a"])
    assert definitive_support(proposed, [matching, incomplete]) == Support(True, [], [])
    assert definitive_support(proposed, [probe("probe:9:z", True)]) == Support(False, [], [])
    assert definitive_support(proposed, [matching, contrary]) == Support(True, [contrary], [])
    # The label decides which observation is contrary.
    negative = verdict(label="likely_not_exploitable", cited=["probe:2:b"])
    assert definitive_support(negative, [matching, contrary]) == Support(True, [matching], [])


@pytest.mark.parametrize(
    ("identity", "step"),
    [
        ("probe:3:call_1", 3),
        ("execute:0:x", 0),
        ("probe:07:x", 7),
        ("probe:12:call:with:colons", 12),
        ("probe:999999999:x", 999_999_999),
        # Malformed ids are unknown (-1), never an exception.
        ("probe:1234567890:x", -1),  # over nine digits
        ("probe:" + "9" * 5000 + ":x", -1),  # past int()'s digit limit
        ("probe:²:x", -1),  # a superscript is a digit to str.isdigit, not to int()
        ("probe:٣:x", -1),  # a non-ASCII decimal digit
        ("probe:-1:x", -1),
        ("probe:+1:x", -1),
        ("probe: 1:x", -1),
        ("probe:3:", -1),  # no tool-call id
        ("probe:3", -1),
        ("probe", -1),
        (":3:x", -1),  # no kind
        ("Probe:3:x", -1),
        ("", -1),
    ],
)
def test_probe_step_parses_only_harness_evidence_ids(identity, step):
    assert probe_step(identity) == step


def test_superseded_probe_must_predate_the_latest_cited_probe():
    cited = probe("probe:5:cited", True)
    older = probe("probe:3:older", False)
    same_step = probe("probe:5:same", False)
    newer = probe("probe:7:newer", False)
    unknown = probe("unknown", False)
    evidence = [cited, older, same_step, newer, unknown]
    ids = [item.id for item in evidence[1:]]
    support = definitive_support(verdict(cited=["probe:5:cited"], superseded=ids), evidence)
    # Only the probe strictly older than the cited one is excused.
    assert support == Support(True, [same_step, newer, unknown], [older])
    # Without a superseded list, every contrary probe blocks.
    plain = definitive_support(verdict(cited=["probe:5:cited"]), evidence)
    assert plain == Support(True, [older, same_step, newer, unknown], [])


def test_supersession_uses_the_latest_of_several_cited_probes():
    early, late = probe("probe:2:early", True), probe("probe:8:late", True)
    flawed = probe("probe:6:flawed", False)
    ids = ["probe:2:early", "probe:8:late"]
    support = definitive_support(verdict(cited=ids, superseded=["probe:6:flawed"]),
                                 [early, late, flawed])
    assert support == Support(True, [], [flawed])
    # Supersession needs a cited matching probe: without one nothing is excused.
    uncorroborated = definitive_support(verdict(superseded=["probe:6:flawed"]), [flawed])
    assert uncorroborated == Support(False, [flawed], [])


def test_superseded_lists_only_qualified_contrary_probes():
    cited = probe("probe:9:cited", True)
    agreeing = probe("probe:1:agreeing", True)
    unqualified = probe("probe:2:unqualified", False, oracle_valid=False)
    listed = verdict(
        cited=["probe:9:cited"], superseded=["probe:1:agreeing", "probe:2:unqualified"]
    )
    assert definitive_support(listed, [cited, agreeing, unqualified]) == Support(True, [], [])


def legacy_definitive_support(verdict, evidence):
    """The rule as it stood before ``Support``: decisions must stay identical."""
    expected = verdict.label == "potentially_exploitable"
    qualified = [item for item in evidence if item.complete_verified_probe]
    cited = [
        item
        for item in qualified
        if item.id in verdict.evidence_ids
        and item.observations["vulnerability_observed"] is expected
    ]
    corroborated = bool(verdict.citations) and bool(cited)

    def step(identity):
        parts = identity.split(":")
        return int(parts[1]) if len(parts) >= 3 and parts[1].isdigit() else -1

    latest_cited = max((step(item.id) for item in cited), default=-1)
    superseded = {
        identity for identity in verdict.superseded_evidence_ids if -1 < step(identity) < latest_cited
    }
    contrary = [
        item
        for item in qualified
        if item.observations["vulnerability_observed"] is not expected
        and item.id not in superseded
    ]
    return corroborated, contrary


def test_admission_decisions_match_the_previous_rule():
    pool = [
        probe("probe:1:a", True),
        probe("probe:2:b", False),
        probe("probe:3:c", True),
        probe("probe:4:d", False),
        probe("probe:5:e", False, negative_control=False),
        probe("execute:6:f", True, exit_code=1),
    ]
    ids = [item.id for item in pool]
    checked = 0
    for label, citations in itertools.product(
        ("potentially_exploitable", "likely_not_exploitable"), (CITED, [])
    ):
        for cited, superseded in itertools.product(
            itertools.combinations(ids, 1), itertools.combinations(ids, 2)
        ):
            proposed = verdict(label, cited, superseded, citations)
            for size in (2, 4, 6):
                evidence = pool[:size]
                corroborated, contrary, superseded_items = definitive_support(proposed, evidence)
                assert (corroborated, contrary) == legacy_definitive_support(proposed, evidence)
                assert not {item.id for item in contrary} & {item.id for item in superseded_items}
                checked += 1
    assert checked == 2 * 2 * 6 * 15 * 3


@pytest.mark.parametrize(
    ("changes", "complete"),
    [
        ({}, True),
        ({"vulnerability_observed": False}, True),
        ({"exit_code": 1}, False),
        ({"exit_code": None}, False),
        ({"timed_out": True}, False),
        ({"output_truncated": True}, False),
        ({"vulnerability_observed": 1}, False),
        ({"vulnerability_observed": "true"}, False),
        ({"vulnerability_observed": None}, False),
        ({"source_verified": None}, False),
        ({"source_verified": "true"}, False),
        ({"workspace_digest": None}, False),
        *(({key: False}, False) for key in PROBE_PREREQUISITES),
        *(({key: 1}, False) for key in PROBE_PREREQUISITES),
    ],
)
def test_complete_verified_probe_requires_every_condition(changes, complete):
    assert probe("probe:1:a", True, **changes).complete_verified_probe is complete


def test_command_evidence_is_never_a_complete_probe():
    item = probe("execute:1:a", True).model_copy(update={"kind": "command"})
    assert item.complete_verified_probe is False


def test_excerpt_bounds_bytes_without_splitting_characters():
    item = probe("probe:1:a", True).model_copy(
        update={"stdout": "é" * 10, "stderr": "ok", "command": "c"}
    )
    short = item.excerpt(limit=5)
    assert short.stdout == "éé"  # 4 bytes; the split fifth byte is dropped
    assert short.stderr == "ok" and short.command == "c"
    assert short.observations["report_excerpted"] is True
    assert item.excerpt(limit=20).observations["report_excerpted"] is False
    assert item.excerpt(limit=20).stdout == item.stdout


def test_citation_line_range_must_be_ordered():
    assert Citation(path="a.py", start_line=2, end_line=2).end_line == 2
    with pytest.raises(ValidationError, match="reversed"):
        Citation(path="a.py", start_line=3, end_line=2)
