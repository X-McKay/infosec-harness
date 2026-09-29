"""Every scored dataset is big enough, and every case in it points at something real.

Why a minimum size at all. `harness eval run` scores one case per row, so accuracy lands on
the grid k/n: with n=1 the only scores are 0% and 100%, with n=2 they are 0/50/100. Against a
`task_success_rate` floor of 0.85 that is not a measurement — it is a coin toss that the
release policy then reports as a pass or a fail. The floor asserted here (MIN_CASES) is the
point at which one case is worth under a fifth of the score; it is a floor and not a
comfortable size, because at n=6 a single wrong case still yields 83% and misses the 0.85
threshold. n=7 is the first size where one failure is survivable, and datasets that carry
weight in release decisions should grow past this minimum rather than sit on it.

Why the other two checks. Duplicate case names collapse in the per-case results table
(`EvalCaseResult.case_name` is how a regression is traced back to a case), so two cases with
one name are one case as far as anyone reading the report is concerned. And a `repo:` that
does not exist resolves to an absolute path the repo-reading agents simply find empty: the
adapter builds AgentDeps from it either way, the agent answers from the prose in the payload
alone, and the case quietly stops testing what it claims to. Both failures are invisible in
an accuracy number, which is why they are asserted here instead.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from infosec_harness.evals.adapters import ADAPTERS
from infosec_harness.settings import REPO_ROOT, get_settings

MIN_CASES = 6

DATASETS = {name: get_settings().agents_dir / name / "evals" / "dataset.yaml" for name in ADAPTERS}


def _cases(agent: str) -> list[dict]:
    return yaml.safe_load(DATASETS[agent].read_text())["cases"]


@pytest.mark.parametrize("agent", sorted(ADAPTERS))
def test_every_agent_with_an_adapter_has_a_dataset(agent):
    assert DATASETS[agent].exists(), f"{agent} has an eval adapter but no dataset to feed it"


@pytest.mark.parametrize("agent", sorted(ADAPTERS))
def test_dataset_is_large_enough_to_measure_against_the_release_threshold(agent):
    """A dataset smaller than MIN_CASES cannot distinguish a passing agent from a lucky one.

    The release policy gates on `task_success_rate`, and the scoring grid is k/n. Below this
    size a single case moves accuracy by more than the entire margin the policy allows, so the
    reported number says more about which case was drawn than about the agent.
    """
    n = len(_cases(agent))
    assert n >= MIN_CASES, (
        f"{agent}: {n} case(s). With n={n} one case is worth {1 / n:.0%} of the score, so the "
        f"release threshold is decided by a single example."
    )


@pytest.mark.parametrize("agent", sorted(ADAPTERS))
def test_case_names_are_unique_within_a_dataset(agent):
    """Case names are the only handle on a case in the persisted results, so they must be keys."""
    names = [case["name"] for case in _cases(agent)]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, f"{agent}: duplicate case name(s) {duplicates}"


@pytest.mark.parametrize("agent", sorted(ADAPTERS))
def test_every_repo_a_case_names_exists(agent):
    """`repo:` is resolved relative to the repository root by `adapters._repo`.

    A path that does not exist is not an error at run time: the agent's file tools just find
    nothing, and it answers from the payload. The case still scores, so a typo here degrades a
    grounded case into a prose-only one without any signal that it happened.
    """
    missing = []
    for case in _cases(agent):
        repo = case.get("repo")
        if repo is None:
            continue
        assert not Path(repo).is_absolute(), f"{agent}/{case['name']}: repo must be repo-relative"
        if not (REPO_ROOT / repo).is_dir():
            missing.append(f"{case['name']} -> {repo}")
    assert not missing, f"{agent}: case(s) naming a repo that is not on disk: {missing}"


def _recon_predict():
    case = next(case for case in _cases("recon") if case["name"] == "java-junit5")
    return ADAPTERS["recon"](case)[3]


@pytest.mark.parametrize("framework", [
    "junit5",
    "JUnit 5",
    "JUnit 5 (Jupiter 5.10.2)",
    "JUnit 5 (JUnit-Jupiter 5.10.2)",
    "JUnit Jupiter 5.10.2",
])
def test_recon_scorer_accepts_bounded_unambiguous_junit5_aliases(framework):
    profile = SimpleNamespace(primary_language="Java", test_framework=framework)
    assert _recon_predict()(profile) == "java/junit5"
    # Canonical scoring must not rewrite the evidence returned by the model.
    assert profile.test_framework == framework


@pytest.mark.parametrize("framework", [
    "junit4",
    "JUnit 4.13",
    "JUnit 4 4.13",
])
def test_recon_scorer_accepts_only_junit4_versions_with_major_four(framework):
    profile = SimpleNamespace(primary_language="Java", test_framework=framework)
    assert _recon_predict()(profile) == "java/junit4"


@pytest.mark.parametrize("framework", [
    "JUnit 4 5.10.2",
    "JUnit 4.13 and JUnit 5.10",
])
def test_recon_scorer_rejects_contradictory_junit4_labels(framework):
    profile = SimpleNamespace(primary_language="Java", test_framework=framework)
    assert _recon_predict()(profile) != "java/junit4"


@pytest.mark.parametrize("framework", [
    "not pytest",
    "JUnit 4 and JUnit 5",
    "JUnit 5 / JUnit 4",
    "JUnit 5 (Jupiter 4.13)",
    "JUnit 5 (JUnit-Jupiter 4.13)",
    "JUnit Jupiter 4.13",
    "pytest or unittest",
    "JUnit 5" + " " * 130,
])
def test_recon_scorer_does_not_launder_negated_mixed_or_unbounded_labels(framework):
    profile = SimpleNamespace(primary_language="Java", test_framework=framework)
    assert _recon_predict()(profile) != "java/junit5"
