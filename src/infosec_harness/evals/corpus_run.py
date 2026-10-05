"""End-to-end corpus evaluation and stage/trajectory scoring."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from infosec_harness.domain.models import Finding, InconclusiveReason
from infosec_harness.evals._json import write_json
from infosec_harness.evals.corpus import approve_corpus_root, corpus_path, load_corpus
from infosec_harness.evals.corpus import languages as corpus_languages
from infosec_harness.evals.provenance import code_version
from infosec_harness.evals.trajectory import (
    AGENT_EXPECTATIONS,
    TrajectoryExpectation,
    check_expectations,
    cwe_skill_prefix,
    scores_skills,
)
from infosec_harness.graph.local import triage_batch_local
from infosec_harness.sandbox import docker
from infosec_harness.settings import get_settings


def _spread(values: list[float]) -> str:
    """`mean` when one sample, `mean [min-max]` when several — so noise is visible."""
    mean = sum(values) / len(values)
    if len(values) == 1:
        return f"{mean:.0%}"
    return f"{mean:.0%} [{min(values):.0%}-{max(values):.0%}]"


# The pipeline's stages, in order, each scored against ground truth the manifest already
# carries. A single accuracy number says a case failed; it cannot say *where*, and locating that
# by hand meant reading raw traces for every failure. Each entry is
# (label, applies_to_case, verdict_fn) where verdict_fn returns True/False, or None for "this
# stage did not get to run", which is counted separately so a late-stage rate is never inflated
# by the cases that never reached it.
def _stage_results(case, out) -> list[tuple[str, bool | None]]:
    """Score one case at each stage. None means the stage was never reached."""
    ctx = out.context
    execs = out.executions
    last = execs[-1] if execs else None
    probes = case.early_exit is None  # `testonly` is meant to stop before a probe

    def sink_located() -> bool | None:
        if ctx is None or ctx.sink is None:
            return None if ctx is None else False
        # The line is what the probe author actually needs; the file alone is not enough.
        # A CodeRef may legitimately span the whole statement, so the truth line must fall
        # inside the range rather than equal its start.
        if ctx.sink.file_path != case.sink_file:
            return False
        last = ctx.sink.end_line or ctx.sink.start_line
        return ctx.sink.start_line <= case.sink_line <= last

    return [
        ("environment built", out.prepared_status == "ready"),
        ("context: reachability", None if ctx is None else ctx.reachability.value == case.reachability),
        ("context: sink located", sink_located()),
        ("context: target callable",
         None if ctx is None else ctx.target_callable == case.target_callable),
        ("probe reached the sink",
         None if not probes else (last.precondition_reached if last else False)),
        ("probe's sink returned",
         None if not probes else (last.sink_returned if last else False)),
        # Gated on the sink having returned, not merely on a probe existing. A silent oracle
        # after a probe that never ran is not agreement -- and on the `fixed` half it would
        # score as a pass for the same reason a zero-test run once scored as a clean negative.
        ("oracle agreed with truth",
         None if not probes or last is None or not last.sink_returned
         else last.oracle_fired == (case.expected_verdict == "potentially_exploitable")),
        ("verdict", out.result.verdict.label.value == case.expected_verdict),
    ]


async def score_corpus(*, language: str = "python", sandbox: bool | None = None,
                       repeat: int = 1, manifest_path: Path | None = None,
                       dataset: str = "seed", limit: int = 0,
                       report: Path | None = None) -> dict:
    """Run the seeded corpus end-to-end and score verdicts against ground truth (§10.2).

    Headline metrics: per-class recall and the false-negative rate on truly exploitable
    cases (the costliest error). With stub models the verdicts are not meaningful (the stub
    is not a judge) — this is the harness that lights up under a live model.
    `sandbox=None` auto-detects the gVisor runtime.

    `language="all"` sweeps every language in the corpus. `repeat` runs the whole thing
    more than once and reports the spread: the corpus is small and the model is stochastic,
    so a single pass has enough run-to-run variance (measured: one agent's skill-evocation
    rate moved between 0% and 44% with no change at all) that comparing two one-pass runs
    cannot separate a real effect from noise. Repeat both sides of an A/B.

    ``report`` writes the metrics, with the code and corpus they were measured on, as JSON.
    """
    code = code_version()
    approve_corpus_root(manifest_path)

    if language == "all" and manifest_path is not None:
        # `languages()` reads the seeded manifest, so sweeping a harvested one has to come
        # from the harvested file rather than from the seed's language list.
        langs = sorted({c.language for c in load_corpus(manifest_path=manifest_path)})
    else:
        langs = corpus_languages() if language == "all" else [language]
    runs: list[dict] = []
    for rep in range(repeat):
        for lang in langs:
            if len(langs) > 1 or repeat > 1:
                print(f"--- {lang}" + (f" (pass {rep + 1}/{repeat})" if repeat > 1 else ""))
            runs.append({"language": lang, **await _score_corpus_once(
                language=lang, sandbox=sandbox, manifest_path=manifest_path,
                dataset=dataset, limit=limit)})
    if len(runs) == 1:
        _write_corpus_report(report, runs[0], code=code, language=language,
                             manifest_path=manifest_path, dataset=dataset, limit=limit,
                             repeat=repeat)
        return runs[0]

    agents = sorted({a for r in runs for a in r["trajectory"]})
    summary = {
        "runs": runs,
        "languages": langs,
        "repeat": repeat,
        "n": sum(r["n"] for r in runs),
        "accuracy_mean": round(sum(r["accuracy"] for r in runs) / len(runs), 4),
        "accuracy_min": min(r["accuracy"] for r in runs),
        "accuracy_max": max(r["accuracy"] for r in runs),
        "trajectory": {
            a: {
                "n": sum(r["trajectory"][a]["n"] for r in runs if a in r["trajectory"]),
                "tool_use_rate_mean": round(_mean_rate(runs, a, "tool_use_rate"), 3),
                "skill_use_rate_mean": round(_mean_rate(runs, a, "skill_use_rate"), 3),
            }
            for a in agents
        },
    }
    print("\n=== aggregate over "
          f"{len(runs)} run(s): {', '.join(langs)}"
          + (f" x{repeat}" if repeat > 1 else "") + " ===")
    print(f"accuracy {_spread([r['accuracy'] for r in runs])}  "
          f"FN-on-exploitable {_spread([r['false_negative_rate_on_exploitable'] for r in runs])}")
    print("tool/skill evocation:")
    for a in agents:
        tools = [r["trajectory"][a]["tool_use_rate"] for r in runs if a in r["trajectory"]]
        skills = [r["trajectory"][a]["skill_use_rate"] for r in runs if a in r["trajectory"]]
        skill_col = _spread(skills) if scores_skills(a) else "n/a (no expectation)"
        print(f"  {a:14} tools {_spread(tools):18} skills {skill_col}")
    _write_corpus_report(report, summary, code=code, language=language,
                         manifest_path=manifest_path, dataset=dataset, limit=limit,
                         repeat=repeat)
    return summary


def _write_corpus_report(path: Path | None, metrics: dict, *, code, language: str,
                         manifest_path: Path | None, dataset: str, limit: int,
                         repeat: int) -> None:
    if path is None:
        return
    write_json(path, {
        "schema_version": 1,
        "subject": {"kind": "corpus", "name": dataset},
        "selection": {"language": language, "limit": limit, "repeat": repeat,
                      "manifest": str(manifest_path or corpus_path())},
        "metrics": metrics,
        "provenance": {
            **code.as_dict(),
            "model_mode": get_settings().model_mode,
            "recorded_at": datetime.now(UTC).isoformat(),
        },
    })
    print(f"corpus report written to {path}")


def _mean_rate(runs: list[dict], agent: str, key: str) -> float:
    """Weight each run's rate by the cases it saw, so languages don't count equally."""
    num = sum(r["trajectory"][agent][key] * r["trajectory"][agent]["n"]
              for r in runs if agent in r["trajectory"])
    den = sum(r["trajectory"][agent]["n"] for r in runs if agent in r["trajectory"])
    return num / den if den else 0.0


async def _score_corpus_once(*, language: str, sandbox: bool | None,
                             manifest_path: Path | None = None, dataset: str = "seed",
                             limit: int = 0) -> dict:
    """One pass over the corpus. See :func:`score_corpus`."""
    cases = load_corpus(language, manifest_path=manifest_path, dataset=dataset)
    if limit:
        # Harvested manifests run to hundreds of cases against real repositories; a bounded
        # slice keeps a first run interpretable. Pairs are kept together, since scoring one
        # half of a pair measures nothing.
        keep = {c.name.rsplit("-", 1)[0] for c in cases[:limit]}
        cases = [c for c in cases if c.name.rsplit("-", 1)[0] in keep]
    if sandbox is None:
        sandbox = await docker.docker_available() and await docker.runtime_available()
    prepare_sink: dict[tuple[str, str], list] = {}
    # A harvested case ships the PoV test that established its ground truth, and on a `-fixed`
    # revision the fix commit put it in the tree. Strip it before any agent reads the checkout,
    # or probe-author is scored on copying rather than authoring.
    masks: dict[tuple[str, str], list[str]] = {}
    for c in cases:
        if c.mask_paths:
            masks.setdefault((c.finding.repo_url, c.finding.revision), []).extend(c.mask_paths)
    # Cache off: an eval must exercise every stage and give the same answer twice.
    # Serial for the same reason, and one more. Concurrency makes per-case latency
    # unreadable -- N probe containers competing for the same sandbox CPU inflate each other's
    # timings, so the p50/p95 numbers in the report would describe contention rather than the
    # pipeline. And a measurement should not be the thing that decides how much hardware the
    # runner needs: production can fan out, an eval establishes the baseline it fans out from.
    # Override with `concurrency=` when deliberately measuring the effect of fanning out.
    outputs = await triage_batch_local([c.finding for c in cases], sandbox=sandbox,
                                       recipe_cache=False, mask_paths=masks, concurrency=1,
                                       prepare_sink=prepare_sink)
    by_fp = {o.finding.fingerprint: o for o in outputs}

    rows, confusion = [], {}
    correct = fn = exploitable = 0
    # Cases the manifest expects to run the full pipeline, and how many of those were right
    # *and* actually got there. `accuracy` alone cannot distinguish a probed verdict from a
    # label guessed before the build.
    expected_to_probe = correct_with_evidence = 0
    unexpected_exits: list[str] = []
    # stage label -> [passed, scored, not_reached], in the order _stage_results returns them.
    stages: dict[str, list[int]] = {}
    first_failures: dict[str, list[str]] = {}
    infrastructure_failures: list[str] = []
    # Trajectory scoring: did the tool-using agents evoke the expected tools/skills?
    traj_totals: dict[str, dict[str, int]] = {}
    # Request counts and repeated identical tool calls, so a `request_limit` breach can be told
    # from honest work without re-running live. inspect_messages de-duplicates by tool name and
    # drops arguments, so without this a run that read one file eight times is byte-identical in
    # the record to one that read it once.
    budget_totals: dict[str, dict[str, int]] = {}
    worst_repeats: dict[str, dict[str, int]] = {}

    def _score_trajectory(agent: str, tools_called, skills_loaded, cwe: str | None = None,
                          requests: int = 0, repeated: dict[str, int] | None = None) -> None:
        # Recorded for every agent, including those with no expectation: an agent that burns its
        # request budget is worth seeing whether or not its tool use is scored.
        b = budget_totals.setdefault(agent, {"n": 0, "requests": 0, "max_requests": 0, "looping": 0})
        b["n"] += 1
        b["requests"] += requests
        b["max_requests"] = max(b["max_requests"], requests)
        b["looping"] += int(bool(repeated))
        for key, count in (repeated or {}).items():
            worst_repeats.setdefault(agent, {})
            worst_repeats[agent][key] = max(worst_repeats[agent].get(key, 0), count)
        base = AGENT_EXPECTATIONS.get(agent)
        if base is None:
            return
        skill_prefixes = base.skill_prefixes
        if agent == "context" and (p := cwe_skill_prefix(cwe)):
            skill_prefixes = (p,)  # require the *matching* CWE skill, not just any
        exp = TrajectoryExpectation(tool_groups=base.tool_groups, skill_prefixes=skill_prefixes)
        res = check_expectations(tools_called, skills_loaded, exp)
        t = traj_totals.setdefault(agent, {"n": 0, "tools_ok": 0, "skills_ok": 0})
        t["n"] += 1
        t["tools_ok"] += int(res.tools_ok)
        t["skills_ok"] += int(res.skills_ok)

    # Prepare-phase agents (recon, env-planner, build repair) run once per repo.
    for invs in prepare_sink.values():
        for inv in invs:
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded,
                              requests=inv.requests, repeated=inv.repeated_tool_calls)

    for c in cases:
        out = by_fp[Finding.compute_fingerprint(c.finding)]
        actual = out.result.verdict.label.value
        ok = actual == c.expected_verdict
        correct += int(ok)
        # An early exit the manifest did not ask for means the label was reached without the
        # mechanism under test: no build, no probe, no oracle. Measured on the Perl pair --
        # both `fixed` cases came back `likely_not_exploitable` via `unreachable_by_context`,
        # scoring as clean passes while never probing anything. Label accuracy stays label
        # accuracy, but a pass with no evidence behind it must be visible, because the same
        # reasoning applied to a vulnerable case is a false negative.
        unexpected_exit = out.result.early_exit and out.result.early_exit != c.early_exit
        if unexpected_exit:
            unexpected_exits.append(f"{c.name} ({out.result.early_exit})")
        if c.early_exit is None:
            expected_to_probe += 1
            correct_with_evidence += int(ok and not unexpected_exit)
        confusion[(c.expected_verdict, actual)] = confusion.get((c.expected_verdict, actual), 0) + 1
        if c.expected_verdict == "potentially_exploitable":
            exploitable += 1
            if actual != "potentially_exploitable":
                fn += 1  # missed a real vulnerability — the costliest error
        rows.append({"case": c.name, "expected": c.expected_verdict, "actual": actual,
                     "ok": ok, "early_exit": out.result.early_exit,
                     "unexpected_early_exit": bool(unexpected_exit),
                     "priority": out.result.priority.value,
                     # Why, not just that: a table of `inconclusive` tells you nothing about
                     # whether the environment failed, the probe was unrepairable, or the
                     # judge declined.
                     "rationale": out.result.verdict.rationale})
        # A provider outage tells us nothing about any stage. Counting it would have read
        # "environment built 1/4" on a run where the environment stage worked and the model
        # endpoint was returning 502 -- the precise misattribution this funnel exists to stop.
        if out.result.verdict.inconclusive_reason == InconclusiveReason.infrastructure_error:
            infrastructure_failures.append(c.name)
            continue
        stage_results = _stage_results(c, out)
        blamed = False
        for label, passed in stage_results:
            tally = stages.setdefault(label, [0, 0, 0])
            if passed is None:
                tally[2] += 1
                continue
            tally[1] += 1
            tally[0] += int(passed)
            # Attribute each failing case to the FIRST stage that went wrong. A late stage
            # inherits every earlier mistake, so without this the blame lands on `verdict`
            # for a case whose context misread reachability three stages earlier.
            if not passed and not blamed:
                first_failures.setdefault(label, []).append(c.name)
                blamed = True

        # Per-finding triage agents (context, probe-author, ...).
        for inv in out.invocations:
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded, c.finding.cwe,
                              requests=inv.requests, repeated=inv.repeated_tool_calls)

    trajectory = {a: {"n": v["n"],
                      "tool_use_rate": round(v["tools_ok"] / v["n"], 3) if v["n"] else 0.0,
                      "skill_use_rate": round(v["skills_ok"] / v["n"], 3) if v["n"] else 0.0}
                  for a, v in sorted(traj_totals.items())}
    metrics = {
        "n": len(cases), "accuracy": round(correct / len(cases), 4) if cases else 0.0,
        "false_negative_rate_on_exploitable": round(fn / exploitable, 4) if exploitable else 0.0,
        "sandbox": sandbox,
        "accuracy_with_evidence": (round(correct_with_evidence / expected_to_probe, 4)
                                   if expected_to_probe else 0.0),
        "unexpected_early_exits": unexpected_exits,
        "infrastructure_failures": infrastructure_failures,
        "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
        "trajectory": trajectory,
        "stages": {label: {"passed": p, "scored": n, "not_reached": nr,
                           "rate": round(p / n, 3) if n else None,
                           "first_failed_here": first_failures.get(label, [])}
                   for label, (p, n, nr) in stages.items()},
        "budget": {a: {"n": v["n"],
                       "mean_requests": round(v["requests"] / v["n"], 2) if v["n"] else 0.0,
                       "max_requests": v["max_requests"],
                       "runs_with_repeated_calls": v["looping"],
                       "worst_repeats": dict(sorted(worst_repeats.get(a, {}).items(),
                                                    key=lambda kv: -kv[1])[:3])}
                   for a, v in sorted(budget_totals.items())},
    }
    for r in rows:
        mark = "OK " if r["ok"] else "XX "
        print(f"  {mark}{r['case']:26} {r['expected']:24} -> {r['actual']:24} {r['early_exit'] or ''}")
        if not r["ok"] and r["rationale"]:
            # Long enough to carry the whole failure. A truncated reason costs more time than
            # the extra lines do: "UsageLimitExceeded: The" says nothing about which limit.
            print(f"        {r['rationale'][:600]}")
    print(f"accuracy={metrics['accuracy']:.0%}  FN-on-exploitable={metrics['false_negative_rate_on_exploitable']:.0%}  "
          f"sandbox={'on' if sandbox else 'off (verdicts not meaningful)'}")
    if unexpected_exits:
        print(f"accuracy-with-evidence={metrics['accuracy_with_evidence']:.0%}  "
              f"({expected_to_probe - correct_with_evidence} of {expected_to_probe} cases that "
              f"should have probed did not reach a probed verdict)")
        print(f"  unexpected early exits: {', '.join(unexpected_exits)}")
    if infrastructure_failures:
        print(f"WARNING: {len(infrastructure_failures)} of {len(cases)} cases failed on "
              f"infrastructure, not on the pipeline (model provider unreachable, timed out, or "
              f"a transport error). These are excluded from the stage funnel below, and the "
              f"accuracy above is not a measurement of anything: {', '.join(infrastructure_failures)}")
    if metrics["stages"]:
        print("stage funnel (where the pipeline actually loses cases):")
        for label, st in metrics["stages"].items():
            if not st["scored"]:
                print(f"  {label:26} --      (not reached in {st['not_reached']} cases)")
                continue
            blame = st["first_failed_here"]
            note = f"   <- first failure for {', '.join(blame)}" if blame else ""
            skipped = f"  (+{st['not_reached']} not reached)" if st["not_reached"] else ""
            print(f"  {label:26} {st['passed']}/{st['scored']}"
                  f"  {st['rate']:.0%}{skipped}{note}")
    print("tool/skill evocation (per agent, rate across cases):")
    for agent, t in trajectory.items():
        skills = f"{t['skill_use_rate']:.0%}" if scores_skills(agent) else "n/a"
        print(f"  {agent:14} tools {t['tool_use_rate']:.0%}  skills {skills}  (n={t['n']})")
    if any(v["max_requests"] for v in metrics["budget"].values()):
        print("requests per agent run (max, and identical calls repeated):")
        for agent, b in metrics["budget"].items():
            if not b["max_requests"]:
                continue
            note = ""
            if b["runs_with_repeated_calls"]:
                worst = next(iter(b["worst_repeats"].items()), None)
                note = (f"  LOOPING in {b['runs_with_repeated_calls']}/{b['n']} runs"
                        + (f", worst {worst[0]} x{worst[1]}" if worst else ""))
            # 15 wide: this section lists every agent, including probe-diagnosis, which is
            # one character wider than the tool-using agents the trajectory table covers.
            print(f"  {agent:15} max {b['max_requests']:3}  mean {b['mean_requests']:6.2f}{note}")
    return metrics
