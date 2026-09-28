# External corpus sources

The seeded corpus under `eval-corpus/` is small, self-contained, and written by us. That is
its strength — the ground truth is exact and the pairs differ only in the one thing we mean
to measure — and also its weakness: every case is a toy, and nothing in it exercises the part
of the pipeline that has to work out how to build an unfamiliar project. This document
covers the external datasets we harvest to get that second kind of signal, what we take from
them, what we deliberately leave behind, and which entries we cannot use at all.

Harvested corpora live under `eval-corpus/external/` and are never merged into
`eval-corpus/manifest.json`. The seeded corpus is a fixture we maintain; a harvested one is a
snapshot of somebody else's data that we re-derive by re-running a script. Keeping them in
separate files keeps that difference visible.

## Vul4J

[Vul4J](https://github.com/tuhh-softsec/vul4j) is a benchmark of real Java vulnerabilities,
each with the upstream repository, the fix commit, and a test that fails before the fix and
passes after it. It is the closest public thing to what our pipeline consumes: a finding
against a real project, with a knowable answer.

**Attribution.** Vul4J: A Dataset of Reproducible Java Vulnerabilities, Quang-Cuong Bui,
Riccardo Scandariato, et al., MSR 2022, <https://github.com/tuhh-softsec/vul4j>. The dataset
is licensed [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) and every case we emit
carries that attribution in its own `source` object, so a case that travels away from this
repository keeps its provenance with it.

Vul4J's **code** is GPL-3.0. This repository has no licence file, so we take nothing from it:
no source, no test files, no adapted logic. `scripts/harvest_vul4j.py` reads
`dataset/vul4j_dataset.csv` and nothing else, and it fetches that file at harvest time rather
than committing a copy, so our view of the dataset cannot silently drift from theirs. The
only Vul4J content in this repository is `eval-corpus/external/vul4j_excerpt.csv`, eight rows
kept so `tests/test_harvest.py` can run offline; it is labelled as an excerpt in
`vul4j_excerpt.NOTICE` and nothing but the tests reads it.

### What we take, and what we refuse

Vul4J's central contribution is reproducibility: pinned Docker images, a compile command, a
test command, and a long list of Maven flags per entry, so that anyone can rebuild each
project exactly as the authors did. We take none of that, on purpose.

Two of the stages this eval exists to measure — `env-planner` and `build-repair` — do exactly
the work those columns short-circuit. An eval that hands the pipeline a known-good
`mvn -DskipTests clean install` measures neither, while still reporting a score, which is
worse than not running them at all. So `compile_cmd`, `test_all_cmd`, `test_cmd`,
`cmd_options`, `src_classes`, and `test_classes` are dropped at parse time and
`tests/test_harvest.py` asserts that no build invocation reaches the output file.

What we do take is facts the pipeline could not be expected to invent: the repository, the
fix commit and its parent, the CVE and CWE, the build system and JDK level as *facts about
the project* rather than as instructions, and whether a proof-of-vulnerability test exists.

### Case shape

Each usable entry becomes a pair, following the seeded corpus's convention:
`vul4j-<n>-vulnerable` at the fix commit's parent, expected `potentially_exploitable`, and
`vul4j-<n>-fixed` at the fix commit, expected `likely_not_exploitable`. The one structural
difference is that `finding.repo_url` is a remote git URL and `finding.revision` is a full
commit SHA, rather than a vendored directory at `HEAD`. `repo.checkout.checkout()` already
handles both and keys its snapshot on `repo_url@revision`, so nothing else has to change.

Beyond `finding` and `truth`, each case carries three extra objects: `source` (provenance and
attribution), `build` (build system, JDK, module — facts, not a recipe), and `cwe_coverage`
(whether we ship a skill for this CWE; see below).

### The leakage rule

**Anything that runs these cases must keep `truth.pov` away from the agent.**

Vul4J's proof-of-vulnerability test is usually added by the fix commit. That is what makes a
pair sound: at the vulnerable revision there is no test demonstrating the bug, so when our
`probe-author` stage writes one, we are measuring whether it can. When the test is already in
the tree the agent reads, the agent can read the exact triggering input straight out of it,
and the probe-author score stops being a measurement of anything.

The harvester checks this per entry and classifies the PoV three ways:

- **`fix-commit`** — the fix adds the test file, or adds this method to an existing test file.
  The vulnerable checkout does not contain it. This is the case we want, and it is 48 of the
  58 entries we keep.
- **`pre-existing`** — the file and the method are both present at the parent commit. These
  entries are not emitted as cases at all: they go to a `quarantined` list in the same file,
  with the reason. There are 11 of them.
- **`not-in-repository`** — neither revision has it, because Vul4J wrote the test themselves.
  These 10 entries are the safest of all from a leakage standpoint, and the weakest from a
  ground-truth standpoint: we have no PoV path to point at, and we will not vendor theirs,
  because their code is GPL-3.0. They are usable, but the only thing verifying a probe against
  them is the pipeline's own oracle.

An entry whose PoV presence we could not establish — a tree GitHub declined to enumerate, a
blob too large to read — is quarantined alongside the leaking ones. Unverified is not the same
as safe, and the failure mode of getting this wrong is silent.

**The quarantine only protects the vulnerable side.** On every `-fixed` case the PoV is in the
checkout by construction, because the fix commit is what added it. No filtering can change
that, so the mitigation has to be applied by the consumer: remove `truth.pov.mask_paths` from
the tree before the agent reads it. Each case records the path and the test name for exactly
this purpose, and the file's `note` says so. Nothing in `src/infosec_harness/` masks these
paths today; that plumbing is still to be written, and until it is, these cases should not be
used to score `probe-author`.

A caveat on the `pre-existing` group, stated plainly because the quarantine is stricter than
the evidence strictly supports: a test method with the same name existing before the fix does
not always mean a working PoV existed. Several of these are tests the fix *modified*, so the
pre-fix version asserted the vulnerable behaviour. What the agent can still copy is the
scenario and the triggering input, which is most of the work, so quarantining is the right
call — but these entries are recoverable with per-entry review, and are kept in the file
rather than discarded so that review is possible.

### CWE coverage

Our trajectory scorer maps a finding's CWE to a `skills/cwe-<n>-*` skill and checks the
matching skill was loaded. A CWE we have no skill for therefore scores zero on that dimension
no matter how the agent behaved.

We do not rewrite the dataset's classification to avoid this. Relabelling somebody's CWE to
suit our scorer is inventing ground truth, and it would hide the honest finding that most of
Vul4J falls outside the eight classes we cover. Instead each case carries a `cwe_coverage`
object with `covered`, `adjacent`, or `uncovered`, and consumers can filter or score
separately.

Of the 58 entries we keep, 20 are `covered` (CWE-22 ×7, CWE-611 ×5, CWE-502 ×4, CWE-79 ×2,
CWE-918 ×2), one is `adjacent`, and 37 are `uncovered`. The uncovered tail is dominated by
CWE-835 (infinite loop), CWE-20 (improper input validation), CWE-264 (permissions), and
13 entries the dataset marks `Not Mapping`.

The single `adjacent` entry is the one CWE rewrite we are willing to defend: CWE-77 (Command
Injection) has no skill of its own, and CWE-78 (OS Command Injection) is its direct child, so
`skills/cwe-78-os-command-injection` reads correctly for it. `cwe_coverage.cwe` names the
substitute; `finding.cwe` still says CWE-77. CWE-74 (Injection, generic) is *not* mapped
this way: it could be any of four of our skills, and picking one would be a guess.

### What we cannot use

Of Vul4J's 129 entries, 60 are skipped outright:

| Count | Reason |
|---|---|
| 50 | The `-S` subset (entries 80–129). These are static-analysis warnings from student projects: no CVE, no CWE, no failing test. Nothing in our pipeline can score them. |
| 4 | The fix commit is a merge with two parents, so there is no single revision that is "before the fix". |
| 3 | The fix commit exists only in a Vul4J-owned mirror (`bqcuong/vul4j`, `tuhh-softsec/Vul4J`), not in the upstream repository the entry names. Cloning upstream would not resolve the SHA, and substituting the mirror would hand agents a history that is not the project's. |
| 2 | The dataset records a commit *range* rather than a single fix commit, so there is no one revision to call `fixed`. |
| 1 | GitHub refuses to serve the commit at all (HTTP 422). |

A further 11 are quarantined for the leakage reason above, leaving 58 entries — 116 cases —
across 42 repositories.

### What would trip the pipeline

Things worth knowing before these cases are run for real:

- **The revisions in the dataset are not all full SHAs.** Seven fix commits are recorded
  abbreviated, one to eight characters. GitHub resolves them today; git may not resolve them
  against a shallow clone, and an abbreviation is not the identity of a commit. The harvester
  stores the canonical SHA the API reports and keeps the original URL on record.
- **The dataset's `repo_slug` is not always where the commit lives.** Four entries disagree
  with their own patch URL. One is a benign upstream rename (`apache/batik` is now
  `apache/xmlgraphics-batik`) and the harvester follows the patch URL; three are the mirrors
  skipped above. `source.repo_slug_reported` and `source.repo_slug_resolved` record both.
- **`cve_id` is not always a CVE.** At least one entry carries a project-local identifier
  (`APACHE-COMMONS-001`). Anything keying on the CVE format needs to tolerate that.
- **34 of the 58 are multi-module builds** where the vulnerability is in a named submodule,
  not the root. `build.module` records which, and a full-reactor build of some of these is
  very large.
- **These are old projects.** They need JDK 7, 8, or 11, and several depend on Maven Central
  artifacts and plugin versions that no longer resolve cleanly with a modern toolchain. Vul4J
  works around this with pinned images and a long list of skip flags; we have deliberately
  chosen to let `build-repair` meet the problem instead, which means some of these cases will
  legitimately fail to build. That is a measurement, not a defect, but it should be expected.
- **Seven of the 58 are Gradle**, against 51 Maven. `skills/build-gradle` gets far less
  exercise from the seeded corpus than this ratio implies.

### Ground truth we could not establish

`truth.sink_file` and `truth.sink_line` are a heuristic: the largest non-test Java file the
fix commit touched, and the first line of its first hunk. `truth.sink_confidence` records
this as `fix-hunk-heuristic`. `truth.target_callable` is the fully-qualified *class* of that
file, not a method, because the dataset does not record one and deriving it would mean
parsing the source.

This is weaker than the seeded corpus, where the sink line is exact. It is as far as we can
get from Vul4J's data alone, and going further would mean building and analysing each project
— which is precisely the work we are refusing to inherit. Where the exact sink matters, these
cases should be scored on the verdict and on reachability, not on sink localisation.

### JDK spread

`build.jdk` carries Vul4J's `compliance_level` column verbatim. Across the 58 harvested
entries: **JDK 8 ×43, JDK 7 ×14, JDK 11 ×1**. Including the 11 quarantined entries, in case
they are later recovered: JDK 8 ×48, JDK 7 ×20, JDK 11 ×1. There is nothing newer than 11 in
the dataset at all.

### Running the harvester

```
uv run python scripts/harvest_vul4j.py                    # fetch and write
uv run python scripts/harvest_vul4j.py --dry-run          # report, write nothing
uv run python scripts/harvest_vul4j.py --dataset <path>   # use a local CSV
```

It needs GitHub API access to resolve parent commits and check PoV presence: pass `--token`,
set `GITHUB_TOKEN` or `GH_TOKEN`, or have an authenticated `gh` on `PATH`. Unauthenticated
runs are capped at 60 requests an hour and will not get through the dataset. Responses cache
under `--cache-dir` (a temporary directory by default, deliberately outside the repository),
so a second run is free and produces a byte-identical file — the output
carries no timestamp, and entries are ordered by their numeric Vul4J id, so a re-run is a
diff only when the upstream dataset has actually changed.
