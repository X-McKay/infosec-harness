"""The JavaScript and Perl corpus variants really are what the manifest says they are.

`test_corpus_oracle.py` closes this gap for Python by importing each variant and driving it with
a reference probe. It cannot do that for JS or Perl, so those cases' ground truth rested on
reading the source — and a "vulnerable" variant accidentally written safe would make every
expected verdict in the manifest wrong with nothing failing.

These drive each variant with the real interpreter, in a subprocess, reading the result through
the harness's own `oracle_signals`: exactly the signal the graph triages on. No container is
involved, so this asserts the *corpus* is sound, not that the isolation is. Skipped when the
interpreter is absent rather than failing, because a missing `node` says nothing about the corpus.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from infosec_harness.sandbox.output import oracle_signals, sink_returned
from infosec_harness.settings import REPO_ROOT

CORPUS = REPO_ROOT / "eval-corpus"
NONCE = "c0rpus1"
PAYLOAD = f"<script>{NONCE}</script>"


def _run(argv: list[str], cwd: Path) -> tuple[bool, bool, bool, str]:
    """(oracle_fired, precondition_reached, sink_returned, output) for one reference probe."""
    res = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=120)
    combined = res.stdout + "\n" + res.stderr
    fired, reached = oracle_signals(combined, NONCE)
    return fired, reached, sink_returned(combined, NONCE), combined


def _assert_pair(results: dict[str, tuple[bool, bool, bool, str]]) -> None:
    for variant, (_fired, reached, returned, output) in results.items():
        assert reached, f"{variant}: the probe never reached the sink:\n{output}"
        assert returned, f"{variant}: the sink call never returned:\n{output}"
    assert results["vulnerable"][0], (
        "the vulnerable variant did not fire the oracle, so the manifest's "
        f"potentially_exploitable is not ground truth:\n{results['vulnerable'][3]}")
    assert not results["fixed"][0], (
        "the fixed variant fired the oracle, so the manifest's likely_not_exploitable is not "
        f"ground truth:\n{results['fixed'][3]}")


# --- JavaScript / TypeScript, ESM ----------------------------------------------------------
# The probe is a plain `node --test`-free script: the point is the corpus's behaviour, and
# bringing a runner into it would test the runner. It imports the .ts through node's own type
# stripping, which is why it needs a node new enough to have it.

_JS_PROBE = """import {{ renderComment }} from "{spec}";
const NONCE = '{nonce}';
const payload = `{payload}`;
console.log(`HARNESS_PRECONDITION::${{NONCE}}`);
const result = renderComment(payload);
console.log(`HARNESS_SINK_RETURNED::${{NONCE}}`);
if (String(result).includes(payload)) {{
  console.log(`HARNESS_ORACLE::${{NONCE}}`);
}}
"""


def _node_strips_types() -> bool:
    if not shutil.which("node"):
        return False
    probe = "type T = string; const x: T = 'ok'; console.log(x);"
    res = subprocess.run(["node", "--experimental-strip-types", "--eval", probe],
                         capture_output=True, text=True, timeout=60)
    return res.returncode == 0


def test_the_esm_typescript_pair_behaves_as_the_manifest_claims(tmp_path):
    """Executed, not read: the vulnerable variant returns the payload verbatim and the fixed one
    encodes it. This pair is the corpus's only ESM + TypeScript + vitest case, so without this
    its ground truth would be the only unverified truth in the corpus."""
    if not _node_strips_types():
        pytest.skip("no node with TypeScript type stripping available")
    results = {}
    for variant in ("vulnerable", "fixed"):
        root = CORPUS / "javascript" / "xssesm" / variant
        assert (root / "src/render.ts").is_file(), root
        work = tmp_path / variant
        shutil.copytree(root, work)
        # A probe file inside the package, so the package's own "type": "module" applies.
        (work / "test" / "probe.mts").write_text(
            _JS_PROBE.format(spec="../src/render.ts", nonce=NONCE, payload=PAYLOAD))
        results[variant] = _run(
            ["node", "--experimental-strip-types", "test/probe.mts"], work)
    _assert_pair(results)


def test_the_esm_typescript_pair_declares_vitest_and_esm(tmp_path):
    """The dimensions this case exists for, asserted rather than left to the file's shape."""
    for variant in ("vulnerable", "fixed"):
        manifest = json.loads(
            (CORPUS / "javascript" / "xssesm" / variant / "package.json").read_text())
        assert manifest["type"] == "module", variant
        assert "vitest" in manifest["scripts"]["test"], variant
        assert "jest" not in json.dumps(manifest), variant


# --- Perl, Test2::V0 -----------------------------------------------------------------------

_PERL_PROBE = """use strict; use warnings;
use lib 'lib';
use Test2::V0;
plan 1;
use Renderer;

my $NONCE = '{nonce}';
my $payload = "{payload}";
print "HARNESS_PRECONDITION::$NONCE\\n";
my $result = Renderer::render($payload);
print "HARNESS_SINK_RETURNED::$NONCE\\n";
print "HARNESS_ORACLE::$NONCE\\n" if index($result, $payload) >= 0;
ok(1);
"""


def _has_test2() -> bool:
    if not shutil.which("perl") or not shutil.which("prove"):
        return False
    return subprocess.run(["perl", "-MTest2::V0", "-e", "1"],
                          capture_output=True, timeout=60).returncode == 0


def test_the_test2_pair_behaves_as_the_manifest_claims(tmp_path):
    """Run through `prove -v -Ilib`, the command the recipe actually produces, with a probe whose
    plan is Test2's `plan 1;` — the form the validator used to reject. Both halves have to hold:
    the corpus's truth and the plan form's validity."""
    if not _has_test2():
        pytest.skip("no perl with Test2::V0 available")
    results = {}
    for variant in ("vulnerable", "fixed"):
        root = CORPUS / "perl" / "xss" / variant
        assert (root / "lib/Renderer.pm").is_file(), root
        work = tmp_path / variant
        shutil.copytree(root, work)
        (work / "t" / "probe.t").write_text(
            _PERL_PROBE.format(nonce=NONCE, payload=PAYLOAD))
        results[variant] = _run(["prove", "-v", "-Ilib", "t/probe.t"], work)
    _assert_pair(results)


def test_a_test2_plan_the_validator_accepts_is_the_one_prove_accepts():
    """The probe above uses `plan 1;` and no `done_testing`, so the validator and prove have to
    agree about it. They did not: `_PERL_PLAN` looked only for `done_testing`, `tests =>` and
    `no_plan`, so a correct Test2 probe was rejected and rewritten."""
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    probe = ProbeSource(test_file_path="t/probe.t",
                        content=_PERL_PROBE.format(nonce=NONCE, payload=PAYLOAD),
                        explanation="reference probe for the Test2::V0 corpus pair")
    assert "done_testing" not in probe.content
    assert _skipping_probe_violations(probe) == []


def test_the_test2_pair_declares_module_build_and_test2(tmp_path):
    for variant in ("vulnerable", "fixed"):
        build_pl = (CORPUS / "perl" / "xss" / variant / "Build.PL").read_text()
        assert "Module::Build" in build_pl and "Test2::V0" in build_pl, variant
        assert not (CORPUS / "perl" / "xss" / variant / "Makefile.PL").exists(), variant
        assert not (CORPUS / "perl" / "xss" / variant / "cpanfile").exists(), variant


def test_every_vendored_javascript_and_perl_case_has_a_ground_truth_check():
    """A case whose truth nothing verifies is a case that can be quietly wrong. Python has
    `test_corpus_oracle.py`; this names the JS and Perl cases still resting on a reading of the
    source, so adding one is a deliberate act rather than an omission.
    """
    from infosec_harness.evals.corpus import load_corpus

    verified = {"javascript-xssesm-vulnerable", "javascript-xssesm-fixed",
                "perl-xss-vulnerable", "perl-xss-fixed"}
    unverified = sorted(
        c.name for c in load_corpus()
        if c.language in ("javascript", "perl") and c.dataset == "seed"
        and c.name not in verified)
    assert unverified == [
        "javascript-cmdi-fixed", "javascript-cmdi-vulnerable",
        "javascript-xss-fixed", "javascript-xss-vulnerable",
        "perl-cmdi-fixed", "perl-cmdi-vulnerable",
        "perl-sqli-fixed", "perl-sqli-vulnerable",
    ], (
        "the set of JS/Perl corpus cases with no executed ground-truth check has changed. Add "
        f"the new case to this module, or to the expected list with a reason: {unverified}"
    )


def test_the_reference_probes_satisfy_the_production_probe_contract():
    """A reference probe the validator would reject is not a reference for anything."""
    from types import SimpleNamespace

    from infosec_harness.agents.validators import validate_probe
    from infosec_harness.domain.models import ProbeSource

    ctx = SimpleNamespace(deps=None)
    for path, content in (("test/probe.mts", _JS_PROBE.format(spec="../src/render.ts",
                                                              nonce=NONCE, payload=PAYLOAD)),
                          ("t/probe.t", _PERL_PROBE.format(nonce=NONCE, payload=PAYLOAD))):
        validate_probe(ctx, ProbeSource(test_file_path=path, content=content,
                                        explanation="reference probe"))
