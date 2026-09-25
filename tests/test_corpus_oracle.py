"""The seeded corpus's ground truth is *true*: the vulnerable variants really are exploitable.

`test_corpus.py` checks the corpus is internally consistent (the finding points at real
code, the sink line matches the weakness). That is structural — it would still pass if a
"vulnerable" variant had been accidentally written safe, and every expected verdict in the
manifest would then be wrong without anything failing.

These tests close that gap for Python by driving each paired variant with a reference probe
written to the real marker protocol (`skills/probe-oracle-protocol/SKILL.md`) and reading
the result through the harness's own `oracle_signals`. The vulnerable variant must fire the
oracle and the fixed variant must not, with both reaching the precondition — exactly the
signal the graph triages on.

These run in-process rather than in the sandbox, so they assert the *corpus* is sound, not
that the container isolation is. Sandbox behaviour is covered by `test_sandbox*.py` and, at
runtime, by a gVisor host.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import uuid
from pathlib import Path

import pytest

from infosec_harness.sandbox.docker import ORACLE_PREFIX, PRECONDITION_PREFIX, oracle_signals
from infosec_harness.settings import REPO_ROOT

CORPUS = REPO_ROOT / "eval-corpus" / "python"


def _load(case: str, variant: str):
    path = CORPUS / case / variant / "app.py"
    spec = importlib.util.spec_from_file_location(f"corpus_{case}_{variant}_{uuid.uuid4().hex}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _probe_sqli(mod, nonce: str) -> None:
    conn = mod.init_db()
    print(f"{PRECONDITION_PREFIX}{nonce}")
    rows = mod.get_user(conn, "alice' OR '1'='1")
    # Oracle: the payload changed the query's structure, so a row the filter should have
    # excluded came back. Not "the string looked like SQL".
    if any("TOP-SECRET" in str(row) for row in rows):
        print(f"{ORACLE_PREFIX}{nonce}")


def _probe_cmdi(mod, nonce: str) -> None:
    canary = Path(tempfile.gettempdir()) / f"harness_canary_{nonce}"
    print(f"{PRECONDITION_PREFIX}{nonce}")
    with contextlib.suppress(Exception):
        mod.count_lines(f"/dev/null; touch {canary}")
    # Oracle: the injected command actually ran (canary_file form).
    if canary.exists():
        print(f"{ORACLE_PREFIX}{nonce}")
        canary.unlink()


def _probe_pathtraversal(mod, nonce: str) -> None:
    # Plant a file the document root must not reach, then traverse to it. Using a file we
    # created keeps the oracle independent of whatever the host has in /etc.
    outside = Path(mod.BASE).parent / f"outside_{nonce}.txt"
    outside.write_bytes(f"SECRET-{nonce}".encode())
    try:
        print(f"{PRECONDITION_PREFIX}{nonce}")
        data = b""
        with contextlib.suppress(Exception):
            data = mod.read_doc(f"../{outside.name}")
        # Oracle: a file outside the document root was read.
        if f"SECRET-{nonce}".encode() in data:
            print(f"{ORACLE_PREFIX}{nonce}")
    finally:
        outside.unlink(missing_ok=True)


def _probe_xss(mod, nonce: str) -> None:
    print(f"{PRECONDITION_PREFIX}{nonce}")
    rendered = str(mod.render_comment(f"<script>{nonce}</script>"))
    # Oracle: the tag survived into the output unencoded.
    if f"<script>{nonce}</script>" in rendered:
        print(f"{ORACLE_PREFIX}{nonce}")


PROBES = {"sqli": _probe_sqli, "cmdi": _probe_cmdi,
          "pathtraversal": _probe_pathtraversal, "xss": _probe_xss}
PAIRS = [(case, variant, variant == "vulnerable")
         for case in PROBES for variant in ("vulnerable", "fixed")]


def _run_probe(case: str, variant: str) -> tuple[bool, bool]:
    nonce = uuid.uuid4().hex
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        PROBES[case](_load(case, variant), nonce)
    return oracle_signals(captured.getvalue(), nonce)


@pytest.mark.parametrize(("case", "variant", "should_fire"), PAIRS,
                         ids=[f"{c}-{v}" for c, v, _ in PAIRS])
def test_variant_fires_the_oracle_only_when_it_is_vulnerable(case, variant, should_fire):
    fired, reached = _run_probe(case, variant)
    assert reached, f"{case}/{variant}: probe never reached the sink — it proves nothing"
    assert fired is should_fire, (
        f"{case}/{variant}: oracle_fired={fired}, expected {should_fire}. The corpus's "
        f"ground truth says this variant is {'exploitable' if should_fire else 'safe'}."
    )


def test_every_python_cwe_directory_has_a_reference_probe():
    """A new CWE case must come with a probe here, or its ground truth stays unchecked."""
    on_disk = {d.name for d in CORPUS.iterdir()
               if d.is_dir() and (d / "fixed").exists()}
    assert on_disk == set(PROBES), f"no reference probe for: {sorted(on_disk - set(PROBES))}"
