"""A trivial test, written by us, that must run and be heard inside the prepared image.

The smoke test proves the image starts and the runner answers `--version`. Neither proves the
thing the whole verdict contract rests on: that a test file *we* wrote is discovered by the
project's own test command, and that its stdout reaches the harness. Everything between those
two facts -- the runner's discovery rules, the provider it selects, the selector syntax, a
project config that re-enables output capture -- is assumed today, and assumed per framework.

That assumption is how a framework discrepancy becomes a false negative. If the environment
plan names a provider or selector the project's framework does not use, a real probe compiles
and runs and prints nothing, `precondition_reached` is false, and the case is recorded as a
probe defect or a clean negative. Nothing says "your recipe cannot run any test here".

The canary says exactly that, and it does so **without knowing which frameworks exist**. It
writes a test that only prints the three markers, runs it through the project's real
`test_command`, and requires all three back. A recipe that cannot carry a marker cannot carry a
probe, whatever the toolchain is -- so this catches JUnit 4 answered as JUnit 5, vitest answered
as jest, Test2 answered as Test::More, and the combination nobody has encoded yet, identically
and at prepare time, where build repair can still act.

Known coupling, stated rather than hidden: the Java and JavaScript canaries must import *some*
framework to be discovered at all, so their content still depends on what the stack reports. If
that is wrong the canary fails to compile rather than failing silently -- and the captured
compiler error names the real framework, which is a far better signal than the silence it
replaces. Making the declared dependency the source of that choice is the detection fix, not
this gate's job.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

# Deliberately distinct from any finding's oracle nonce: this proves the transport, and must
# never be mistaken for evidence about a vulnerability.
CANARY_NONCE = "harness-canary-0000"
NEGATIVE_CANARY_NONCE = "harness-canary-negative-0000"
CONTROL_RESULT_PREFIX = "HARNESS_CONTROL_RESULT::"
CONTROL_PROTOCOL = "unit-probe-controls/v1"


@dataclass(frozen=True)
class ControlResult:
    """Controls executed through the same selector and adapter as a real probe."""

    positive: bool
    negative: bool
    status: str = "checked"
    version: str = CONTROL_PROTOCOL

    @property
    def passed(self) -> bool:
        return self.status == "checked" and self.positive and self.negative


def encode_control_result(result: ControlResult) -> str:
    payload = {
        "negative": result.negative,
        "positive": result.positive,
        "status": result.status,
        "version": result.version,
    }
    return CONTROL_RESULT_PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def parse_control_result(text: str) -> ControlResult | None:
    """Read the last control record; old histories without one remain explicitly legacy."""
    for line in reversed((text or "").splitlines()):
        if not line.startswith(CONTROL_RESULT_PREFIX):
            continue
        try:
            value = json.loads(line.removeprefix(CONTROL_RESULT_PREFIX))
            if value.get("version") != CONTROL_PROTOCOL:
                return None
            return ControlResult(
                positive=value.get("positive") is True,
                negative=value.get("negative") is True,
                status=str(value.get("status") or ""),
                version=str(value["version"]),
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
    return None

_CLASS_SELECTOR = re.compile(r"(?:-Dtest=|--tests\s+['\"]?\*?)([A-Za-z_$][\w$]*)")


def selector_class_name(test_command: str, default: str = "HarnessProbeTest") -> str:
    """The class name the test command selects, so the canary is the file it will look for.

    A JVM command selects by class, so a canary written to some other name is simply not run --
    which would look exactly like the failure this gate exists to detect, for the wrong reason.
    """
    match = _CLASS_SELECTOR.search(test_command or "")
    return match.group(1) if match else default


def _python(nonce: str, *, oracle: bool) -> tuple[str, str]:
    oracle_line = f'    print("HARNESS_ORACLE::{nonce}", flush=True)\n' if oracle else ""
    return "tests/test_harness_canary.py", f'''# Written by the harness. Proves a test we author is discovered and its stdout is heard.
def test_harness_canary():
    print("HARNESS_PRECONDITION::{nonce}", flush=True)
    print("HARNESS_SINK_RETURNED::{nonce}", flush=True)
{oracle_line.rstrip()}
'''


def _perl(nonce: str, *, oracle: bool) -> tuple[str, str]:
    oracle_line = f'print "HARNESS_ORACLE::{nonce}\\n";\n' if oracle else ""
    return "t/harness_canary.t", f'''use strict;
use warnings;
use Test::More tests => 1;

# Written by the harness. Proves a test we author is discovered and its stdout is heard.
print "HARNESS_PRECONDITION::{nonce}\\n";
print "HARNESS_SINK_RETURNED::{nonce}\\n";
{oracle_line.rstrip()}
ok(1, 'canary ran');
'''


def _javascript(nonce: str, *, oracle: bool) -> tuple[str, str]:
    oracle_line = f"  console.log('HARNESS_ORACLE::{nonce}');\n" if oracle else ""
    return "harness_canary.test.js", f'''// Written by the harness. Proves a test we author is discovered and its stdout is heard.
test('harness canary', () => {{
  console.log('HARNESS_PRECONDITION::{nonce}');
  console.log('HARNESS_SINK_RETURNED::{nonce}');
{oracle_line.rstrip()}
}});
'''


def _java(nonce: str, class_name: str, *, oracle: bool) -> tuple[str, str]:
    # No package declaration: a package would have to match the directory, and the default
    # package is discovered by every Surefire provider. JUnit 5's annotation is used because
    # that is what the current recipes assume; when the project is JUnit 4 this fails to
    # *compile*, and the error names `org.junit.jupiter` as missing -- which is the diagnosis.
    oracle_line = (f'        System.out.println("HARNESS_ORACLE::{nonce}");\n'
                   if oracle else "")
    return f"src/test/java/{class_name}.java", f'''import org.junit.jupiter.api.Test;

// Written by the harness. Proves a test we author is discovered and its stdout is heard.
public class {class_name} {{
    @Test
    public void harnessCanary() {{
        System.out.println("HARNESS_PRECONDITION::{nonce}");
        System.out.println("HARNESS_SINK_RETURNED::{nonce}");
{oracle_line.rstrip()}
    }}
}}
'''


def canary_for(language: str, test_command: str, *, nonce: str = CANARY_NONCE,
               oracle: bool = True,
               ) -> tuple[str, str] | None:
    """`(test_file_path, content)` for a language, or None when we cannot write one.

    None means "not checked", never "passed": a language this module has not learned must not
    fail preparation, and must not be reported as verified either.
    """
    lang = (language or "").lower()
    if lang == "python":
        return _python(nonce, oracle=oracle)
    if lang == "perl":
        return _perl(nonce, oracle=oracle)
    if lang in ("javascript", "typescript"):
        return _javascript(nonce, oracle=oracle)
    if lang in ("java", "kotlin"):
        return _java(nonce, selector_class_name(test_command), oracle=oracle)
    return None


def missing_markers(output: str, *, nonce: str = CANARY_NONCE) -> list[str]:
    """Which of the three markers did not survive the round trip."""
    return [name for name, prefix in (
        ("precondition", "HARNESS_PRECONDITION::"),
        ("sink_returned", "HARNESS_SINK_RETURNED::"),
        ("oracle", "HARNESS_ORACLE::"),
    ) if f"{prefix}{nonce}" not in output]


def explain(language: str, test_command: str, missing: list[str], output: str) -> str:
    """Why preparation is being failed, in terms build repair can act on."""
    return (
        f"The environment cannot run a test this harness writes. A canary {language} test that "
        f"only prints the three markers was executed with {test_command!r} and "
        f"{', '.join(missing)} did not reach stdout. Every probe depends on those markers, so a "
        f"real probe here would run, print nothing, and be recorded as having reached nothing -- "
        f"a false negative rather than an error. The fault is in the environment spec (the "
        f"runner's discovery rules, the provider or selector it names, or a project config that "
        f"re-enables output capture), not in any probe. Captured output:\n"
        f"{output[-1500:]}"
    )
