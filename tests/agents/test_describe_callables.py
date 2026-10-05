"""`describe_callables` against the real corpus, starting with the file that caused a false negative.

`eval-corpus/javascript/cmdi/vulnerable/src/cmd.js` ends `module.exports = { countLines }`. A probe
author wrote `const countLines = require("../src/cmd")`, bound the module object, and the call threw
inside a promise that resolved anyway; jest exited 0 and an exploitable finding was reported not
exploitable. Twice. The whole point of this tool is that the reach form it prints for that symbol is
a *destructuring* require, so these tests pin that first and the rest of the languages after it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.runtime import capabilities as caps
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.tools import symbols as symbol_inspection

CORPUS = Path(__file__).resolve().parents[2] / "eval-corpus"


def _describe(case: str, path: str) -> str:
    root = CORPUS / case
    assert root.is_dir(), f"corpus case {case} is missing"
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(root)))
    return symbol_inspection.describe_callables(ctx, path)


def _block(report: str, symbol: str) -> str:
    """The lines describing one symbol, so an assertion cannot be satisfied by another's text."""
    blocks = [b for b in report.split("\n\n") if b.startswith(symbol + " ")]
    assert len(blocks) == 1, f"expected exactly one block for {symbol!r} in:\n{report}"
    return blocks[0]


# --- the measured failure ----------------------------------------------------------------


def test_the_javascript_named_export_is_reported_as_named_and_destructured():
    report = _describe("javascript/cmdi/vulnerable", "src/cmd.js")
    block = _block(report, "countLines")

    assert "export=named" in block
    assert "export=default" not in block
    # The reach form must be a destructuring require, not a default binding.
    assert 'const { countLines } = require("./src/cmd");' in block
    assert "const countLines = require(" not in report, (
        "the tool must never print the default-import form for a named export"
    )
    assert "kind=function" in block and "params=(path, cb)" in block


def test_the_javascript_report_says_why_a_default_import_would_fail():
    """A reach form the agent does not understand is a reach form the agent will "improve"."""
    block = _block(_describe("javascript/cmdi/vulnerable", "src/cmd.js"), "countLines")
    assert "NAMED export" in block
    assert "module OBJECT" in block


def test_a_javascript_default_export_is_not_destructured(tmp_path):
    """The inverse error: `module.exports = fn` must not be reported as a named export."""
    (tmp_path / "solo.js").write_text("function only(a) { return a; }\nmodule.exports = only;\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    block = _block(symbol_inspection.describe_callables(ctx, "solo.js"), "only")
    assert "export=default" in block
    assert 'const only = require("./solo");' in block
    assert "{ only }" not in block


# --- the module systems and dialects this tool has to survive ----------------------------
#
# This tool exists to stop one false negative, so a file it *refuses* is the worst outcome
# available: the probe author then writes the import from memory, which is the exact mistake.


@pytest.mark.parametrize("name", ["render.ts", "render.tsx", "render.mts", "render.cts"])
def test_typescript_is_described_rather_than_refused(tmp_path, name):
    """`.ts` was absent from _LANG_BY_SUFFIX, so this tool raised ModelRetry on every file in a
    TypeScript repository — while `detect_stack` happily classified the repo as `typescript` and
    the plan sent it to jest. The declaration forms the scanner matches are spelled identically
    in TypeScript; only the annotations differ, and they sit inside the parameter list."""
    (tmp_path / name).write_text(
        "export function renderComment(text: string): string {\n"
        '  return "<div>" + text + "</div>";\n}\n'
    )
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, name)
    block = _block(report, "renderComment")
    assert "export=named" in block
    # Extensionless: `./render.ts` is what ts-jest and tsc's own resolver reject.
    assert 'import { renderComment } from "./render";' in block
    assert "TypeScript source" in report and "compiles TS" in report


def test_an_esm_specifier_keeps_its_extension(tmp_path):
    """Measured under node 18/20/22: `import { x } from "../src/render"` in a `"type": "module"`
    package dies with ERR_MODULE_NOT_FOUND under `node --test` and plain node, because node's
    ESM resolver does no extension guessing. vitest and jest's vm-modules mode forgive it, so
    printing the form that works under every runner is strictly better than printing the other."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src/render.js").write_text(
        'export function renderComment(t) { return "<div>" + t + "</div>"; }\n'
    )
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "src/render.js")
    assert 'import { renderComment } from "./src/render.js";' in report
    assert 'from "./src/render"' not in report.replace('from "./src/render.js"', "")
    assert "ERR_MODULE_NOT_FOUND" in report


def test_a_commonjs_require_specifier_stays_extensionless(tmp_path):
    """CommonJS resolution *does* guess, and the corpus case this tool was built for is CJS: the
    require form must not acquire an extension just because ESM needs one."""
    (tmp_path / "cmd.js").write_text(
        "function countLines(p) { return p; }\nmodule.exports = { countLines };\n"
    )
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "cmd.js")
    assert 'const { countLines } = require("./cmd");' in report


def test_an_mjs_module_keeps_the_mjs_extension(tmp_path):
    (tmp_path / "render.mjs").write_text("export function render(t) { return t; }\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    assert 'from "./render.mjs"' in symbol_inspection.describe_callables(ctx, "render.mjs")


# --- one file per corpus language --------------------------------------------------------


def test_python_is_parsed_not_guessed():
    report = _describe("python/sqli/vulnerable", "app.py")
    assert "language=python" in report
    assert "parsed with Python's `ast`" in report and "CERTAIN" in report
    block = _block(report, "get_user")
    assert "kind=function" in block
    assert "params=(conn, name)" in block
    assert "from app import get_user" in block
    assert "no instance needed" in block


def test_python_reports_a_method_as_needing_an_instance(tmp_path):
    (tmp_path / "svc.py").write_text(
        "class Svc:\n"
        "    def __init__(self, base):\n"
        "        self.base = base\n"
        "    def read(self, name):\n"
        "        return open(self.base + name).read()\n"
    )
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "svc.py")
    assert "kind=class" in _block(report, "Svc")
    method = _block(report, "Svc.read")
    assert "kind=method" in method
    assert "needs an instance" in method
    assert "Svc(base).read(name)" in method


def test_java_reports_the_fully_qualified_class_and_the_instance_call():
    report = _describe("java/cmdi/vulnerable", "src/main/java/com/example/Runner.java")
    assert "language=java" in report
    assert "package: com.example" in report
    assert "heuristic text scan" in report
    block = _block(report, "Runner.run")
    assert "kind=method" in block
    assert "params=(String arg)" in block
    assert "import com.example.Runner;" in block
    assert "new Runner(...).run(...)" in block
    assert "needs an instance" in block


def test_perl_reports_a_non_exported_sub_as_fully_qualified():
    report = _describe("perl/cmdi/vulnerable", "lib/Runner.pm")
    assert "language=perl" in report
    assert "package: Runner" in report
    assert "no Exporter found" in report
    block = _block(report, "Runner::run")
    assert "export=not exported" in block
    assert "params=($arg)" in block
    assert "Runner::run(...)" in block
    assert "FULLY QUALIFIED" in block


def test_perl_distinguishes_export_from_export_ok_from_neither(tmp_path):
    (tmp_path / "Ex.pm").write_text(
        "package Ex;\nuse Exporter 'import';\n"
        "our @EXPORT = qw(always);\nour @EXPORT_OK = qw(maybe);\n"
        "sub always { my ($x) = @_; return $x; }\n"
        "sub maybe { my ($y) = @_; return $y; }\n"
        "sub hidden { my ($w) = @_; return $w; }\n1;\n"
    )
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "Ex.pm")
    assert "use Ex;  ->  always(...)" in _block(report, "Ex::always")
    maybe = _block(report, "Ex::maybe")
    assert "use Ex qw(maybe);" in maybe and "does not import it" in maybe
    assert "Ex::hidden(...)" in _block(report, "Ex::hidden")


# --- honesty about what was and was not found --------------------------------------------


def test_every_language_states_what_is_certain_and_what_is_inferred():
    for case, path in [
        ("python/sqli/vulnerable", "app.py"),
        ("javascript/cmdi/vulnerable", "src/cmd.js"),
        ("java/cmdi/vulnerable", "src/main/java/com/example/Runner.java"),
        ("perl/cmdi/vulnerable", "lib/Runner.pm"),
    ]:
        report = _describe(case, path)
        certainty = next(ln for ln in report.splitlines() if ln.startswith("certainty:"))
        assert "CERTAIN" in certainty, certainty
        assert "INFERRED" in certainty or "`ast`" in certainty, certainty


def test_a_file_with_no_callables_says_so_rather_than_inventing_one(tmp_path):
    (tmp_path / "consts.py").write_text('BASE = "/tmp"\nLIMIT = 5\n')
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "consts.py")
    assert "symbols found: 0" in report
    assert "no callable symbols found" in report
    assert "reach:" not in report


def test_unparseable_python_reports_nothing_instead_of_guessing(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n    pass\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "broken.py")
    assert "symbols found: 0" in report
    assert "`ast` refused this file" in report
    assert "reach:" not in report


def test_an_unsupported_extension_is_refused_rather_than_scanned_as_a_guess():
    """requirements.txt is a real corpus file; pretending to parse it would be a lie."""
    with pytest.raises(ModelRetry, match="no supported extension"):
        _describe("python/cmdi/vulnerable", "requirements.txt")


# --- a retry the model can act on --------------------------------------------------------
# java-sqli-vulnerable aborted in a live run with "Tool 'describe_callables' exceeded max
# retries count of 2": the model kept passing something that is not a repo-relative file path
# and every retry said only that it "does not exist". A retry that does not name the corrected
# value cannot end the loop, so each shape below asserts the message names the file to call.

JAVA_CASE = "java/sqli/vulnerable"
JAVA_FILE = "src/main/java/com/example/UserDao.java"


def _retry_message(case: str, path: str) -> str:
    with pytest.raises(ModelRetry) as excinfo:
        _describe(case, path)
    return str(excinfo.value)


def test_a_fully_qualified_class_name_is_answered_with_the_file_that_defines_it():
    """`com.example.UserDao` is the single likeliest wrong argument for a Java finding."""
    message = _retry_message(JAVA_CASE, "com.example.UserDao")
    assert JAVA_FILE in message, message
    assert "not a class or package name" in message


@pytest.mark.parametrize(
    "wrong",
    [
        "UserDao",  # bare type name
        "com/example/UserDao",  # package path, extension dropped
        "com/example/UserDao.java",  # right file, wrong depth (the source root is stripped)
        "UserDao.class",  # the compiled artefact instead of the source
    ],
)
def test_a_path_that_points_at_the_right_file_by_the_wrong_route_names_that_file(wrong):
    message = _retry_message(JAVA_CASE, wrong)
    assert JAVA_FILE in message, message
    assert "exactly that path" in message


def test_a_filename_with_a_real_extension_is_not_called_a_class_name():
    """The corrective clause has to fit the mistake actually made."""
    assert "not a class or package name" not in _retry_message(JAVA_CASE, "UserDao.java")


def test_an_absolute_path_is_answered_with_its_repo_relative_form():
    absolute = str(CORPUS / JAVA_CASE / JAVA_FILE)
    message = _retry_message(JAVA_CASE, absolute)
    assert "is an absolute path" in message
    assert f"Call describe_callables with {JAVA_FILE!r}" in message, message


def test_a_directory_is_answered_with_the_files_inside_it():
    message = _retry_message(JAVA_CASE, "src/main/java/com/example")
    assert "is a directory" in message
    assert JAVA_FILE in message, message


def test_a_directory_with_no_source_in_it_points_at_list_files(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.txt").write_text("nothing callable here\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    with pytest.raises(ModelRetry) as excinfo:
        symbol_inspection.describe_callables(ctx, "docs")
    message = str(excinfo.value)
    assert "list_files('docs')" in message, message
    assert "read_file" in message


def test_a_name_that_matches_nothing_still_names_the_sources_it_could_parse():
    message = _retry_message(JAVA_CASE, "com.example.Nope")
    assert JAVA_FILE in message, message


def test_an_ambiguous_name_lists_every_match_instead_of_picking_one():
    """Two snapshots of the same class live under eval-corpus/java/sqli; guessing would be a lie."""
    message = _retry_message("java/sqli", "com.example.UserDao")
    assert f"vulnerable/{JAVA_FILE}" in message, message
    assert f"fixed/{JAVA_FILE}" in message, message
    assert "whichever one the finding points at" in message


def test_an_unsupported_extension_names_the_source_with_the_same_stem(tmp_path):
    (tmp_path / "UserDao.java").write_text("package com.example;\npublic class UserDao {}\n")
    (tmp_path / "UserDao.txt").write_text("notes about UserDao\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    with pytest.raises(ModelRetry) as excinfo:
        symbol_inspection.describe_callables(ctx, "UserDao.txt")
    message = str(excinfo.value)
    assert "no supported extension" in message
    assert "read_file('UserDao.txt')" in message
    assert "'UserDao.java'" in message, message


def test_a_path_outside_the_root_is_never_named_back_to_the_model():
    """The confinement boundary: the message may not say what does or does not exist outside."""
    message = _retry_message(JAVA_CASE, "/etc/passwd")
    assert "does not exist in the repository" in message
    assert "Call describe_callables with '/" not in message
    assert str(CORPUS) not in message


# --- the same confinement as the other read tools ----------------------------------------


@pytest.mark.parametrize("bad", ["../../etc/passwd", "src/../../../etc/hosts", "/etc/passwd"])
def test_path_escape_is_rejected_like_read_file(bad):
    with pytest.raises(ModelRetry):
        _describe("javascript/cmdi/vulnerable", bad)


def test_a_missing_path_inside_the_root_is_a_retry_not_a_crash():
    with pytest.raises(ModelRetry, match="does not exist"):
        _describe("javascript/cmdi/vulnerable", "src/nope.js")


def test_output_stays_inside_the_declared_toolset_bound(tmp_path):
    """max_output_bytes in tool.yaml has to remain truthful for a hostile-sized file."""
    body = "".join(
        f"def f{i}({', '.join(f'a{j}' for j in range(40))}):\n    pass\n" for i in range(500)
    )
    (tmp_path / "huge.py").write_text(body)
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "huge.py")
    from infosec_harness.tools.policies import load_policies

    assert len(report.encode()) <= load_policies()["repo-read-only"].max_output_bytes
    assert f"showing the first {symbol_inspection.MAX_SYMBOLS}" in report


# --- registration ------------------------------------------------------------------------


def test_the_tool_is_on_the_stable_repo_ro_toolset_instance():
    """A fresh toolset per call is rejected as a runtime addition under Temporal."""
    first = caps.RepoReadOnly().get_toolset()
    assert first is caps.RepoReadOnly().get_toolset()
    assert first.id == "repo_ro"
    assert "describe_callables" in first.tools


def test_the_tool_policy_declares_the_new_tool_as_a_read():
    from infosec_harness.tools.policies import ToolEffect, load_policies

    policy = load_policies()["repo-read-only"]
    tool = next(t for t in policy.tools if t.name == "describe_callables")
    assert tool.effect is ToolEffect.read


@pytest.mark.parametrize("agent", ["context", "probe-author", "probe-repair"])
def test_the_agents_that_need_it_are_told_to_use_it_imperatively(agent):
    """A descriptive mention gets ignored; the instruction has to be an order."""
    from infosec_harness.runtime.registry import load_spec

    text = "\n".join(load_spec(agent).instructions or [])
    tool = "describe_callables" if agent == "context" else "inspect_target"
    assert tool in text, f"{agent} is not told the tool exists"
    assert f"Call `{tool}`" in text or f"call `{tool}`" in text


def test_a_file_larger_than_the_read_cap_is_described_from_its_first_bytes_only(
        tmp_path, monkeypatch):
    """Regression: describe_callables read the whole file with `read_text()`, bypassing
    MAX_FILE_BYTES, so a multi-gigabyte file was loaded into the worker to describe it."""
    from infosec_harness.tools import repository as repo_tools

    monkeypatch.setattr(repo_tools, "MAX_FILE_BYTES", 64)
    monkeypatch.setattr(symbol_inspection, "MAX_FILE_BYTES", 64)
    (tmp_path / "big.py").write_text("def early(a):\n    pass\n" + "x = 1\n" * 50
                                     + "def late(b):\n    pass\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    report = symbol_inspection.describe_callables(ctx, "big.py")
    assert "early" in report and "late" not in report
    assert "larger than 64 bytes" in report
