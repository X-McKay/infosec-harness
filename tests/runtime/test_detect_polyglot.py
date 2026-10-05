"""What `detect_stack` says about JavaScript and Perl repositories that are not the default shape.

The harness has to work on *any* JS or Perl codebase, and the fingerprint is the first thing that
decides: `_primary_language` picks the env-plan branch and `test_frameworks[0]` is what recon
reports as the framework, which selects the probe template and the test command. Every case here
was built as a real fixture and run with real node (18/20/22) or real perl 5.34 + prove 3.43
before being pinned; the docstrings say what the run showed.
"""

from __future__ import annotations

import json

import pytest

from infosec_harness.agents.stubs import _env_plan
from infosec_harness.domain.models import RepoSnapshot
from infosec_harness.graph.ops import LocalOps
from infosec_harness.graph.prepare import run_prepare
from infosec_harness.repo.components import component_stack, owning_component, preparation_key
from infosec_harness.repo.detect import detect_stack, js_test_runners

CJS = "function renderComment(t) { return '<div>' + t + '</div>'; }\nmodule.exports = { renderComment };\n"
ESM = "export function renderComment(t) { return '<div>' + t + '</div>'; }\n"
RUNNER_PM = ("package Runner;\nuse strict;\nuse warnings;\n"
             "sub render { my ($t) = @_; return \"<div>\" . $t . \"</div>\"; }\n1;\n")


def _pkg(tmp_path, **fields):
    (tmp_path / "package.json").write_text(json.dumps({"name": "f", "private": True, **fields}))


def _plan(tmp_path) -> dict:
    return _env_plan(detect_stack(str(tmp_path)).model_dump())


def test_polyglot_manifests_produce_separate_component_contracts(tmp_path):
    py = tmp_path / "services" / "api"
    js = tmp_path / "web"
    py.mkdir(parents=True)
    js.mkdir()
    (py / "pyproject.toml").write_text("[project]\nname='api'\n")
    (py / "app.py").write_text("x = 1\n")
    (js / "package.json").write_text('{"scripts":{"test":"node --test"}}')
    (js / "app.mjs").write_text("export const x = 1;\n")

    components = {component.root: component for component in detect_stack(str(tmp_path)).components}

    assert components["services/api"].languages == {"python": 1}
    assert components["services/api"].build_systems == ["python"]
    assert components["web"].languages == {"javascript": 1}
    assert components["web"].build_systems == ["npm"]
    assert all(component.support.value == "experimental" for component in components.values())

    api = owning_component(detect_stack(str(tmp_path)), "services/api/app.py")
    web = owning_component(detect_stack(str(tmp_path)), "web/app.mjs")
    assert api is not None and preparation_key(api) == "services/api"
    assert web is not None and preparation_key(web) == "web"
    assert owning_component(detect_stack(str(tmp_path)), "README.md") is None


async def test_component_preparation_uses_separate_stack_and_workdir(tmp_path):
    py = tmp_path / "services" / "api"
    js = tmp_path / "web"
    py.mkdir(parents=True)
    js.mkdir()
    (py / "pyproject.toml").write_text("[project]\nname='api'\n")
    (py / "app.py").write_text("x = 1\n")
    (js / "package.json").write_text('{"scripts":{"test":"node --test"}}')
    (js / "app.mjs").write_text("export const x = 1;\n")
    stack = detect_stack(str(tmp_path))
    snapshot = RepoSnapshot(
        repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="component",
    )
    ops = LocalOps(sandbox=False, recipe_cache=False)

    prepared = {}
    for path in ("services/api/app.py", "web/app.mjs"):
        component = owning_component(stack, path)
        assert component is not None
        outcome = await run_prepare(
            ops, snapshot, component_stack(stack, component), component_root=component.root)
        prepared[component.root] = outcome.prepared

    assert prepared["services/api"].stack.languages == {"python": 1}
    assert prepared["web"].stack.languages == {"javascript": 1}
    assert prepared["services/api"].build.spec.module_path == "services/api"
    assert prepared["web"].build.spec.module_path == "web"
    assert prepared["services/api"].build.spec.scope == "partial"
    assert prepared["web"].build.spec.scope == "partial"


async def test_resolved_nested_component_rebinds_once(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from infosec_harness.domain.models import (
        BuildResult,
        CodeLocation,
        ComponentProfile,
        EnvironmentSpec,
        Finding,
        FindingSourceKind,
        PreparedEnvironment,
        StackFingerprint,
    )
    from infosec_harness.graph import prepare as prepare_module

    api = ComponentProfile(root="services/api", languages={"python": 3},
                           manifest_paths=["services/api/pyproject.toml"],
                           build_systems=["python"])
    web = ComponentProfile(root="web", languages={"javascript": 2},
                           manifest_paths=["web/package.json"], build_systems=["npm"])
    stack = StackFingerprint(languages={"python": 3, "javascript": 2},
                             test_dirs=["services/api/tests", "web/test"],
                             components=[api, web])
    snapshot = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path),
                            content_hash="resolved-component")

    def environment(module_path=None):
        spec = EnvironmentSpec(base_image="python:3.12-slim", test_command="pytest {test_file}",
                               scope="partial" if module_path else "full",
                               module_path=module_path)
        return PreparedEnvironment(snapshot=snapshot, stack=stack,
                                   build=BuildResult(ok=True, image_tag="fixture", spec=spec),
                                   status="ready")

    finding = Finding(fingerprint="resolved", title="Resolved from prose", repo_url=str(tmp_path),
                      revision="HEAD", location=CodeLocation(file_path="services/api/app.py"),
                      source_kind=FindingSourceKind.generic_json)
    sentinel = SimpleNamespace(prepared=environment("services/api"), invocations=[])
    calls = []

    async def fake_run_prepare(ops, got_snapshot, got_stack, *, component_root):
        calls.append((got_snapshot, got_stack, component_root))
        return sentinel

    monkeypatch.setattr(prepare_module, "run_prepare", fake_run_prepare)
    rebound = await prepare_module.prepare_resolved_component(object(), finding, environment())

    assert rebound is sentinel
    assert calls[0][0] == snapshot
    assert calls[0][1].languages == {"python": 3}
    assert calls[0][2] == "services/api"

    # A repository-wide planner may coincidentally choose the resolved component's path. Its
    # full polyglot stack still needs rebinding to the component-local discovery contract.
    assert await prepare_module.prepare_resolved_component(
        object(), finding, environment("services/api")) is sentinel
    assert len(calls) == 2

    narrowed = component_stack(stack, api)
    assert narrowed.test_dirs == ["tests"]
    already_bound = environment("services/api").model_copy(update={"stack": narrowed})
    assert await prepare_module.prepare_resolved_component(
        object(), finding, already_bound) is None
    assert len(calls) == 2


# --- language counting ---------------------------------------------------------------------

def test_a_pure_esm_package_is_still_javascript(tmp_path):
    """`.mjs` was absent from EXT_LANG, so a package that renamed every file to .mjs counted
    ZERO javascript files. `_primary_language` then answered "unknown" and the plan fell all the
    way through to `sh {test_file}` with no install commands at all — the whole Node branch
    skipped for a Node project."""
    _pkg(tmp_path, type="module")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/render.mjs").write_text(ESM)

    stack = detect_stack(str(tmp_path))
    assert stack.languages.get("javascript") == 1
    assert _plan(tmp_path)["base_image"] == "node:22-slim"
    assert "{test_file}" in _plan(tmp_path)["test_command"]


def test_a_cjs_only_package_is_javascript_too(tmp_path):
    _pkg(tmp_path)
    (tmp_path / "lib.cjs").write_text(CJS)
    assert detect_stack(str(tmp_path)).languages.get("javascript") == 1


# --- which Node runner ---------------------------------------------------------------------

@pytest.mark.parametrize(
    ("script", "dev_deps", "expected"),
    [("jest", {"jest": "^29"}, "jest"),
     ("vitest run", {"vitest": "^2"}, "vitest"),
     ("mocha", {"mocha": "^10"}, "mocha"),
     ("node --test", {}, "node:test"),
     ("tsx --test", {"tsx": "^4"}, "node:test")],
)
def test_the_runner_a_project_declares_is_the_one_reported(tmp_path, script, dev_deps, expected):
    """mocha and node's own runner were detected by nothing, so a project using either reported
    an empty `test_frameworks`, recon answered "unknown", and the plan still said `npx jest` —
    which in an offline container exits 1 with `npx canceled due to missing packages`."""
    _pkg(tmp_path, scripts={"test": script}, devDependencies=dev_deps)
    (tmp_path / "src.js").write_text(CJS)
    assert detect_stack(str(tmp_path)).test_frameworks[:1] == [expected]


def test_a_migration_carrying_both_runners_reports_the_one_its_test_script_uses(tmp_path):
    """A repo mid-migration has jest and vitest side by side. Sorted order answers "jest", and
    `npx vitest run --runTestsByPath <path>` — or `npx jest` where only vitest is installed —
    costs the whole run. recon reads `test_frameworks[0]`, so the ordering is the fix."""
    _pkg(tmp_path, scripts={"test": "vitest run"},
         devDependencies={"jest": "^29", "vitest": "^2"})
    (tmp_path / "src.js").write_text(CJS)

    frameworks = detect_stack(str(tmp_path)).test_frameworks
    assert frameworks[0] == "vitest" and "jest" in frameworks
    assert _plan(tmp_path)["test_command"] == "npx vitest run --silent=false {test_file}"


def test_a_node_test_project_with_no_script_is_found_from_its_test_files(tmp_path):
    """`node --test` is not a package, so nothing in package.json names it."""
    _pkg(tmp_path)
    (tmp_path / "test").mkdir()
    (tmp_path / "test/probe.test.js").write_text(
        "const test = require('node:test');\ntest('x', () => {});\n")
    assert js_test_runners(tmp_path) == ["node:test"]


def test_a_runner_is_not_invented_from_an_unrelated_dependency(tmp_path):
    """`ava` and `tap` as bare substrings match "available", "java" and "tapable". A runner named
    by accident is worse than one not named: the plan would build a command for it."""
    _pkg(tmp_path, devDependencies={"tapable": "^2", "available-typed-arrays": "^1"})
    assert js_test_runners(tmp_path) == []


# --- the plan the fingerprint produces -----------------------------------------------------

def test_the_node_plan_carries_the_silencing_defeat_for_the_runners_that_need_it(tmp_path):
    """Measured: a project `jest.config.js`/`vitest.config.js` with `silent: true` erases all
    three HARNESS_ markers while the run exits 0. mocha and node:test never capture stdout."""
    for script, dev_deps, expected in (
        ("jest", {"jest": "^29"}, "npx jest --silent=false --runTestsByPath {test_file}"),
        ("vitest run", {"vitest": "^2"}, "npx vitest run --silent=false {test_file}"),
        ("mocha", {"mocha": "^10"}, "npx mocha {test_file}"),
        ("node --test", {}, "node --test {test_file}"),
    ):
        _pkg(tmp_path, scripts={"test": script}, devDependencies=dev_deps)
        (tmp_path / "src.js").write_text(CJS)
        assert _plan(tmp_path)["test_command"] == expected, script


def test_a_lockfile_makes_the_install_reproducible(tmp_path):
    _pkg(tmp_path, scripts={"test": "jest"}, devDependencies={"jest": "^29"})
    (tmp_path / "src.js").write_text(CJS)
    assert _plan(tmp_path)["install_commands"] == ["npm install --no-audit --no-fund"]
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    assert _plan(tmp_path)["install_commands"] == ["npm ci --no-audit --no-fund"]


def test_a_typescript_project_gets_a_runner_that_can_compile_it(tmp_path):
    """A bare `npx jest` on a `.ts` probe fails to parse it — the default babel transform has no
    TypeScript plugin — and the run reports `Tests: 1 failed` having executed nothing of the
    probe. Measured working alternatives: `--preset ts-jest` with @types/jest installed, vitest
    with no configuration at all, and `npx tsx --test` for node's runner."""
    _pkg(tmp_path, scripts={"test": "jest"}, devDependencies={"jest": "^29"})
    (tmp_path / "src.ts").write_text("export function f(t: string): string { return t; }\n")
    plan = _plan(tmp_path)
    assert "--preset ts-jest" in plan["test_command"]
    assert any("ts-jest" in c and "@types/jest" in c for c in plan["install_commands"])

    _pkg(tmp_path, scripts={"test": "vitest run"}, devDependencies={"vitest": "^2"})
    assert _plan(tmp_path)["test_command"] == "npx vitest run --silent=false {test_file}"

    _pkg(tmp_path, scripts={"test": "node --test"})
    plan = _plan(tmp_path)
    assert plan["test_command"] == "npx tsx --test {test_file}"
    assert any("tsx" in c for c in plan["install_commands"])


# --- Perl ----------------------------------------------------------------------------------

def _perl_repo(tmp_path, t_body: str, **files):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib/Runner.pm").write_text(RUNNER_PM)
    (tmp_path / "t").mkdir()
    (tmp_path / "t/probe.t").write_text(t_body)
    for name, body in files.items():
        (tmp_path / name.replace("__", ".")).write_text(body)


def test_a_test2_distribution_is_not_reported_as_test_more(tmp_path):
    """Every Perl repo was reported as Test::More regardless of what its `t/` actually used.
    A Test2::V0 script declares its plan as `plan 1;` — Test2 has no `tests =>` spelling — so
    naming the wrong dialect points the author at a template whose plan form was then rejected."""
    _perl_repo(tmp_path, "use Test2::V0;\nplan 1;\nok(1);\n", cpanfile="requires 'Test2::V0';\n")
    assert detect_stack(str(tmp_path)).test_frameworks[:1] == ["Test2::V0"]


def test_a_test_more_distribution_still_reports_test_more(tmp_path):
    _perl_repo(tmp_path, "use Test::More;\nok(1);\ndone_testing();\n")
    assert detect_stack(str(tmp_path)).test_frameworks[:1] == ["Test::More"]


def test_an_empty_test_dir_falls_back_to_test_more_rather_than_nothing(tmp_path):
    """Test::More is the ecosystem default and the probe author needs *some* template named; a
    repository with an empty `t/` must not report no framework at all."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib/Runner.pm").write_text(RUNNER_PM)
    (tmp_path / "t").mkdir()
    assert detect_stack(str(tmp_path)).test_frameworks[:1] == ["Test::More"]


def test_a_module_build_distribution_reports_a_build_system(tmp_path):
    """Build.PL was in MANIFESTS but not in BUILD_SYSTEM, so a Module::Build distribution
    reported `build_systems: []` while the plan ran cpanm against it anyway."""
    _perl_repo(tmp_path, "use Test::More;\nok(1);\ndone_testing();\n",
               Build__PL="use Module::Build;\n")
    stack = detect_stack(str(tmp_path))
    assert stack.build_systems == ["cpanm"] and "Build.PL" in stack.manifests


# --- how the stub diagnosis reads a Node failure -------------------------------------------

def test_the_node_failures_that_only_build_repair_can_fix_are_named_as_environment_issues():
    """Both were measured as exit-1 runs with no test output at all, which the stub used to read
    as a probe defect — routing repair to the stage that can rewrite a probe but install nothing.

    `npx canceled due to missing packages` is what an offline container does when the spec names
    a runner the project never declared; the jest validation error is what a `jest.config.js`
    naming `testEnvironment: 'jsdom'` does when jest-environment-jsdom (removed from jest core in
    28) was not installed.
    """
    from infosec_harness.agents.stubs import _diagnosis

    for stderr in ('npm error npx canceled due to missing packages and no YES option: '
                   '["jest@30.5.2"]',
                   "● Validation Error:\n\n  Test environment jest-environment-jsdom cannot be "
                   "found. Make sure the testEnvironment configuration option points to an "
                   "existing node module."):
        text = ("<probe_execution>\n"
                + json.dumps({"attempt": 1, "exit_code": 1, "oracle_fired": False,
                              "precondition_reached": False, "sink_returned": False,
                              "stderr_tail": stderr})
                + "\n</probe_execution>")
        assert _diagnosis(text)["kind"] == "environment_issue", stderr


def test_a_fired_oracle_is_a_positive_even_when_the_runner_counted_no_tests():
    """Mirrors graph.triage._ground_zero_test_diagnosis. Measured: a prove-run script that prints
    all three markers and declares no plan reports `Tests: 0` with exit 1 and a fired oracle."""
    from infosec_harness.agents.stubs import _diagnosis

    text = ("<probe_execution>\n"
            + json.dumps({"attempt": 1, "exit_code": 1, "oracle_fired": True,
                          "precondition_reached": True, "sink_returned": True,
                          "runner_reported_no_tests": "prove: no tests were run"})
            + "\n</probe_execution>")
    assert _diagnosis(text)["kind"] == "valid_positive"


def test_the_perl_plan_names_the_module_root(tmp_path):
    """`prove -v {test_file}` with no -I works only because the probe template carries
    `use lib 'lib'`. Measured: a distribution whose modules live in blib/lib or src/perl dies on
    `Can't locate Runner.pm` before printing a marker, so the flag belongs in the recipe."""
    _perl_repo(tmp_path, "use Test::More;\nok(1);\ndone_testing();\n", cpanfile="")
    assert _plan(tmp_path)["test_command"] == "prove -v -Ilib {test_file}"


def test_components_keep_distinct_declared_java_releases(tmp_path):
    from infosec_harness.repo.components import component_stack, owning_component

    for name, version in (("legacy", 8), ("modern", 17)):
        component = tmp_path / name
        component.mkdir()
        (component / "pom.xml").write_text(
            f"<project><properties><maven.compiler.release>{version}</maven.compiler.release></properties></project>")
        (component / "App.java").write_text("class App {}")
    stack = detect_stack(str(tmp_path))
    legacy = component_stack(stack, owning_component(stack, "legacy/App.java"))
    modern = component_stack(stack, owning_component(stack, "modern/App.java"))
    assert legacy.java_release == 8
    assert modern.java_release == 17


# --- untrusted tree shapes -----------------------------------------------------------------

@pytest.mark.parametrize("name", ["pom.xml", "package.json", "build.gradle", "cpanfile",
                                  "pyproject.toml"])
def test_a_directory_named_like_a_manifest_is_absent_not_a_crash(tmp_path, name):
    """Fingerprinting reads only the regular files the validated walk admitted. A directory
    named `pom.xml` used to reach `read_text` through an `exists()` check and raise
    IsADirectoryError out of detection of an untrusted repository."""
    (tmp_path / name).mkdir()
    (tmp_path / name / "inner.txt").write_text("<artifactId>junit</artifactId>\n")
    (tmp_path / "Main.java").write_text("class Main {}\n")
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "dir.t").mkdir()

    stack = detect_stack(str(tmp_path))

    assert name not in stack.manifests and stack.build_systems == []
    assert stack.java_release is None
    assert [component.root for component in stack.components] == ["."]
    assert stack.components[0].manifest_paths == []


def test_component_profiles_cover_their_subtree_from_one_walk(tmp_path, monkeypatch):
    """A component's languages and manifests include nested components; its frameworks and
    Java level come from its own root. The tree is walked once however many components exist."""
    from infosec_harness.repo import detect

    (tmp_path / "pom.xml").write_text("<maven.compiler.source>1.8</maven.compiler.source>")
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "pom.xml").write_text(
        "<artifactId>junit-jupiter</artifactId><maven.compiler.release>17</maven.compiler.release>")
    (tmp_path / "svc" / "A.java").write_text("class A {}\n")
    (tmp_path / "web" / "test").mkdir(parents=True)
    (tmp_path / "web" / "package.json").write_text("{}")
    (tmp_path / "web" / "test" / "a.mjs").write_text("import test from 'node:test';\n")
    walks = []
    real_walk = detect.walk_files
    monkeypatch.setattr(detect, "walk_files", lambda *a, **k: walks.append(a) or real_walk(*a, **k))

    components = {c.root: c for c in detect_stack(str(tmp_path)).components}

    assert len(walks) == 1
    assert components["."].languages == {"java": 1, "javascript": 1}
    assert components["."].manifest_paths == ["pom.xml", "svc/pom.xml", "web/package.json"]
    assert components["."].java_release == 8 and components["svc"].java_release == 17
    assert components["svc"].test_frameworks == ["junit5"]
    assert components["web"].test_frameworks == ["node:test"]
    assert components["web"].manifest_paths == ["package.json"]
