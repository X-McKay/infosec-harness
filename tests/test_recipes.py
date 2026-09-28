"""The environment-recipe cache: a spec that built, reused for the next repo of the same shape."""
import tempfile
from pathlib import Path

from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.persistence.recipes import (
    FilesystemRecipeStore,
    NullRecipeStore,
    is_cacheable,
    stack_key,
)


def _maven(**kw) -> StackFingerprint:
    base = {"languages": {"java": 3}, "manifests": ["pom.xml"], "build_systems": ["maven"],
            "test_frameworks": ["junit5"], "test_dirs": ["src/test/java"]}
    return StackFingerprint(**{**base, **kw})


def _spec(**kw) -> EnvironmentSpec:
    base = {"base_image": "maven:3.9-eclipse-temurin-17",
            "install_commands": ["mvn -B -DskipTests test-compile"],
            "test_command": "mvn -B -o test -Dtest=HarnessProbeTest"}
    return EnvironmentSpec(**{**base, **kw})


def _store() -> FilesystemRecipeStore:
    return FilesystemRecipeStore(root=Path(tempfile.mkdtemp()))


def test_the_key_is_the_shape_of_a_repo_not_its_size():
    """Two Maven projects want the same recipe however many files they have, so file counts and
    per-project paths must not enter the key -- otherwise the cache never hits."""
    assert stack_key(_maven()) == stack_key(_maven(languages={"java": 900}, test_dirs=["other"]))


def test_a_different_toolchain_is_a_different_key():
    python = StackFingerprint(languages={"python": 3}, manifests=["requirements.txt"],
                              build_systems=["pip"], test_frameworks=["pytest"])
    assert stack_key(_maven()) != stack_key(python)
    # Same language, different build system: a Gradle recipe must not be served to Maven.
    assert stack_key(_maven()) != stack_key(_maven(build_systems=["gradle"]))


def test_a_recorded_recipe_comes_back():
    store, key = _store(), stack_key(_maven())
    assert store.lookup(key) is None
    store.record(key, _spec())
    assert store.lookup(key).test_command == _spec().test_command


def test_a_recipe_is_evicted_the_moment_it_stops_working():
    """The whole safety story: a stale entry costs one build attempt, once, then ceases to exist."""
    store, key = _store(), stack_key(_maven())
    store.record(key, _spec())
    store.forget(key)
    assert store.lookup(key) is None


def test_a_corrupt_entry_is_dropped_rather_than_breaking_the_run():
    store, key = _store(), stack_key(_maven())
    (store.root / f"{key}.json").write_text("{not json at all")
    assert store.lookup(key) is None
    assert not (store.root / f"{key}.json").exists(), "the bad entry should be gone, not retried"


def test_a_partial_build_is_never_cached():
    """A partial spec names a module_path chosen for one project's layout; replaying it against
    another repo of the same stack would build the wrong directory, or nothing at all."""
    assert is_cacheable(_spec())
    assert not is_cacheable(_spec(scope="partial", module_path="services/api"))


def test_the_disabled_store_changes_nothing():
    store = NullRecipeStore()
    store.record("k", _spec())
    assert store.lookup("k") is None


async def test_corpus_scoring_does_not_read_or_write_the_cache():
    """An eval must exercise every stage and give the same answer twice.

    With the cache on, the first repository of a stack records a recipe that every later
    repository reuses, so env-planner runs once instead of once per repo and the stage funnel
    loses the signal it exists to provide -- and whether that happened depended on what a
    previous run had left on disk. That is exactly how this test came to be written.
    """
    from infosec_harness.evals.run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    traj = metrics["trajectory"]
    assert "env-planner" in traj, "the planner was skipped; corpus scoring is using the cache"
    assert traj["env-planner"]["n"] == traj["recon"]["n"], (
        "env-planner ran fewer times than recon, so some repos were served from the cache"
    )


async def test_a_second_repo_of_the_same_shape_skips_the_planner(tmp_path, monkeypatch):
    """The payoff: the recipe is tried before the planner is asked.

    The expensive parts of a spec -- the surefire warm-up, cpanm's --local-lib and its matching
    PERL5LIB, -Dmaven.repo.local on both sides of the two-path layout -- are properties of the
    stack, not the project. Re-deriving them per repository is both slow and a fresh chance to
    get them wrong.
    """
    from infosec_harness.domain.models import RepoSnapshot
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.graph.prepare import run_prepare
    from infosec_harness.repo.detect import detect_stack

    monkeypatch.setenv("HARNESS_RECIPE_CACHE_DIR", str(tmp_path / "recipes"))
    ops = LocalOps(sandbox=False, recipe_cache=True)

    async def prepare(name: str):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "requirements.txt").write_text("")
        (repo / "app.py").write_text("def f(db, n):\n    return db.execute('SELECT ' + n)\n")
        snap = RepoSnapshot(repo_url=str(repo), revision="HEAD", path=str(repo),
                            content_hash=name.ljust(8, "x"))
        out = await run_prepare(ops, snap, detect_stack(str(repo)))
        return out, [i.agent for i in out.invocations]

    first, first_agents = await prepare("one")
    assert first.prepared.status == "ready"
    assert "env-planner" in first_agents, "the first repo of a shape must plan normally"

    second, second_agents = await prepare("two")
    assert second.prepared.status == "ready"
    assert "env-planner" not in second_agents, (
        f"the recipe was not reused; the planner ran again (agents: {second_agents})"
    )
    # recon still runs: the profile feeds later prompts, and only the planner is skipped.
    assert "recon" in second_agents
    assert second.prepared.build.spec.test_command == first.prepared.build.spec.test_command
