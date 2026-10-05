"""A cache of environment specs that are known to build, keyed by the *shape* of a repository.

Preparation is already cached per repo@revision, which helps the second finding in a repo and
nobody else. But the expensive part is rarely repo-specific: the Maven surefire warm-up, the
`cpanm --local-lib` incantation and its matching `PERL5LIB`, `-Dmaven.repo.local` on both sides
of the two-path layout -- each was discovered the hard way, and each is a property of the
*stack*, not of any one project. Without this, the next Maven repository re-derives all of it
from scratch, and may derive it wrong.

So a spec that built and smoke-tested clean is recorded under a fingerprint of the stack's
shape, and the next repository with the same shape tries it before asking the planner. A hit
skips an agent call and an uncertain build; a miss costs one build attempt and falls back to
the normal path.

Deliberately a cache, not a learning system: one key, one spec, evicted the moment it stops
working. It can only ever save time -- a wrong entry is discovered by the build that would
have happened anyway, and is then gone.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from infosec_harness._io import write_json
from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.persistence.paths import workspace_dir
from infosec_harness.settings import get_settings


def stack_key(stack: StackFingerprint) -> str:
    """A stable identity for a kind of repository, not a particular one.

    Only shape goes in. File *counts* are excluded, since two Maven projects of different sizes
    want the same recipe, and so is `test_dirs`, which varies per project. What
    remains -- the dominant language, the build systems, the test frameworks, the declared Java
    level, and the manifest filenames -- is exactly what determines how a repo is built and
    tested.

    `java_release` is part of the identity because it decides the base image, and both directions
    of mismatch are hard build failures: sharing one recipe between a Java 7 and a Java 17 project
    hands one of them a JDK whose javac refuses its language level.
    """
    parts = [
        f"lang={stack.top_language}",
        "build=" + ",".join(sorted(stack.build_systems)),
        "test=" + ",".join(sorted(stack.test_frameworks)),
        f"java={stack.java_release if stack.java_release is not None else ''}",
        "manifests=" + ",".join(sorted(stack.manifests)),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class RecipeStore:
    """One atomically published recipe per stack shape; disabled stores perform no I/O."""

    def __init__(self, root: Path | None = None, *, enabled: bool | None = None) -> None:
        settings = get_settings()
        self.enabled = settings.recipe_cache_enabled if enabled is None else enabled
        self.root = root or settings.recipe_cache_dir or workspace_dir() / "recipes"

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def lookup(self, key: str) -> EnvironmentSpec | None:
        if not self.enabled:
            return None
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            return EnvironmentSpec.model_validate(json.loads(path.read_text())["spec"])
        except Exception:
            # A stale or hand-edited entry must never break a run: drop it and plan normally.
            self.forget(key)
            return None

    def record(self, key: str, spec: EnvironmentSpec) -> None:
        if self.enabled:
            write_json(self._path(key), {"spec": spec.model_dump(mode="json")})

    def forget(self, key: str) -> None:
        if self.enabled:
            self._path(key).unlink(missing_ok=True)


def is_cacheable(spec: EnvironmentSpec) -> bool:
    """Only a full-scope spec generalises to another repository.

    A partial build names a `module_path` chosen for one project's layout; replaying that
    against a different repo of the same stack would build the wrong directory, or nothing.
    """
    return spec.scope == "full" and not spec.module_path


def lookup_recipe(stack: StackFingerprint, store: RecipeStore | None = None) -> EnvironmentSpec | None:
    return (store or RecipeStore()).lookup(stack_key(stack))


def record_recipe_outcome(stack: StackFingerprint, spec: EnvironmentSpec, *, worked: bool,
                          store: RecipeStore | None = None) -> None:
    """Keep a spec that built and smoke-tested, drop one that did not.

    Eviction on first failure is the whole safety story: a stale recipe costs exactly one build
    attempt, once, and then stops existing. A spec that worked but cannot generalise to another
    repository (a partial build) is neither kept nor evicted.
    """
    store, key = store or RecipeStore(), stack_key(stack)
    if worked and is_cacheable(spec):
        store.record(key, spec)
    elif not worked:
        store.forget(key)
