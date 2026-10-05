"""Deterministic ownership and preparation views for discovered repository components."""

from __future__ import annotations

from pathlib import PurePosixPath

from infosec_harness.domain.models import ComponentProfile, StackFingerprint


def owning_component(stack: StackFingerprint, file_path: str | None) -> ComponentProfile | None:
    """Return the deepest component containing ``file_path``, or ``None`` when unresolved.

    A root component is a valid fallback only when discovery actually produced one. Guessing a
    component from the file extension would collapse a polyglot repository back into one stack.
    """
    if not file_path or file_path.startswith("/"):
        return None
    path = PurePosixPath(file_path)
    if ".." in path.parts:
        return None
    candidates: list[tuple[int, ComponentProfile]] = []
    for component in stack.components:
        root = PurePosixPath(component.root)
        if component.root == "." or path == root or root in path.parents:
            depth = 0 if component.root == "." else len(root.parts)
            candidates.append((depth, component))
    if not candidates:
        return None
    deepest = max(depth for depth, _ in candidates)
    winners = [component for depth, component in candidates if depth == deepest]
    return winners[0] if len(winners) == 1 else None


def component_stack(stack: StackFingerprint, component: ComponentProfile) -> StackFingerprint:
    """Narrow repository discovery to the component that will be prepared.

    Language, manifest, build-system, framework, and test-directory signals become
    component-local so a Python service cannot borrow the Node frontend's environment recipe.
    """
    root = PurePosixPath(component.root)
    test_dirs: list[str] = []
    for value in stack.test_dirs:
        path = PurePosixPath(value)
        if component.root == ".":
            test_dirs.append(value)
        elif path == root or root in path.parents:
            test_dirs.append(path.relative_to(root).as_posix())
    return StackFingerprint(
        languages=component.languages,
        manifests=sorted({PurePosixPath(path).name for path in component.manifest_paths}),
        build_systems=component.build_systems,
        test_frameworks=component.test_frameworks,
        test_dirs=sorted(test_dirs),
        java_release=(component.java_release if component.java_release is not None else stack.java_release)
                     if "java" in component.languages else None,
        components=[component],
    )


def preparation_key(component: ComponentProfile | None) -> str:
    """Stable key used to share one prepared environment among compatible findings."""
    return component.root if component is not None else "<unresolved>"
