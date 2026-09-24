"""Deterministic stack fingerprinting (P1): language counts, manifests, and declared registries.

No model involved. The declared registries become the build-stage egress allowlist (D14).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from infosec_harness.domain.models import StackFingerprint

EXT_LANG = {
    ".py": "python", ".java": "java", ".kt": "java", ".scala": "java",
    ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".pl": "perl", ".pm": "perl", ".t": "perl", ".go": "go", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".c": "c", ".cc": "cpp", ".cpp": "cpp",
}
MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock", "uv.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "cpanfile", "Makefile.PL", "Build.PL", "go.mod", "Gemfile", "composer.json", "Cargo.toml",
}
BUILD_SYSTEM = {
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "package.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn",
    "pyproject.toml": "python", "requirements.txt": "pip", "setup.py": "pip",
    "cpanfile": "cpanm", "Makefile.PL": "cpanm",
}
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist", ".idea", ".tox"}


def _detect_test_frameworks(root: Path, langs: dict[str, int]) -> list[str]:
    fw: set[str] = set()
    text = ""
    for name in ("pyproject.toml", "package.json", "pom.xml", "build.gradle", "requirements.txt", "cpanfile"):
        p = root / name
        if p.exists():
            text += p.read_text(errors="ignore").lower()
    if "pytest" in text or (root / "tests").is_dir() and langs.get("python"):
        fw.add("pytest")
    if "junit" in text or (langs.get("java") and (root / "src/test/java").is_dir()):
        fw.add("junit5")
    if "jest" in text:
        fw.add("jest")
    if "vitest" in text:
        fw.add("vitest")
    if langs.get("perl") or list(root.glob("t/*.t")):
        fw.add("Test::More")
    return sorted(fw)


_REGISTRY_RE = re.compile(r"https?://[\w.-]+(?::\d+)?", re.I)


def _detect_registries(root: Path) -> list[str]:
    hosts: set[str] = set()
    for rel in (".npmrc", "pip.conf", "pip/pip.conf", ".pip/pip.conf", "settings.xml", ".mvn/settings.xml"):
        p = root / rel
        if p.exists():
            for m in _REGISTRY_RE.findall(p.read_text(errors="ignore")):
                hosts.add(m.split("//", 1)[1].split("/")[0])
    for name in ("pom.xml", "build.gradle", "build.gradle.kts", ".yarnrc.yml"):
        p = root / name
        if p.exists():
            for m in _REGISTRY_RE.findall(p.read_text(errors="ignore")):
                hosts.add(m.split("//", 1)[1].split("/")[0])
    return sorted(hosts)


def detect_stack(root: str) -> StackFingerprint:
    base = Path(root)
    langs: dict[str, int] = {}
    manifests: set[str] = set()
    test_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        rel_dir = os.path.relpath(dirpath, base)
        if os.path.basename(dirpath) in ("test", "tests", "t", "spec", "__tests__"):
            test_dirs.add(rel_dir)
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXT_LANG:
                langs[EXT_LANG[ext]] = langs.get(EXT_LANG[ext], 0) + 1
            if name in MANIFESTS:
                manifests.add(name)
    build_systems = sorted({BUILD_SYSTEM[m] for m in manifests if m in BUILD_SYSTEM})
    return StackFingerprint(
        languages=dict(sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))),
        manifests=sorted(manifests),
        build_systems=build_systems,
        test_frameworks=_detect_test_frameworks(base, langs),
        registries=_detect_registries(base),
        test_dirs=sorted(test_dirs),
    )
