"""Fetch checksum-pinned OpenShell release artifacts without installing or extracting them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / ".dev-tools" / "openshell.json"
ARTIFACT_DIR = ROOT / ".harness" / "openshell" / "artifacts"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_CHUNK_SIZE = 1024 * 1024


class ArtifactError(RuntimeError):
    """Pinned artifact selection or verification failed."""


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), dict):
        raise ArtifactError("invalid OpenShell artifact manifest")
    for key, entry in manifest["artifacts"].items():
        if not isinstance(entry, dict):
            raise ArtifactError("invalid artifact entry")
        _validate_entry(key, entry)
    return manifest


def select_artifact(
    manifest: dict[str, Any], component: str, os_name: str, architecture: str
) -> tuple[str, dict[str, Any]]:
    matches = [
        (key, entry)
        for key, entry in manifest["artifacts"].items()
        if entry.get("component") == component
        and entry.get("os") == os_name
        and entry.get("architecture") == architecture
    ]
    if len(matches) != 1:
        raise ArtifactError("no unique pinned artifact matches this selection")
    key, entry = matches[0]
    _validate_entry(key, entry)
    return key, entry


def _validate_entry(key: str, entry: dict[str, Any]) -> None:
    filename = entry.get("filename")
    digest = entry.get("sha256")
    if (
        not isinstance(key, str)
        or not _FILENAME.fullmatch(key)
        or not isinstance(filename, str)
        or not _FILENAME.fullmatch(filename)
        or filename in {".", ".."}
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
    ):
        raise ArtifactError("invalid artifact entry")


def _safe_target(directory: Path, filename: str) -> Path:
    if not _FILENAME.fullmatch(filename) or filename in {".", ".."}:
        raise ArtifactError("invalid artifact filename")
    if directory.is_symlink():
        raise ArtifactError("artifact directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    root = directory.resolve()
    target = root / filename
    if target.is_symlink():
        raise ArtifactError("cached artifact cannot be a symlink")
    if target.exists() and not target.is_file():
        raise ArtifactError("cached artifact must be a regular file")
    if target.resolve(strict=False).parent != root:
        raise ArtifactError("artifact path escapes the local artifact directory")
    return target


def download_artifact(
    entry: dict[str, Any],
    directory: Path = ARTIFACT_DIR,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
    timeout: float = 30.0,
    base_url: str | None = None,
) -> Path:
    """Download one manifest entry, verify it, and atomically publish the local file."""
    _validate_entry("artifact", entry)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    manifest = load_manifest()
    url_base = base_url or manifest["release_base_url"]
    try:
        parsed = urllib.parse.urlsplit(url_base) if isinstance(url_base, str) else None
    except ValueError as exc:
        raise ArtifactError("release URL must use HTTPS") from exc
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ArtifactError("release URL must use HTTPS")
    target = _safe_target(directory, entry["filename"])
    expected = entry["sha256"]
    if target.is_file():
        if _sha256_file(target) == expected:
            return target
        target.unlink()

    fd, partial_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".part", dir=target.parent
    )
    partial = Path(partial_name)
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as output:
            response = opener(url_base.rstrip("/") + "/" + entry["filename"], timeout=timeout)
            with response:
                while chunk := response.read(_CHUNK_SIZE):
                    output.write(chunk)
                    digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != expected:
            raise ArtifactError("downloaded artifact checksum mismatch")
        os.replace(partial, target)
        return target
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", help="pinned component key, such as cli-linux-x64")
    args = parser.parse_args()
    manifest = load_manifest()
    entry = manifest["artifacts"].get(args.component)
    if not isinstance(entry, dict):
        raise SystemExit("unknown pinned artifact selection")
    path = download_artifact(entry)
    print(f"verified {args.component}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
