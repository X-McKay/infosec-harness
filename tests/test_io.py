"""The atomic evidence writer: complete files only, owner-only, no temporary file left."""

import json
import os
import stat

import pytest

from infosec_harness._io import atomic_write_bytes, write_json


def leftovers(directory):
    return sorted(path.name for path in directory.iterdir() if path.name.startswith("."))


def test_write_publishes_owner_only_and_replaces(tmp_path):
    path = tmp_path / "report.json"
    atomic_write_bytes(path, b"first")
    assert path.read_bytes() == b"first"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    atomic_write_bytes(path, b"second", sync_directory=True)
    assert path.read_bytes() == b"second"
    assert leftovers(tmp_path) == []


def test_exclusive_write_refuses_and_keeps_the_existing_file(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b"previous")
    with pytest.raises(FileExistsError):
        atomic_write_bytes(path, b"new", exclusive=True)
    assert path.read_bytes() == b"previous"
    assert leftovers(tmp_path) == []
    fresh = tmp_path / "fresh.json"
    atomic_write_bytes(fresh, b"new", exclusive=True)
    assert fresh.read_bytes() == b"new"


def test_failed_publish_leaves_the_previous_file_and_no_temporary(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_bytes(b"previous")

    def interrupted(source, target):
        raise OSError("publish interrupted")

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(OSError, match="publish interrupted"):
        atomic_write_bytes(path, b"partial")
    assert path.read_bytes() == b"previous"
    assert leftovers(tmp_path) == []


def test_write_json_is_strict_and_encodes_before_making_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "report.json"
    with pytest.raises(ValueError, match="not JSON compliant"):
        write_json(nested, {"rate": float("nan")})
    with pytest.raises(TypeError):
        write_json(nested, {"value": object()})
    assert not (tmp_path / "a").exists()
    write_json(nested, {"rate": 0.5, "items": [1, "two"]})
    assert nested.read_text() == json.dumps({"rate": 0.5, "items": [1, "two"]}, indent=2) + "\n"
    with pytest.raises(FileExistsError):
        write_json(nested, {}, exclusive=True)
    assert json.loads(nested.read_text())["rate"] == 0.5

