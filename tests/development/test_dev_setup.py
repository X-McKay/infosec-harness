"""dev_setup.py: pins come from .mise.toml; reset and gc delete only what they own."""

import hashlib
import sys
from pathlib import Path

import pytest
from conftest import load_script

setup = load_script("dev_setup")


def test_tool_pins_are_read_from_mise_toml():
    tools = setup.mise_tools()
    assert set(setup.TOOL_CHECKS) <= tools.keys()
    assert all(tools[name] for name in setup.TOOL_CHECKS)


def test_tool_versions_must_equal_the_pin_exactly(monkeypatch):
    pins = setup.mise_tools()
    outputs = {
        "python": f"Python {pins['python']}",
        "uv": f"uv {pins['uv']} (abc 2026-01-01)",
        "just": f"just {pins['just']}",
        "temporal": f"temporal version {pins['http:temporal']} (Server 1, UI 2)",
        "node": f"v{pins['node']}",
    }
    monkeypatch.setattr(setup, "command_version", lambda command, *args: outputs.get(command))
    assert setup.tool_mismatches(list(setup.TOOL_CHECKS)) == []
    # A global tool of another version on PATH does not satisfy the pin; neither does absence.
    outputs["uv"] = f"uv {pins['uv']}1 (abc)"
    del outputs["temporal"]
    assert setup.tool_mismatches(list(setup.TOOL_CHECKS)) == [
        f"managed uv {pins['uv']} (found {pins['uv']}1)",
        f"managed temporal {pins['http:temporal']} (found none)",
    ]


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """A fake ~/.cache/ih with this checkout's home plus in-use, orphaned and unknown ones."""
    base = tmp_path / "ih"
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.setattr(setup, "RUNTIME_HOMES", base)
    monkeypatch.setattr(setup, "ROOT", checkout)
    monkeypatch.setattr(setup, "STATE", checkout / ".harness")
    monkeypatch.setattr(setup, "ENV_PATH", checkout / ".harness" / "dev.env")
    monkeypatch.setattr(setup, "LIMA_HOME", setup.runtime_home_for(checkout))
    monkeypatch.setattr(setup, "_worktree_homes", lambda: {})

    def home(owner: Path | None, *, recorded: bool = True) -> Path:
        path = setup.runtime_home_for(owner) if owner else base / "abcdef0123"
        path.mkdir(parents=True)
        if owner and recorded:
            (path / setup.OWNER_RECORD).write_text(f"{owner}\n")
        return path

    sibling = tmp_path / "sibling"
    sibling.mkdir()
    return {
        "current": home(checkout),
        "in-use": home(sibling),
        "orphaned": home(tmp_path / "deleted-worktree"),
        "unknown": home(None),
    }


def test_gc_classifies_homes_and_lists_without_deleting(homes, capsys):
    found = {state: home for home, state, _owner in setup.classify_runtime_homes()}
    assert found == homes
    assert setup.gc(delete=False) == 0
    assert all(path.exists() for path in homes.values())
    assert "1 orphaned" in capsys.readouterr().out


def test_gc_delete_removes_only_orphaned_homes(homes):
    assert setup.gc(delete=True) == 0
    assert not homes["orphaned"].exists()
    assert all(homes[state].exists() for state in ("current", "in-use", "unknown"))


def test_gc_refuses_to_orphan_a_vm_it_cannot_stop(homes, monkeypatch, tmp_path):
    (homes["orphaned"] / setup.LIMA_INSTANCE).mkdir()
    monkeypatch.setattr(setup, "lima_paths", lambda: (tmp_path, tmp_path / "missing-limactl"))
    assert setup.gc(delete=True) == 2
    assert homes["orphaned"].exists()


def test_unrecorded_home_of_a_live_worktree_is_in_use(homes, monkeypatch, tmp_path):
    live = tmp_path / "legacy-worktree"
    live.mkdir()
    legacy = setup.runtime_home_for(live)
    legacy.mkdir()
    monkeypatch.setattr(setup, "_worktree_homes", lambda: {legacy: live})
    assert (legacy, "in-use", live) in setup.classify_runtime_homes()


def test_only_runtime_homes_can_be_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "RUNTIME_HOMES", tmp_path / "ih")
    for path in (tmp_path, tmp_path / "ih", tmp_path / "ih" / "not-a-hash", Path.home()):
        with pytest.raises(RuntimeError, match="not a ./dev runtime home"):
            setup.delete_runtime_home(path)


def test_reset_needs_confirmation_and_keeps_tools(homes, monkeypatch, capsys):
    state = setup.STATE
    for name in ("dev.env", "runtime-home", "bin/docker", "workspace/finding/a.txt",
                 "mise/installs/uv", "logs/compose-1", "reports/r.json"):
        (state / name).parent.mkdir(parents=True, exist_ok=True)
        (state / name).write_text("x")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert setup.reset(assume_yes=False) == 2
    assert (state / "dev.env").exists() and homes["current"].exists()

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert setup.reset(assume_yes=False) == 1
    assert (state / "dev.env").exists() and homes["current"].exists()

    identity = f"harness-{hashlib.sha256(str(setup.ROOT.resolve()).encode()).hexdigest()[:10]}"
    monkeypatch.setattr("builtins.input", lambda prompt: identity)
    assert setup.reset(assume_yes=False) == 0
    assert not homes["current"].exists()
    for name in ("dev.env", "runtime-home", "bin/docker", "workspace"):
        assert not (state / name).exists(), name
    for name in ("mise/installs/uv", "logs/compose-1", "reports/r.json"):
        assert (state / name).exists(), name
    assert homes["in-use"].exists() and homes["orphaned"].exists()
    capsys.readouterr()


def test_runtime_home_records_its_owner(homes):
    setup.LIMA_HOME.joinpath(setup.OWNER_RECORD).unlink()
    setup.STATE.mkdir(parents=True)
    setup.ensure_lima_home()
    assert (setup.LIMA_HOME / setup.OWNER_RECORD).read_text().strip() == str(setup.ROOT)
    assert (setup.STATE / "runtime-home").read_text().strip() == str(setup.LIMA_HOME)
