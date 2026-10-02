from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "openshell_artifacts", ROOT / "scripts" / "openshell_artifacts.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
openshell_artifacts = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(openshell_artifacts)
ArtifactError = openshell_artifacts.ArtifactError
download_artifact = openshell_artifacts.download_artifact
load_manifest = openshell_artifacts.load_manifest
select_artifact = openshell_artifacts.select_artifact

EXPECTED = {
    "cli-macos-arm64": "cdde7e92bd7eac664031cf171cfe80d29e7f122a6674917b25a4ce0bcbc33466",
    "cli-linux-arm64": "9880c5776688231d5242deb046cdee361734f94901b9123949a0baf29fdadd9e",
    "cli-linux-x64": "7eb6917285331a09e3300266a0558616481a5e9927cae2612ea07c4045b6dd6f",
    "gateway-linux-arm64": "8ec1b6ca5b71ef5085fa51f3244d719a541e8f0d58cc569c7a0d6705b6204397",
    "supervisor-linux-arm64": "57328624479b29261cf1f9eeb847df867bac7deb3186bb36bfde07fdcd2a94f5",
    "sandbox-linux-arm64": "4c68f2bc8e00a0a7d5d66d7bc2d836be6b255602a8f1b1650b4262c7935894b3",
    "gateway-linux-x64": "218d887845b3a020ab7535c9985eb9c666d6938f144044957f8b82b42892aadb",
    "supervisor-linux-x64": "801d717f4211b4c24449b08a47ce5571ff623ce993c10d44e133dbe2edc36611",
    "sandbox-linux-x64": "f07ad7177f4c3ff7743f89531eda36bb784c56b45b166f49c5a51fbcfa5274a6",
    "sdk-wheel": "8c409da4f176d42418d92366fe201f47cceef2c0fa432bfbce2bf938649d59cf",
}


class FakeResponse(io.BytesIO):
    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_manifest_has_independently_expected_release_and_asset_pins():
    manifest = load_manifest(ROOT / ".dev-tools" / "openshell.json")
    assert manifest["release"] == "0.1.2"
    assert manifest["commit"] == "6648bd0c290efbc41ba131ee9831ee45cd431f94"
    assert {key: entry["sha256"] for key, entry in manifest["artifacts"].items()} == EXPECTED
    assert len(manifest["artifacts"]) == len(EXPECTED)
    for key, entry in manifest["artifacts"].items():
        openshell_artifacts._validate_entry(key, entry)
    assert manifest["oci_indexes"] == {
        "gateway": "sha256:2fe4dad9118e14ab80a8258b545ea6e6cd74c3469e24ad4e6610f964d98913a2",
        "supervisor": "sha256:d7b5264bb6bc56f4796e6fa3617b8e4a8d785be0b7293542efd8cc250b0fb67a",
        "sandbox": "sha256:bf4797b6c511f2d8ba02955dbba4bf76c1f0dd6d83531420c5408d5f1fb9d72f",
    }


def test_manifest_loader_rejects_bad_digest_in_any_entry(tmp_path: Path):
    manifest = json.loads((ROOT / ".dev-tools" / "openshell.json").read_text(encoding="utf-8"))
    manifest["artifacts"]["sandbox-linux-x64"]["sha256"] = "f" * 63
    bad_manifest = tmp_path / "openshell.json"
    bad_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ArtifactError, match="invalid artifact entry"):
        load_manifest(bad_manifest)


def test_selection_resolves_exact_platform_artifact_and_rejects_unknown():
    manifest = load_manifest(ROOT / ".dev-tools" / "openshell.json")
    key, entry = select_artifact(manifest, "cli", "linux", "x86_64")
    assert key == "cli-linux-x64"
    assert entry["filename"] == "openshell-x86_64-unknown-linux-musl.tar.gz"
    with pytest.raises(ArtifactError):
        select_artifact(manifest, "cli", "windows", "x64")


def test_download_verifies_and_atomically_publishes_with_fake_stream(tmp_path: Path):
    content = b"offline fake release artifact"
    entry = {"filename": "openshell-test.tar.gz", "sha256": hashlib.sha256(content).hexdigest()}
    calls: list[tuple[str, float]] = []

    def opener(url: str, *, timeout: float) -> FakeResponse:
        calls.append((url, timeout))
        return FakeResponse(content)

    path = download_artifact(
        entry,
        tmp_path / "artifacts",
        opener=opener,
        timeout=4.5,
        base_url="https://release.invalid/v1/",
    )
    assert path.read_bytes() == content
    assert calls == [("https://release.invalid/v1/openshell-test.tar.gz", 4.5)]
    assert list(path.parent.iterdir()) == [path]


def test_digest_mismatch_removes_partial_and_does_not_publish(tmp_path: Path):
    entry = {"filename": "openshell-test.tar.gz", "sha256": "0" * 64}
    with pytest.raises(ArtifactError, match="checksum mismatch"):
        download_artifact(
            entry,
            tmp_path,
            opener=lambda *_args, **_kwargs: FakeResponse(b"wrong"),
            base_url="https://release.invalid/",
        )
    assert list(tmp_path.iterdir()) == []


def test_failed_stream_cleans_partial_file(tmp_path: Path):
    class BrokenResponse(FakeResponse):
        def read(self, _size: int = -1) -> bytes:
            raise OSError("injected stream failure")

    entry = {"filename": "openshell-test.tar.gz", "sha256": "0" * 64}
    with pytest.raises(OSError, match="injected stream failure"):
        download_artifact(
            entry,
            tmp_path,
            opener=lambda *_args, **_kwargs: BrokenResponse(),
            base_url="https://release.invalid/",
        )
    assert list(tmp_path.iterdir()) == []


def test_correct_cached_file_skips_fetch_and_corrupt_cached_file_is_replaced(tmp_path: Path):
    content = b"verified cache content"
    entry = {"filename": "openshell-test.tar.gz", "sha256": hashlib.sha256(content).hexdigest()}
    cached = tmp_path / entry["filename"]
    cached.write_bytes(content)

    def should_not_fetch(*_args: object, **_kwargs: object) -> None:
        pytest.fail("correct cached artifact refetched")

    assert (
        download_artifact(
            entry, tmp_path, opener=should_not_fetch, base_url="https://release.invalid/"
        )
        == cached
    )

    cached.write_bytes(b"corrupt")
    path = download_artifact(
        entry,
        tmp_path,
        opener=lambda *_args, **_kwargs: FakeResponse(content),
        base_url="https://release.invalid/",
    )
    assert path.read_bytes() == content
    assert list(tmp_path.iterdir()) == [cached]


def test_selection_and_target_reject_path_traversal(tmp_path: Path):
    entry = {"filename": "../escape", "sha256": "0" * 64}
    with pytest.raises(ArtifactError, match="invalid artifact entry"):
        download_artifact(
            entry,
            tmp_path,
            opener=lambda *_args, **_kwargs: pytest.fail("opened"),
            base_url="https://release.invalid/",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://release.invalid/",
        "https:///missing-host",
        "https://user:password@release.invalid/",
        "https://release.invalid/?token=value",
        "https://release.invalid/#fragment",
        "https://[broken/",
    ],
)
def test_release_url_rejects_non_https_or_ambiguous_urls(tmp_path: Path, url: str):
    entry = {"filename": "openshell-test.tar.gz", "sha256": "0" * 64}
    with pytest.raises(ArtifactError, match="release URL must use HTTPS"):
        download_artifact(
            entry,
            tmp_path,
            opener=lambda *_args, **_kwargs: pytest.fail("invalid URL opened"),
            base_url=url,
        )


def test_cached_directory_and_all_artifact_symlinks_are_rejected(tmp_path: Path):
    entry = {"filename": "openshell-test.tar.gz", "sha256": "0" * 64}
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / entry["filename"]).mkdir()
    with pytest.raises(ArtifactError, match="regular file"):
        download_artifact(
            entry,
            cache,
            opener=lambda *_args, **_kwargs: pytest.fail("opened"),
            base_url="https://release.invalid/",
        )

    (cache / entry["filename"]).rmdir()
    real_file = cache / "real-file"
    real_file.write_bytes(b"cached bytes")
    (cache / entry["filename"]).symlink_to(real_file)
    with pytest.raises(ArtifactError, match="cached artifact cannot be a symlink"):
        download_artifact(
            entry,
            cache,
            opener=lambda *_args, **_kwargs: pytest.fail("opened"),
            base_url="https://release.invalid/",
        )

    cache_link = tmp_path / "cache-link"
    cache_link.symlink_to(cache, target_is_directory=True)
    with pytest.raises(ArtifactError, match="directory cannot be a symlink"):
        download_artifact(
            entry,
            cache_link,
            opener=lambda *_args, **_kwargs: pytest.fail("opened"),
            base_url="https://release.invalid/",
        )


def test_failed_refetch_removes_corrupt_cache_and_closes_temp_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    entry = {"filename": "openshell-test.tar.gz", "sha256": "0" * 64}
    cached = tmp_path / entry["filename"]
    cached.write_bytes(b"corrupt cache")
    original_fdopen = openshell_artifacts.os.fdopen
    exits: list[int] = []

    class TrackedFile:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args: object) -> bool | None:
            exits.append(1)
            return self.wrapped.__exit__(*args)

        def __getattr__(self, name: str):
            return getattr(self.wrapped, name)

    monkeypatch.setattr(
        openshell_artifacts.os,
        "fdopen",
        lambda *args, **kwargs: TrackedFile(original_fdopen(*args, **kwargs)),
    )

    def failed_opener(*_args: object, **_kwargs: object):
        raise OSError("injected HTTP failure")

    with pytest.raises(OSError, match="injected HTTP failure"):
        download_artifact(
            entry, tmp_path, opener=failed_opener, base_url="https://release.invalid/"
        )
    assert exits == [1]
    assert not cached.exists()
    assert list(tmp_path.iterdir()) == []


def test_startup_control_candidate_recipe_pins_patch_and_source_before_tests():
    recipe = (ROOT / "deploy/openshell/Dockerfile.supervisor-backport").read_text()
    patch = (ROOT / "deploy/openshell/patches/0002-bound-startup-control-wait.patch").read_bytes()
    assert (
        hashlib.sha256(patch).hexdigest()
        == "50af0650f4091bce8d6e05cba4f77d9010c251cd3eac268767b73e2e4db87caa"
    )
    assert b"--- a/crates/openshell-sandbox-backend/src/runtime.rs\n" in patch
    assert patch.count(b"--- a/") == 2
    assert (
        b"--- a/crates/openshell-sandbox-backend/src/runtime/tests/credential_renewal.rs\n" in patch
    )
    assert (
        "50af0650f4091bce8d6e05cba4f77d9010c251cd3eac268767b73e2e4db87caa  /tmp/startup-control.patch"
        in recipe
    )
    before = recipe.index(
        "1e7a0740d1dfebf4ce04aad1b1c274f9fff7d2c2e3525923cad3177c4ce26497  crates/openshell-sandbox-backend/src/runtime.rs"
    )
    apply = recipe.index("patch --fuzz=0 -p1 < /tmp/startup-control.patch")
    after = recipe.index(
        "bf713402164de46be4385e7e6011a5e60b5e35b26479495c2db1f70658ff0433  crates/openshell-sandbox-backend/src/runtime.rs"
    )
    tests = recipe.index("cargo test --locked -p openshell-sandbox-backend --lib startup_control")
    build = recipe.index("cargo zigbuild --locked --release")
    assert before < apply < after < tests < build
    assert (
        recipe.count(
            "bf713402164de46be4385e7e6011a5e60b5e35b26479495c2db1f70658ff0433  crates/openshell-sandbox-backend/src/runtime.rs"
        )
        == 2
    )


def test_startup_control_candidate_keeps_enforcement_and_real_replay_checks():
    recipe = (ROOT / "deploy/openshell/Dockerfile.supervisor-backport").read_text()
    assert "cargo test --locked -p openshell-sandbox --lib --no-run --message-format=json" in recipe
    assert "fail_closed_validation_failure_deactivates_previous_generation" in recipe
    assert "cargo test --locked -p openshell-supervisor-network --lib generation" in recipe
    assert (
        "cargo test --locked -p openshell-supervisor-network --lib fail_closed_quarantine" in recipe
    )
    assert recipe.index("provider_poll -- --nocapture") < recipe.index(
        "COPY 0002-bound-startup-control-wait.patch"
    )
    assert (
        recipe.count("ea10e2922eece4077a2c1be17cac83214aa5f79f39fd6c5cc830e1a2cf9d459a  Cargo.lock")
        == 5
    )
    # Existing qualification metadata remains historical; it is not proof of
    # the unbuilt two-patch candidate's image or binary.
    historical = json.loads((ROOT / ".dev-tools/openshell-supervisor-backport.json").read_text())
    assert historical["changed_files"][0]["path"] == "crates/openshell-supervisor/src/lib.rs"
    assert (
        historical["patch_sha256"]
        == "f62b1a304969ed47eddbc808c964ee6b69259118d30c61a7b63524a6d9321c54"
    )


def test_unbuilt_startup_manifest_is_separate_and_all_declared_inputs_are_pinned():
    candidate = json.loads(
        (ROOT / ".dev-tools/openshell-supervisor-startup-candidate.json").read_text()
    )
    assert candidate["status"] == "not_built"
    assert candidate["runtime_qualification"] == "not_checked"
    assert candidate["actual_image"] is None and candidate["actual_binary_sha256"] is None
    historical = ROOT / candidate["historical_qualification_file"]
    assert (
        hashlib.sha256(historical.read_bytes()).hexdigest()
        == candidate["historical_qualification_sha256"]
    )
    recipe_path = ROOT / candidate["recipe_file"]
    assert hashlib.sha256(recipe_path.read_bytes()).hexdigest() == candidate["recipe_sha256"]
    recipe = recipe_path.read_text()
    for patch in candidate["patches"]:
        assert hashlib.sha256((ROOT / patch["file"]).read_bytes()).hexdigest() == patch["sha256"]
    for source in candidate["changed_files"]:
        for field in ("original_sha256", "patched_sha256"):
            assert source[field] + "  " + source["path"] in recipe
    for check in candidate["required_rust_tests"]:
        if check["package"] == "openshell-sandbox":
            assert candidate["boundary_replay_test_runner"]["uid"] == 65532
            assert candidate["boundary_replay_test_runner"]["gid"] == 65532
            assert (
                "--exact boundary_server::linux::tests::" + check["filter"] + " --nocapture"
                in recipe
            )
            assert "cargo test --locked -p openshell-sandbox --lib --no-run" in recipe
        else:
            assert (
                f"cargo test --locked -p {check['package']} --lib {check['filter']} -- --nocapture"
                in recipe
            )
    assert candidate["timeouts_seconds"] == {
        "attach": 300,
        "discover_policy": 300,
        "confirm": 60,
        "start_agent": 60,
        "other_control": 30,
        "connect_retry": 30,
    }


def test_boundary_replay_recipe_runs_exact_test_with_nonroot_identity():
    recipe = (ROOT / "deploy/openshell/Dockerfile.supervisor-backport").read_text()
    compile_command = (
        "cargo test --locked -p openshell-sandbox --lib --no-run --message-format=json"
    )
    runner = 'setpriv --reuid=65532 --regid=65532 --clear-groups -- "$boundary_test" --exact boundary_server::linux::tests::control_restart_replays_running_lifecycle_exactly_once --nocapture'
    assert compile_command in recipe and runner in recipe
    assert recipe.index(compile_command) < recipe.index(runner)
    assert "(cd /tmp && setpriv" in recipe
    assert "command -v python3 && command -v setpriv" in recipe
    assert "cargo test --locked -p openshell-sandbox --lib control_restart" not in recipe


@pytest.mark.parametrize("rejection", [None, "duplicate", "foreign", "non_test", "symlink"])
def test_boundary_replay_extractor_rejects_ambiguous_or_foreign_executable(tmp_path, rejection):
    recipe = (ROOT / "deploy/openshell/Dockerfile.supervisor-backport").read_text()
    line = next(line for line in recipe.splitlines() if 'boundary_test="$(python3 -c ' in line)
    code = shlex.split(line.split("python3 -c ", 1)[1].split(')" &&', 1)[0])[0]
    executable = tmp_path / "openshell_sandbox-0123abcd"
    executable.write_text("fixture executable")
    executable.chmod(0o755)
    if rejection == "symlink":
        target = tmp_path / "target"
        executable.rename(target)
        executable.symlink_to(target)
    row = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///src/crates/openshell-sandbox#0.0.0",
        "target": {"name": "openshell_sandbox", "kind": ["lib"]},
        "profile": {"test": True},
        "executable": str(executable),
    }
    if rejection == "foreign":
        row["package_id"] = "path+file:///src/crates/unrelated#0.0.0"
    if rejection == "non_test":
        row["profile"] = {"test": False}
    records = tmp_path / "artifacts.json"
    records.write_text(
        "\n".join(json.dumps(row) for _ in range(2 if rejection == "duplicate" else 1))
    )
    # Relocate only the build-directory fixtures; exercise the actual recipe parser.
    code = code.replace("/tmp/boundary-test-artifacts.json", str(records)).replace(
        "/src/target/debug/deps/", str(tmp_path) + "/"
    )
    if rejection is None:
        exec(code, {})
    else:
        with pytest.raises(AssertionError):
            exec(code, {})
