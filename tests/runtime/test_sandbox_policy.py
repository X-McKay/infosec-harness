"""Sandbox policy and hardening: base-image allowlist, fail-closed runtime, image provenance,
and read-only workload args — all deterministic."""
import asyncio
import csv
import json

import pytest

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import docker, engine
from infosec_harness.sandbox.docker import ensure_runtime_available
from infosec_harness.sandbox.image import builder_proxy_environment
from infosec_harness.sandbox.policy import (
    DisallowedBaseImage,
    InvalidEnvironmentSpec,
    SandboxUnavailable,
    image_repository,
    validate_base_image,
)
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import get_settings

# Docker official images and one whole registry: what each entry says, nothing more.
ALLOW = ["docker.io/library", "public.ecr.aws"]
DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize("image", ["python:3.12-slim", "node:22-slim", "maven:3.9-eclipse-temurin-21",
                                   "docker.io/library/perl:5.40", "docker.io/python:3",
                                   f"python@{DIGEST}", f"python:3.12@{DIGEST}",
                                   "public.ecr.aws/x/y:1"])
def test_base_image_allowed(image):
    assert validate_base_image(image, ALLOW) == image


@pytest.mark.parametrize("image", [
    "evil.example.com/malware:latest", "ghcr.io/x/y:1", "quay.io/foo/bar",
    # A Docker Hub account is not Docker official images, explicit host or not.
    "someorg/python:3", "docker.io/someorg/python:3",
    # Namespaces match whole components, not string prefixes.
    "docker.io/library-evil/python:3", "librarything/python",
    # `localhost` is a registry host, never a Docker Hub account.
    "localhost/python:3", "localhost:5000/library/python",
])
def test_base_image_outside_the_entries_is_rejected(image):
    with pytest.raises(DisallowedBaseImage):
        validate_base_image(image, ALLOW)


@pytest.mark.parametrize("image", ["", "Python:3", "python:", "python@sha256:abc", "a//b",
                                   "-python", "python:3:4", "python@x@y",
                                   "evil.example.com:port/x"])
def test_unparseable_base_image_is_rejected_not_guessed(image):
    with pytest.raises(DisallowedBaseImage):
        validate_base_image(image, ["docker.io", "evil.example.com"])


def test_base_image_entries_mean_what_they_say():
    assert image_repository("python:3") == ("docker.io", ("library", "python"))
    assert image_repository("someorg/app") == ("docker.io", ("someorg", "app"))
    assert image_repository("registry.example:5000/a/b:1") == ("registry.example:5000", ("a", "b"))
    # A bare host admits that whole registry, Docker Hub included, because that is what it says.
    assert validate_base_image("someorg/app", ["docker.io"]) == "someorg/app"
    # An account entry admits that account only.
    assert validate_base_image("someorg/app", ["docker.io/someorg"]) == "someorg/app"
    with pytest.raises(DisallowedBaseImage):
        validate_base_image("python:3", ["docker.io/someorg"])
    with pytest.raises(DisallowedBaseImage):
        validate_base_image("python:3", ["", "/"])


async def test_fail_closed_when_runtime_missing(monkeypatch):
    async def _no(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    with pytest.raises(SandboxUnavailable):
        await ensure_runtime_available("test")


async def test_configured_non_gvisor_runtime_fails_closed_even_when_present(monkeypatch):
    async def _yes(_runtime=None):
        return True

    monkeypatch.setattr(docker, "runtime_available", _yes)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(get_settings(), "sandbox_runtime", "runc", raising=False)
    with pytest.raises(SandboxUnavailable, match="not gVisor"):
        await ensure_runtime_available("test")


def test_settings_reject_weaker_runtime_without_explicit_override(monkeypatch):
    from infosec_harness.settings import Settings

    monkeypatch.delenv("HARNESS_ALLOW_INSECURE_RUNTIME", raising=False)
    with pytest.raises(ValueError, match="runsc"):
        Settings(_env_file=None, sandbox_runtime="runc", allow_insecure_runtime=False)
    assert Settings(_env_file=None, sandbox_runtime="runc", allow_insecure_runtime=True)
    assert Settings(_env_file=None, sandbox_runtime="runsc", allow_insecure_runtime=False)


@pytest.mark.parametrize("stdout,expected", [
    ('{"runtimes":{"runc":{},"runsc":{}},"default":"runsc"}', True),
    # Registered but not the default: buildx's executor would inherit the weaker default.
    ('{"runtimes":{"runc":{},"runsc":{}},"default":"runc"}', False),
    # Names that merely contain or end with the required one are different runtimes.
    ('{"runtimes":{"runc":{},"xrunsc":{}},"default":"xrunsc"}', False),
    ('{"runtimes":{"runc":{},"runsc-debug":{}},"default":"runsc-debug"}', False),
    ('{"runtimes":{"runc":{"path":"runsc"}},"default":"runsc"}', False),
    ('{"runtimes":["runsc"],"default":"runsc"}', False),
    ('{"runtimes":{"runc":{}}} runsc', False),
    ("", False),
])
async def test_runtime_must_be_registered_and_default_by_parsed_name(monkeypatch, stdout, expected):
    async def fake_run(argv, *, stdin=None, timeout):
        assert argv[:2] == ["docker", "info"]
        return ProcessResult(0, stdout + "\n", "", False, 0)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    assert await docker.runtime_available("runsc") is expected


async def test_runtime_probe_template_is_one_json_document(monkeypatch):
    seen = []

    async def fake_run(argv, *, stdin=None, timeout):
        seen.append(argv[-1])
        return ProcessResult(1, "", "daemon down", False, 0)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    assert await docker.runtime_available("runsc") is False
    template = seen[0]
    # Filling every action with a JSON value must yield a JSON object.
    filled = template.replace("{{json .Runtimes}}", '{"runsc":{}}').replace(
        "{{json .DefaultRuntime}}", '"runsc"')
    assert json.loads(filled) == {"runtimes": {"runsc": {}}, "default": "runsc"}


async def test_a_host_without_docker_reports_no_runtime_rather_than_raising(monkeypatch):
    async def no_client(argv, *, stdin=None, timeout):
        raise SandboxUnavailable("the Docker client is not installed on this host")

    monkeypatch.setattr(engine, "run_docker", no_client)
    assert await docker.docker_available() is False
    assert await docker.runtime_available("runsc") is False
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(get_settings(), "sandbox_runtime", "runsc", raising=False)
    with pytest.raises(SandboxUnavailable, match="not available on this host"):
        await ensure_runtime_available("test")


async def test_build_validates_the_spec_before_touching_the_daemon(monkeypatch):
    async def must_not_run(*_args, **_kwargs):
        raise AssertionError("the daemon was contacted for a disallowed spec")

    monkeypatch.setattr(engine, "run_docker", must_not_run)
    monkeypatch.setattr(docker, "runtime_available", must_not_run)
    spec = _spec().model_copy(update={"base_image": "someorg/python:3"})
    monkeypatch.setattr(get_settings(), "allowed_base_registries", ALLOW, raising=False)
    with pytest.raises(DisallowedBaseImage):
        await docker.build_image("/nonexistent", spec, "harness-target:x")


async def test_fail_closed_bypassed_when_insecure_allowed(monkeypatch):
    async def _no(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", True, raising=False)
    await ensure_runtime_available("test")  # no raise


def _spec(**kw):
    return EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                           test_command="python -m pytest -q -s {test_file}", **kw)


def test_dockerfile_stages_repo_readonly():
    df = docker.render_dockerfile(_spec())
    assert f"COPY --chown={docker.SANDBOX_USER} . {docker.REPO_STAGE}" in df
    assert f"LABEL {docker.IMAGE_LABEL}" in df
    assert f"WORKDIR {docker.REPO_STAGE}" in df


@pytest.mark.parametrize(
    "spec",
    [
        _spec().model_copy(update={"install_commands": ["echo ok\nUSER root"]}),
        _spec(env={"SAFE\nUSER root": "x"}),
        _spec(scope="partial", module_path="../../host"),
        _spec().model_copy(update={"test_command": "pytest tests"}),
    ],
)
def test_generated_fields_cannot_inject_dockerfile_structure(spec):
    with pytest.raises(InvalidEnvironmentSpec):
        docker.render_dockerfile(spec)


def test_build_argv_uses_buildx_and_proxy(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "use_buildx", True, raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://172.30.0.2:3128", raising=False)
    monkeypatch.setattr(s, "build_egress_network", "harness-egress", raising=False)
    argv = docker.build_argv("/tmp/Dockerfile", "tag:1", "/ctx")
    assert "buildx" in argv and "--builder" in argv and s.buildx_builder in argv
    assert argv[-2:] == ["--", "/ctx"]
    assert f"{docker.PROVENANCE_LABEL}=tag:1" in argv
    joined = " ".join(argv)
    assert "HTTP_PROXY=http://172.30.0.2:3128" in joined
    assert "NO_PROXY=localhost,127.0.0.1" in joined
    assert "--network=default" in argv
    assert "--network=harness-egress" not in argv


async def test_build_egress_fails_closed_without_internal_network(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://172.30.0.2:3128", raising=False)
    monkeypatch.setattr(s, "build_egress_host_ip", "172.30.0.2", raising=False)
    monkeypatch.setattr(s, "build_egress_network", "ordinary-network", raising=False)

    async def fake_run(argv, *, stdin=None, timeout):
        return ProcessResult(0, "false\n", "", False, 0)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    with pytest.raises(SandboxUnavailable, match="not internal"):
        await docker.ensure_build_egress_boundary()


async def test_builder_is_created_on_internal_network_and_verified(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "use_buildx", True, raising=False)
    monkeypatch.setattr(s, "build_egress_network", "harness-egress", raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://172.30.0.2:3128", raising=False)
    monkeypatch.setattr(s, "build_egress_host_ip", "172.30.0.2", raising=False)
    monkeypatch.setattr(s, "sandbox_runtime", "runsc", raising=False)
    calls = []

    async def fake_run(argv, *, stdin=None, timeout):
        calls.append(argv)
        if argv[:3] == ["docker", "buildx", "inspect"] and len(calls) == 1:
            return ProcessResult(1, "", "missing", False, 0)
        if argv[:3] == ["docker", "buildx", "create"]:
            return ProcessResult(0, "created", "", False, 0)
        if argv[:3] == ["docker", "buildx", "inspect"]:
            return ProcessResult(
                0, f"Name: {s.buildx_builder}\nDriver: docker-container\n"
                f"Name: {s.buildx_builder}0\n", "", False, 0
            )
        if argv[-1] == "{{.HostConfig.Runtime}}":
            return ProcessResult(0, "runsc\n", "", False, 0)
        if argv[-1] == "{{json .NetworkSettings.Networks}}":
            return ProcessResult(0, '{"harness-egress": {}}\n', "", False, 0)
        if argv[-1] == "{{json .Config.Env}}":
            environment = [
                f"{name}={value}" for name, value in builder_proxy_environment().items()
            ]
            return ProcessResult(0, json.dumps(environment), "", False, 0)
        raise AssertionError(argv)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    await docker.ensure_builder()

    create = next(call for call in calls if call[:3] == ["docker", "buildx", "create"])
    start = create.index("--driver-opt")
    assert create[start:start + 2] == ["--driver-opt", "network=harness-egress"]
    options = [create[index + 1] for index, value in enumerate(create) if value == "--driver-opt"]
    decoded = [next(csv.reader([option])) for option in options]
    assert all(len(row) == 1 and "=" in row[0] for row in decoded)
    assert ["env.NO_PROXY=localhost,127.0.0.1"] in decoded
    assert ["env.no_proxy=localhost,127.0.0.1"] in decoded
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        assert f"env.{name}=http://172.30.0.2:3128" in create


async def test_existing_builder_with_extra_network_fails_closed(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "use_buildx", True, raising=False)
    monkeypatch.setattr(s, "build_egress_network", "harness-egress", raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://172.30.0.2:3128", raising=False)
    monkeypatch.setattr(s, "build_egress_host_ip", "172.30.0.2", raising=False)
    monkeypatch.setattr(s, "sandbox_runtime", "runsc", raising=False)

    async def fake_run(argv, *, stdin=None, timeout):
        if argv[:3] == ["docker", "buildx", "inspect"]:
            return ProcessResult(
                0, f"Name: {s.buildx_builder}\nDriver: docker-container\n"
                f"Name: {s.buildx_builder}0\n", "", False, 0
            )
        if argv[-1] == "{{.HostConfig.Runtime}}":
            return ProcessResult(0, "runsc\n", "", False, 0)
        return ProcessResult(
            0, '{"harness-egress": {}, "bridge": {}}\n', "", False, 0
        )

    monkeypatch.setattr(engine, "run_docker", fake_run)
    with pytest.raises(SandboxUnavailable, match="do not match"):
        await docker.ensure_builder()


@pytest.mark.parametrize("host_ip,proxy", [
    ("egress-proxy", "http://egress-proxy:3128"),
    ("172.30.0.2", "http://172.30.0.3:3128"),
    ("::1", "http://[::1]:3128"),
])
async def test_secure_builder_rejects_non_numeric_or_mismatched_proxy(monkeypatch, host_ip, proxy):
    s = get_settings()
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "build_egress_network", "harness-egress", raising=False)
    monkeypatch.setattr(s, "build_egress_host_ip", host_ip, raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", proxy, raising=False)
    with pytest.raises(SandboxUnavailable, match="IPv4|exactly matches"):
        await docker.ensure_builder()


async def test_existing_builder_with_stale_proxy_fails_closed(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "use_buildx", True, raising=False)
    monkeypatch.setattr(s, "build_egress_network", "harness-egress", raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://172.30.0.2:3128", raising=False)
    monkeypatch.setattr(s, "build_egress_host_ip", "172.30.0.2", raising=False)
    monkeypatch.setattr(s, "sandbox_runtime", "runsc", raising=False)

    async def fake_run(argv, *, stdin=None, timeout):
        if argv[:3] == ["docker", "buildx", "inspect"]:
            return ProcessResult(
                0, f"Name: {s.buildx_builder}\nDriver: docker-container\n"
                f"Name: {s.buildx_builder}0\n", "", False, 0
            )
        if argv[-1] == "{{.HostConfig.Runtime}}":
            return ProcessResult(0, "runsc\n", "", False, 0)
        if argv[-1] == "{{json .NetworkSettings.Networks}}":
            return ProcessResult(0, '{"harness-egress": {}}\n', "", False, 0)
        if argv[-1] == "{{json .Config.Env}}":
            return ProcessResult(
                0, '["HTTP_PROXY=http://user:stale-secret@172.30.0.99:3128",'
                '"ALL_PROXY=http://other-secret@172.30.0.98:3128"]', "", False, 0)
        raise AssertionError(argv)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    with pytest.raises(SandboxUnavailable, match="proxy configuration is stale") as exc_info:
        await docker.ensure_builder()
    message = str(exc_info.value)
    assert "HTTP_PROXY" in message and "ALL_PROXY" in message
    assert "stale-secret" not in message and "other-secret" not in message


async def test_run_probe_readonly_argv_shape(monkeypatch):
    # Inspect the docker run argv the probe would use (via a captured _run).
    captured = {}

    async def fake_run(argv, *, stdin=None, timeout):
        captured["argv"] = argv
        captured["stdin"] = stdin
        return ProcessResult(exit_code=0, stdout=f"{docker.PRECONDITION_PREFIX}n",
                                 stderr="", timed_out=False, duration_s=0.1)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    monkeypatch.setattr(get_settings(), "sandbox_read_only_root", True, raising=False)
    await docker.run_probe("img", "tests/t.py", "print('x')", "pytest {test_file}", "n")
    argv = captured["argv"]
    assert "--read-only" in argv and "--network=none" in argv
    assert any(a.startswith("--tmpfs=/work") for a in argv)
    assert captured["stdin"] == b"print('x')"


async def test_run_shell_is_read_only_no_network_and_staged(monkeypatch):
    calls = []

    async def fake_run(argv, *, stdin=None, timeout):
        calls.append(argv)
        return ProcessResult(0, "ok", "", False, 0)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    monkeypatch.setattr(get_settings(), "sandbox_read_only_root", True, raising=False)
    await docker.run_shell("img", "echo hi", idempotency_key="operation-2")
    name = docker.container_name("operation-2")
    # A stale container from a crashed attempt is removed before the retry starts.
    assert calls[0] == ["docker", "rm", "-f", name]
    argv = calls[1]
    assert "--read-only" in argv and "--network=none" in argv
    assert any(a.startswith("--tmpfs=/work") for a in argv)
    assert any(a.startswith("--tmpfs=/tmp") for a in argv)
    assert argv[-1].startswith("set -e; cp -a /opt/repo /work/repo;")
    assert argv[-1].endswith("set +e; echo hi")


@pytest.mark.parametrize("labels,expected", [
    ({"harness.image": "target", docker.PROVENANCE_LABEL: "harness-target:a-b"}, True),
    ({"harness.image": "target"}, False),
    ({"harness.image": "target", docker.PROVENANCE_LABEL: "harness-target:other"}, False),
    ({docker.PROVENANCE_LABEL: "harness-target:a-b"}, False),
    (None, False),
])
async def test_cached_image_requires_harness_provenance(monkeypatch, labels, expected):
    async def fake_run(argv, *, stdin=None, timeout):
        assert argv[:3] == ["docker", "image", "inspect"] and argv[-2:] == ["--", "harness-target:a-b"]
        return ProcessResult(0, json.dumps(labels), "", False, 0)

    monkeypatch.setattr(engine, "run_docker", fake_run)
    assert await docker.image_exists("harness-target:a-b") is expected


def test_image_tag_identity_includes_build_boundary_mode(monkeypatch):
    s = get_settings()
    spec = _spec()
    monkeypatch.setattr(s, "build_egress_proxy", "", raising=False)
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    secure = docker.image_tag_for("repohash", spec)
    monkeypatch.setattr(s, "allow_insecure_runtime", True, raising=False)
    assert docker.image_tag_for("repohash", spec) != secure
    monkeypatch.setattr(s, "allow_insecure_runtime", False, raising=False)
    monkeypatch.setattr(s, "build_egress_network", "another-network", raising=False)
    assert docker.image_tag_for("repohash", spec) != secure


async def test_cancelled_named_workload_is_removed(monkeypatch):
    started = asyncio.Event()
    removed = []

    async def fake_run(argv, *, stdin=None, timeout):
        if argv[:3] == ["docker", "rm", "-f"]:
            removed.append(argv[-1])
            return ProcessResult(0, "", "", False, 0)
        started.set()
        await asyncio.Future()

    monkeypatch.setattr(engine, "run_docker", fake_run)
    task = asyncio.create_task(docker.run_shell("img", "sleep 30", idempotency_key="operation-1"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Once before the run (stale same-name container) and once after cancellation.
    assert removed == [docker.container_name("operation-1")] * 2


async def test_build_and_probe_activities_with_faked_sandbox(tmp_path, monkeypatch):
    """Build/probe workloads run with the hardening (fail-closed + base-image) when the
    runtime is faked present — the logic the Temporal activities wrap, minus Temporal."""
    from infosec_harness.domain.models import ProbeSource, RepoSnapshot
    from infosec_harness.graph import workloads

    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    (tmp_path / "requirements.txt").write_text("")

    async def _rt(runtime=None):
        return True

    async def _exists(tag):
        return False

    async def _build(path, spec, tag):
        return ProcessResult(exit_code=0, stdout="built", stderr="", timed_out=False, duration_s=0.1)

    async def _probe(image, tfp, content, cmd, nonce, module_path=""):
        return ProcessResult(exit_code=0, stdout=f"{docker.PRECONDITION_PREFIX}{nonce}",
                                 stderr="", timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "runtime_available", _rt)
    monkeypatch.setattr(docker, "image_exists", _exists)
    monkeypatch.setattr(docker, "build_image", _build)
    monkeypatch.setattr(docker, "run_probe", _probe)

    snap = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="h" * 8)
    spec = EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                          test_command="python -m pytest -q -s {test_file}")
    build = await workloads.build_environment(snap, spec)
    assert build.ok and build.image_tag

    probe = ProbeSource(test_file_path="tests/t.py", content="print('HARNESS')")
    ex = await workloads.execute_probe(build.image_tag, probe, spec, "abc", 1)
    assert ex.precondition_reached and ex.exit_code == 0


async def test_build_activity_fails_closed_without_runtime(tmp_path, monkeypatch):
    from infosec_harness.domain.models import RepoSnapshot
    from infosec_harness.graph import workloads

    async def _no(runtime=None):
        return False

    async def _exists(tag):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(docker, "image_exists", _exists)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    snap = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="h" * 8)
    spec = EnvironmentSpec(base_image="python:3.12-slim", install_commands=[],
                          test_command="pytest {test_file}")
    build = await workloads.build_environment(snap, spec)
    assert not build.ok and "runsc" in build.error_excerpt
