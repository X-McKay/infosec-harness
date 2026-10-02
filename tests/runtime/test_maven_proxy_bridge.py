"""Build-only native Resolver proxy bridge; no daemon or repository requests."""
import shlex
from types import SimpleNamespace

import pytest

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import docker
from infosec_harness.sandbox.policy import SandboxUnavailable


def configure(monkeypatch, proxy="http://192.0.2.10:3128", host="192.0.2.10"):
    monkeypatch.setattr(docker, "get_settings", lambda: SimpleNamespace(build_egress_proxy=proxy, build_egress_host_ip=host))


def spec(runner="mvn", **overrides):
    return EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-21", install_commands=["mvn -B -s settings.xml -DskipTests test-compile"], test_command=f"{runner} -B -o test-compile -Dtest=HarnessProbeTest", **overrides)


@pytest.mark.parametrize("runner", ["mvn", "./mvnw", "/opt/apache-maven/bin/mvn", "'mvn'"])
def test_recognized_maven_runners_get_build_only_bridge(monkeypatch, runner):
    configure(monkeypatch)
    rendered = docker.render_dockerfile(spec(runner))
    install = next(line for line in rendered.splitlines() if line.startswith("RUN export MAVEN_OPTS="))
    assert "-Daether.connector.http.useSystemProperties=true" in install
    assert "-Dhttp.proxyHost=192.0.2.10 -Dhttp.proxyPort=3128" in install
    assert "-Dhttps.proxyHost=192.0.2.10 -Dhttps.proxyPort=3128" in install
    assert "-Dhttp.nonProxyHosts=localhost|127.0.0.1" in install
    assert install.endswith("; mvn -B -s settings.xml -DskipTests test-compile")
    assert not any(line.startswith("ENV MAVEN_OPTS=") for line in rendered.splitlines())
    assert "settings.xml" in install and "--global-settings" not in rendered


def test_empty_proxy_preserves_original_install_commands(monkeypatch):
    configure(monkeypatch, proxy="")
    rendered = docker.render_dockerfile(spec())
    assert "RUN mvn -B -s settings.xml -DskipTests test-compile" in rendered
    assert "useSystemProperties" not in rendered and "export MAVEN_OPTS=" not in rendered


@pytest.mark.parametrize("command", ["python -m pytest {test_file}", "gradle test --tests HarnessProbeTest"])
def test_other_runners_do_not_get_maven_bridge(monkeypatch, command):
    configure(monkeypatch)
    value = spec().model_copy(update={"test_command": command})
    assert "MAVEN_OPTS" not in docker.render_dockerfile(value)


@pytest.mark.parametrize("proxy,host", [
    ("http://proxy.example:3128", "192.0.2.10"),
    ("http://192.0.2.11:3128", "192.0.2.10"),
    ("https://192.0.2.10:3128", "192.0.2.10"),
    ("http://user:secret@192.0.2.10:3128", "192.0.2.10"),
    ("http://192.0.2.10:3128/path", "192.0.2.10"),
    ("http://192.0.2.10:3128?query=bad", "192.0.2.10"),
    ("http://127.0.0.1:3128", "127.0.0.1"),
])
def test_invalid_operator_proxy_rejected_for_render_and_cache(monkeypatch, proxy, host):
    configure(monkeypatch, proxy=proxy, host=host)
    with pytest.raises(SandboxUnavailable):
        docker.render_dockerfile(spec())
    with pytest.raises(SandboxUnavailable):
        docker.image_tag_for("sealed-source", spec())


def test_proxy_switch_changes_maven_target_cache_identity(monkeypatch):
    configure(monkeypatch)
    original = docker.image_tag_for("sealed-source", spec())
    configure(monkeypatch, proxy="http://192.0.2.11:3128", host="192.0.2.11")
    assert docker.image_tag_for("sealed-source", spec()) != original
    configure(monkeypatch, proxy="http://192.0.2.10:3129")
    assert docker.image_tag_for("sealed-source", spec()) != original
    configure(monkeypatch, proxy="")
    assert docker.image_tag_for("sealed-source", spec()) != original
    assert docker.IMAGE_FORMAT_VERSION == "3"


async def test_run_prefix_preserves_existing_opts_and_original_settings(tmp_path, monkeypatch):
    configure(monkeypatch)
    executable = tmp_path / "mvn"
    executable.write_text('#!/bin/sh\nprintf "%s" "$MAVEN_OPTS" > "$CAPTURE_FILE"\nprintf "%s\n" "$@" > "$ARGUMENT_FILE"\n')
    executable.chmod(0o700)
    captured = tmp_path / "captured"
    arguments = tmp_path / "arguments"
    import os
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("MAVEN_OPTS", "-Xmx128m -Dretained.setting=unchanged")
    monkeypatch.setenv("CAPTURE_FILE", str(captured))
    monkeypatch.setenv("ARGUMENT_FILE", str(arguments))
    install = next(line.removeprefix("RUN ") for line in docker.render_dockerfile(spec()).splitlines() if line.startswith("RUN export MAVEN_OPTS="))
    result = await docker._run(["/bin/sh", "-c", install], timeout=5)
    assert result.exit_code == 0
    values = shlex.split(captured.read_text())
    assert values[:2] == ["-Xmx128m", "-Dretained.setting=unchanged"]
    assert "-Daether.connector.http.useSystemProperties=true" in values
    assert "-Dhttp.nonProxyHosts=localhost|127.0.0.1" in values
    assert arguments.read_text().splitlines() == ["-B", "-s", "settings.xml", "-DskipTests", "test-compile"]
    assert os.environ["MAVEN_OPTS"] == "-Xmx128m -Dretained.setting=unchanged"
