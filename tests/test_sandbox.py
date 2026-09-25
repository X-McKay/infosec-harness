from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import docker


def _spec(**kw):
    return EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                           test_command="python -m pytest -q -s {test_file}", **kw)


def test_dockerfile_is_deterministic_and_nonroot():
    df = docker.render_dockerfile(_spec(system_packages=["gcc"]))
    assert df == docker.render_dockerfile(_spec(system_packages=["gcc"]))
    assert f"USER {docker.SANDBOX_USER}" in df
    assert "COPY --chown" in df


def test_partial_scope_sets_module_workdir():
    df = docker.render_dockerfile(_spec(scope="partial", module_path="services/api"))
    assert "WORKDIR /opt/repo/services/api" in df


def test_oracle_signals_match_nonce():
    n = "abc123"
    assert docker.oracle_signals(f"{docker.ORACLE_PREFIX}{n}", n) == (True, True)
    assert docker.oracle_signals(f"{docker.PRECONDITION_PREFIX}{n}", n) == (False, True)
    assert docker.oracle_signals("nothing", n) == (False, False)
    assert docker.oracle_signals(f"{docker.ORACLE_PREFIX}other", n) == (False, False)


def test_image_tag_changes_with_spec():
    t1 = docker.image_tag_for("repohash", _spec())
    t2 = docker.image_tag_for("repohash", _spec(system_packages=["gcc"]))
    assert t1 != t2
