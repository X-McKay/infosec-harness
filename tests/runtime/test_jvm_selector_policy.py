"""Single-class selector consistency from rendering to probe invocation.

One parser (``policy.jvm_class_selector``) decides the class: the Dockerfile validation and the
control-test writer both read it, so they cannot disagree.
"""
from types import SimpleNamespace

import pytest

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import canary, docker, policy


@pytest.fixture
def candidate():
    return policy


def environment(command):
    return EnvironmentSpec(base_image='maven:3.9-eclipse-temurin-21', test_command=command)


@pytest.mark.parametrize('command', [
    'mvn -q -B -o test -Dtest=HarnessProbeTest -Dmaven.repo.local=/work/home/.m2/repository',
    '/opt/bin/mvn -B -o test -Dtest=HarnessProbeTest',
    'mvn -o test -Dtest=OtherTest',
    "mvn -o test '-Dtest=OtherTest'",
    "gradle --offline test --tests '*OtherTest'",
    './mvnw -o test -Dtest=HarnessProbeTest',
    "./gradlew --offline test --tests '*HarnessProbeTest'",
    'gradle --offline test --tests HarnessProbeTest',
])
async def test_render_and_probe_keep_one_named_class_without_substituting_path(candidate, monkeypatch, command):
    selected = 'OtherTest' if 'OtherTest' in command else 'HarnessProbeTest'
    assert candidate.jvm_class_selector(command) == selected
    assert docker.render_dockerfile(environment(command)).startswith('FROM maven:')
    path, content = canary.canary_for('java', command)
    assert path == f'src/test/java/{selected}.java'
    assert f'public class {selected}' in content
    observed = []

    async def fake_container(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(exit_code=0)

    monkeypatch.setattr(docker, '_run_container', fake_container)
    result = await docker.run_probe('owned-test-image', path, content, command, 'offline-nonce')
    assert result.exit_code == 0 and len(observed) == 1
    argv, kwargs = observed[0]
    script = argv[-1]
    assert f'( {command} )' in script
    assert f'-Dtest={path}' not in script and f'--tests {path}' not in script
    assert '--network=none' in argv and '--read-only' in argv
    assert kwargs['stdin'] == content.encode()


@pytest.mark.parametrize('command', [
    'mvn -o test', 'mvn -o test -Dtest=',
    'mvn -o test -Dtest={test_file}',
    'mvn -o test -Dtest=src/test/java/HarnessProbeTest.java',
    'mvn -o test -Dtest=HarnessProbeTest -Dtest=OtherTest',
    'mvn -o test -Dtest=*', 'mvn -o test -Dtest=HarnessProbeTest,OtherTest',
    'mvn -o test -Dtest=com.example.HarnessProbeTest',
    "mvn -o test -Dtest='OtherTest'",
    "mvn -o test -Dtest='HarnessProbeTest'",
    'mvn -o test -Dother=-Dtest=OtherTest -Dtest=FooTest',
    'mvn -o test -Dtest=HarnessProbeTest#method',
    'mvn -o test -Dtest=HarnessProbeTest && echo ok',
    'mvn -o test -Dtest=HarnessProbeTest; echo ok',
    'mvn -o test -Dtest=HarnessProbeTest | cat',
    'mvn -o test -Dtest=HarnessProbeTest > output',
    'mvn -o test -Dtest=HarnessProbeTest $(echo extra)',
    'mvn -o test -Dtest=HarnessProbeTest --tests OtherTest',
    'gradle --offline test', "gradle --offline test --tests '*'",
    "gradle --offline test --tests '**HarnessProbeTest'",
    "gradle --offline test --tests 'Harness*Test'",
    'gradle --offline test --tests com.example.HarnessProbeTest',
    'gradle --offline test --tests=HarnessProbeTest',
    'gradle --offline test --tests HarnessProbeTest --tests OtherTest',
    'gradle --offline test -Dtest=HarnessProbeTest',
    "mvn -o test -Dtest='HarnessProbeTest",
])
def test_invalid_jvm_selectors_never_render(candidate, command):
    with pytest.raises(candidate.InvalidEnvironmentSpec):
        docker.render_dockerfile(environment(command))
    # Nor is a control test written under a guessed class name.
    with pytest.raises(candidate.InvalidEnvironmentSpec):
        canary.canary_for('java', command)


@pytest.mark.parametrize('command', ['pytest -q {test_file}', 'prove -v {test_file}', 'npx jest --runTestsByPath {test_file}'])
def test_path_runners_keep_exact_one_placeholder(candidate, command):
    assert candidate.jvm_class_selector(command) is None
    assert candidate.validate_environment_spec(environment(command)).test_command == command
    for changed in (command.replace('{test_file}', 'tests'), command + ' {test_file}'):
        with pytest.raises(candidate.InvalidEnvironmentSpec):
            docker.render_dockerfile(environment(changed))


@pytest.mark.parametrize('updates', [
    {'base_image': 'foreign.example/image:1'}, {'env': {'BAD\nUSER root': 'x'}},
    {'install_commands': ['echo ok\nUSER root']}, {'system_packages': ['bad;token']},
    {'scope': 'partial', 'module_path': '../../host'},
])
def test_class_alternative_does_not_bypass_existing_structure_or_path_guards(candidate, updates):
    spec = environment('mvn -o test -Dtest=HarnessProbeTest').model_copy(update=updates)
    with pytest.raises((candidate.InvalidEnvironmentSpec, candidate.DisallowedBaseImage)):
        docker.render_dockerfile(spec)
