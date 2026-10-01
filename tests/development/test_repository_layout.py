"""Developer entry points must locate the renamed UI and keep local outputs ignored."""

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ComposeLoader(yaml.SafeLoader):
    """Read Compose reset/override tags without needing a Docker daemon."""


def _compose_tag(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


for _tag in ("!reset", "!override"):
    ComposeLoader.add_constructor(_tag, _compose_tag)


def test_compose_ui_build_and_editable_mount_resolve_to_the_same_directory():
    base = yaml.load((ROOT / "docker-compose.yml").read_text(), Loader=ComposeLoader)
    overlay = yaml.load((ROOT / "docker-compose.dev.yml").read_text(), Loader=ComposeLoader)
    context = (ROOT / base["services"]["web"]["build"]).resolve()
    mounts = overlay["services"]["web"]["volumes"]
    source = next(mount.split(":")[0] for mount in mounts if ":/app:ro" in mount)
    assert context == (ROOT / source).resolve() == ROOT / "ui"
    for required in ("Dockerfile", "package.json", "package-lock.json", "src/main.tsx"):
        assert (context / required).is_file()


def test_transient_outputs_remain_ignored_after_the_directory_move():
    outputs = [
        ".harness/logs/compose-example", ".harness/reports/evals/exp-example.json",
        "ui/dist/index.html", "ui/node_modules/.cache/tsconfig.tsbuildinfo",
    ]
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", *outputs], cwd=ROOT,
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == set(outputs)


def test_temporal_history_and_visibility_use_separate_schema_databases():
    base = yaml.load((ROOT / "docker-compose.yml").read_text(), Loader=ComposeLoader)
    temporal = base["services"]["temporal"]["environment"]
    assert temporal["DBNAME"] != temporal["VISIBILITY_DBNAME"]
    bootstrap = (ROOT / "deploy/postgres-init.sh").read_text()
    for name in (temporal["DBNAME"], temporal["VISIBILITY_DBNAME"]):
        assert f"CREATE DATABASE {name}'" in bootstrap


def test_temporal_database_bootstrap_sends_idempotent_sql(tmp_path):
    import os

    psql = tmp_path / "psql"
    psql.write_text("#!/bin/sh\ncat\n")
    psql.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/postgres-init.sh")], capture_output=True, text=True,
        env={**os.environ, "POSTGRES_USER": "fixture", "PATH": f"{tmp_path}:{os.environ['PATH']}"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("CREATE DATABASE") == 2
    for name in ("temporal", "temporal_visibility"):
        assert f"SELECT 'CREATE DATABASE {name}' WHERE NOT EXISTS" in result.stdout
        assert f"datname = '{name}')\\gexec" in result.stdout
