"""Generate an isolated executor context from the current immutable dependency lock.

Run using the checkout's pinned Python environment, then build the output with the
existing runsc build-egress builder. No deployment or credentials are provisioned.
"""

from __future__ import annotations

import argparse
import shutil
import tomllib
from pathlib import Path

from packaging.markers import Marker, default_environment


def build_context(root: Path, output: Path, *, machine: str = "aarch64") -> None:
    if output.is_symlink() or output.exists():
        raise ValueError("Choose a new private build context directory")
    output.mkdir(parents=True, mode=0o700)
    lock = tomllib.loads((root / "uv.lock").read_text())
    packages = {}
    for package in lock["package"]:
        if package["name"] in packages:
            raise ValueError("Ambiguous lock version requires explicit platform qualification")
        packages[package["name"]] = package
    environment = {
        **default_environment(),
        "sys_platform": "linux",
        "platform_system": "Linux",
        "os_name": "posix",
        "platform_machine": machine,
        "python_version": "3.12",
        "python_full_version": "3.12.0",
    }
    pending = ["pydantic-ai-slim", "openai", "tiktoken", "httpx"]
    selected = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages[name]
        if package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ValueError("Executor dependencies must be hash-pinned public registry artifacts")
        selected[name] = package
        for dependency in package.get("dependencies", []):
            if not dependency.get("marker") or Marker(dependency["marker"]).evaluate(environment):
                pending.append(dependency["name"])
    requirements = []
    for name, package in sorted(selected.items()):
        hashes = sorted(
            {artifact["hash"] for artifact in package.get("wheels", [])}
            | ({package["sdist"]["hash"]} if package.get("sdist") else set())
        )
        if not hashes:
            raise ValueError("Unhashed executor dependency")
        requirements.append(
            f"{name}=={package['version']} " + " ".join(f"--hash={value}" for value in hashes)
        )
    (output / "requirements.txt").write_text("\n".join(requirements) + "\n")
    package_dir = output / "infosec_harness"
    (package_dir / "inference").mkdir(parents=True)
    (package_dir / "agents").mkdir()
    for path in (package_dir, package_dir / "inference", package_dir / "agents"):
        (path / "__init__.py").write_text("")
    for name in ("auth", "codec", "compat", "diagnostics", "executor", "http_service", "protocol", "timing"):
        shutil.copyfile(
            root / f"src/infosec_harness/inference/{name}.py", package_dir / f"inference/{name}.py"
        )
    shutil.copyfile(
        root / "src/infosec_harness/agents/intake_schema.py",
        package_dir / "agents/intake_schema.py",
    )
    shutil.copyfile(root / "deploy/openshell/Dockerfile.executor", output / "Dockerfile")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--machine", choices=("aarch64", "x86_64"), default="aarch64")
    args = parser.parse_args()
    build_context(Path(__file__).resolve().parents[2], args.output, machine=args.machine)
