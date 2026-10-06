"""Run each corpus fixture's maintainer tests against its variant, outside any agent input.

Fixture tests demonstrate the behaviour of their own variant, so they would tell an agent the
answer. They live under eval-corpus/verification/<lang>/<topic>/<a|b>/, mirroring the
fixture's layout, and never enter a snapshot. For each verification directory this copies the
matching fixture into a temporary directory, overlays the tests and runs the language's runner.

Every runner must pass, except a C variant the manifest marks potentially_exploitable: its
`make test` must abort with an AddressSanitizer report. One line per fixture; non-zero exit on
any failure. Standard library only; reading the manifest here is maintainer-side scoring data.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "eval-corpus"
VERIFICATION = CORPUS / "verification"
IGNORED = shutil.ignore_patterns(".git", ".venv", "venv", "node_modules", "__pycache__")
TIMEOUT_SECONDS = 300
RUNNERS = {"python": "pytest", "javascript": "node --test", "perl": "prove -l t", "c": "make test"}


def pinned_node() -> Path:
    version = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]["node"]
    return ROOT / ".harness/mise/installs/node" / version / "bin/node"


def verification_dirs() -> list[Path]:
    return sorted(path for path in VERIFICATION.glob("*/*/*") if path.is_dir())


def expected_verdicts() -> dict[str, str]:
    cases = json.loads((CORPUS / "manifest.json").read_text())["cases"]
    return {
        case["finding"]["repo_url"].removeprefix("eval-corpus/"): case["truth"]["expected_verdict"]
        for case in cases
    }


def command(language: str, repo: Path, python: str, node: str) -> list[str]:
    if language == "python":
        return [python, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                "--rootdir", str(repo), "-c", os.devnull, "."]
    if language == "javascript":
        script = json.loads((repo / "package.json").read_text()).get("scripts", {}).get("test")
        if script != "node --test":
            raise ValueError(f"unsupported offline test script {script!r}")
        return [node, "--test"]
    if language == "perl":
        return ["prove", "-l", "t"]
    if language == "c":
        return ["make", "test", "CC=cc"]
    raise ValueError(f"no offline runner for {language}")


def verify(fixture: str, verdict: str | None, python: str, node: str) -> tuple[bool, str]:
    language = fixture.split("/", 1)[0]
    source = CORPUS / fixture
    if not source.is_dir() or verdict is None:
        return False, "no matching fixture in the manifest"
    with tempfile.TemporaryDirectory(prefix="corpus-verify-") as temporary:
        repo = Path(temporary) / "repo"
        shutil.copytree(source, repo, ignore=IGNORED)
        shutil.copytree(VERIFICATION / fixture, repo, dirs_exist_ok=True, ignore=IGNORED)
        try:
            argv = command(language, repo, python, node)
        except ValueError as error:
            return False, str(error)
        environment = dict(os.environ, PATH=f"{Path(node).parent}{os.pathsep}{os.environ['PATH']}")
        try:
            result = subprocess.run(argv, cwd=repo, env=environment, capture_output=True,
                                    text=True, timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return False, f"{argv[-1]} timed out after {TIMEOUT_SECONDS} s"
    output = (result.stdout + result.stderr).strip().splitlines()
    last = output[-1][:100] if output else ""
    runner = RUNNERS[language]
    if language == "c" and verdict == "potentially_exploitable":
        aborted = result.returncode != 0 and "AddressSanitizer" in result.stdout + result.stderr
        return aborted, f"{runner}: exit {result.returncode}, sanitizer abort expected"
    return result.returncode == 0, f"{runner}: exit {result.returncode}; {last}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="interpreter with pytest")
    parser.add_argument("--node", help="node binary (default: the pinned .harness install)")
    args = parser.parse_args()
    node = Path(args.node) if args.node else pinned_node()
    if not node.is_file():
        print(f"node not found at {node}; pass --node", file=sys.stderr)
        return 2
    verdicts = expected_verdicts()
    failures = 0
    directories = verification_dirs()
    for directory in directories:
        fixture = directory.relative_to(VERIFICATION).as_posix()
        ok, detail = verify(fixture, verdicts.get(fixture), args.python, str(node))
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} {fixture:28} {detail}", flush=True)
    print(f"{len(directories) - failures} of {len(directories)} fixtures verified")
    return 1 if failures or not directories else 0


if __name__ == "__main__":
    sys.exit(main())
