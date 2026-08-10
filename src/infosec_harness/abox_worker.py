"""Narrow, no-network abox microVM worker planning.

This module is deliberately not an active-validation backend.  It stages one
sealed controller artifact read-only and has a fixed guest program return only
its SHA-256.  Target repositories, target commands, credentials, and egress
are never accepted as inputs.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_SEALED_INPUT_BYTES = 64 * 1024 * 1024
MAX_CONSOLE_BYTES = 16 * 1024
EXPECTED_ABOX_VERSION = "abox 0.6.0"
_TASK_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9])?$")
_CONTROLLER_PROJECT_CONFIG = Path(__file__).parents[2] / ".abox" / "project.toml"
_GUEST_DIGEST_PROGRAM = (
    "import hashlib,os,pathlib;"
    "p=pathlib.Path(os.environ['ABOX_INPUT_FILE']);"
    "print(hashlib.sha256(p.read_bytes()).hexdigest())"
)


class AboxWorkerError(ValueError):
    """A controller-side refusal before any guest is started."""


@dataclass(frozen=True)
class SealedArtifact:
    """Bounded bytes captured once by the controller before a guest exists."""

    sha256: str
    source_name: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class AboxWorkerPlan:
    """An inspectable exact invocation for one sealed, no-network artifact."""

    workspace: Path
    task_id: str
    artifact: SealedArtifact
    worker_config_sha256: str
    timeout_seconds: int = 30

    def argv(self, staged_input: Path | None = None) -> list[str]:
        # The placeholder is intentional: a plan must never disclose a source
        # path, and the actual path is a private controller-created snapshot.
        input_path = staged_input or Path("<controller-sealed-artifact>")
        return [
            "abox",
            "run",
            "--repo",
            str(self.workspace),
            "--task",
            self.task_id,
            "--network",
            "safe",
            "--ephemeral",
            "--no-warm",
            "--timeout",
            str(self.timeout_seconds),
            "--input-file",
            f"{input_path}:sealed-evidence.json",
            "--",
            "python3",
            "-I",
            "-c",
            _GUEST_DIGEST_PROGRAM,
        ]


@dataclass(frozen=True)
class AboxWorkerResult:
    admitted: bool
    verified: bool
    reason: str
    task_id: str
    artifact_sha256: str
    worker_config_sha256: str
    workspace_commit: str | None = None
    abox_version: str | None = None
    console_sha256: str | None = None


def seal_input(source: Path) -> SealedArtifact:
    """Read a regular non-symlink file exactly once into a bounded snapshot."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise AboxWorkerError("sealed input must be a regular non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AboxWorkerError("sealed input must be a regular file")
        if metadata.st_size > MAX_SEALED_INPUT_BYTES:
            raise AboxWorkerError("sealed input exceeds the worker staging limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_SEALED_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_SEALED_INPUT_BYTES:
        raise AboxWorkerError("sealed input exceeds the worker staging limit")
    return SealedArtifact(
        sha256=hashlib.sha256(content).hexdigest(),
        source_name=source.name,
        content=content,
    )


def plan_no_network_worker(workspace: Path, sealed_input: Path, task_id: str) -> AboxWorkerPlan:
    return plan_from_sealed_artifact(workspace, seal_input(sealed_input), task_id)


def plan_from_sealed_artifact(
    workspace: Path, artifact: SealedArtifact, task_id: str
) -> AboxWorkerPlan:
    """Create an invocation plan without executing a guest or reading source bodies."""

    if not _TASK_ID.fullmatch(task_id):
        raise AboxWorkerError("invalid abox task identifier")
    if not workspace.is_dir():
        raise AboxWorkerError("controller workspace does not exist")
    try:
        approved_config = _CONTROLLER_PROJECT_CONFIG.read_bytes()
        workspace_config = (workspace / ".abox" / "project.toml").read_bytes()
    except OSError as exc:
        raise AboxWorkerError("controller workspace lacks the approved abox project configuration") from exc
    if not approved_config or workspace_config != approved_config:
        raise AboxWorkerError("controller workspace abox configuration does not match the approved safe profile")
    return AboxWorkerPlan(
        workspace=workspace.resolve(),
        task_id=task_id,
        artifact=artifact,
        worker_config_sha256=hashlib.sha256(approved_config).hexdigest(),
    )


def _result(plan: AboxWorkerPlan, admitted: bool, verified: bool, reason: str, **fields: str | None) -> AboxWorkerResult:
    return AboxWorkerResult(
        admitted,
        verified,
        reason,
        plan.task_id,
        plan.artifact.sha256,
        plan.worker_config_sha256,
        **fields,
    )


def _command_output(command: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError:
        return 127, "", "command unavailable"
    return completed.returncode, completed.stdout, completed.stderr


def _materialize_private_snapshot(artifact: SealedArtifact, directory: Path) -> Path:
    path = directory / "sealed-evidence.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(artifact.content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o400)
    if hashlib.sha256(path.read_bytes()).hexdigest() != artifact.sha256:
        raise AboxWorkerError("controller snapshot digest mismatch")
    return path


def run_no_network_worker(plan: AboxWorkerPlan) -> AboxWorkerResult:
    """Run only the fixed digest verifier after validating abox prerequisites."""

    if shutil.which("abox") is None:
        return _result(plan, False, False, "abox binary is unavailable")
    code, version, _ = _command_output(["abox", "--version"])
    abox_version = version.strip()
    if code != 0 or abox_version != EXPECTED_ABOX_VERSION:
        return _result(plan, False, False, "unapproved abox version", abox_version=abox_version or None)
    try:
        current_config = (plan.workspace / ".abox" / "project.toml").read_bytes()
    except OSError:
        return _result(plan, False, False, "controller workspace configuration disappeared", abox_version=abox_version)
    if hashlib.sha256(current_config).hexdigest() != plan.worker_config_sha256:
        return _result(plan, False, False, "controller workspace configuration changed", abox_version=abox_version)
    code, commit, _ = _command_output(["git", "-C", str(plan.workspace), "rev-parse", "HEAD"])
    workspace_commit = commit.strip() or None
    if code != 0 or workspace_commit is None:
        return _result(
            plan,
            False,
            False,
            "abox requires a controller-owned Git workspace",
            abox_version=abox_version,
        )
    with tempfile.TemporaryDirectory(prefix="infosec-harness-sealed-") as temporary:
        try:
            staged_input = _materialize_private_snapshot(plan.artifact, Path(temporary))
        except AboxWorkerError as exc:
            return _result(
                plan,
                False,
                False,
                str(exc),
                workspace_commit=workspace_commit,
                abox_version=abox_version,
            )
        try:
            completed = subprocess.run(
                plan.argv(staged_input),
                check=False,
                capture_output=True,
                text=True,
                timeout=plan.timeout_seconds + 20,
            )
        except subprocess.TimeoutExpired:
            return _result(
                plan,
                False,
                False,
                "abox worker timed out",
                workspace_commit=workspace_commit,
                abox_version=abox_version,
            )
    console = (completed.stdout + completed.stderr)[:MAX_CONSOLE_BYTES]
    console_sha = hashlib.sha256(console.encode("utf-8", errors="replace")).hexdigest()
    observed = [line.strip() for line in completed.stdout.splitlines() if re.fullmatch(r"[0-9a-f]{64}", line.strip())]
    if completed.returncode != 0:
        return _result(
            plan,
            False,
            False,
            "abox worker exited unsuccessfully",
            workspace_commit=workspace_commit,
            abox_version=abox_version,
            console_sha256=console_sha,
        )
    if observed != [plan.artifact.sha256]:
        return _result(
            plan,
            False,
            False,
            "sealed artifact digest mismatch",
            workspace_commit=workspace_commit,
            abox_version=abox_version,
            console_sha256=console_sha,
        )
    return _result(
        plan,
        True,
        True,
        "sealed artifact verified in safe microVM",
        workspace_commit=workspace_commit,
        abox_version=abox_version,
        console_sha256=console_sha,
    )


def run_live_self_test(project_config: Path, sealed_input: Path) -> AboxWorkerResult:
    """Exercise abox without exposing a target repository to the guest."""

    artifact = seal_input(sealed_input)
    try:
        approved_config = _CONTROLLER_PROJECT_CONFIG.read_bytes()
        requested_config = project_config.read_bytes()
    except OSError as exc:
        raise AboxWorkerError("abox project configuration is unavailable") from exc
    if requested_config != approved_config:
        raise AboxWorkerError("live self-test requires the approved abox project configuration")
    with tempfile.TemporaryDirectory(prefix="infosec-harness-abox-") as temporary:
        workspace = Path(temporary) / "controller-workspace"
        (workspace / ".abox").mkdir(parents=True)
        shutil.copyfile(project_config, workspace / ".abox" / "project.toml")
        (workspace / "README.md").write_text("controller-owned abox self-test\n", encoding="utf-8")
        for command in (
            ["git", "init", "-b", "main", str(workspace)],
            ["git", "-C", str(workspace), "add", "README.md", ".abox/project.toml"],
            [
                "git",
                "-C",
                str(workspace),
                "-c",
                "user.name=infosec-harness",
                "-c",
                "user.email=infosec-harness@invalid",
                "commit",
                "-m",
                "controller workspace",
            ],
            ["abox", "project", "trust", "--repo", str(workspace)],
        ):
            code, stdout, stderr = _command_output(command)
            if code != 0:
                return AboxWorkerResult(
                    False,
                    False,
                    "abox controller workspace setup failed",
                    "sealed-evidence-self-test",
                    artifact.sha256,
                    hashlib.sha256(approved_config).hexdigest(),
                    console_sha256=hashlib.sha256((stdout + stderr).encode()).hexdigest(),
                )
        return run_no_network_worker(
            plan_from_sealed_artifact(workspace, artifact, "sealed-evidence-self-test")
        )
