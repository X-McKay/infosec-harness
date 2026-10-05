"""Secure, opt-in execution checks for agent evaluation outputs.

These checks are deliberately separate from the structural adapter reducers. Repository
content and model-authored environment specifications are untrusted, so the default engine
uses the same immutable snapshot, build-egress, and runsc-backed probe paths as production.
An unavailable secure runtime is evidence that the check was not performed, never evidence
that the answer passed or failed.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from infosec_harness.domain.models import EnvironmentSpec, RepoRef, SourceMode
from infosec_harness.repo.checkout import checkout
from infosec_harness.sandbox import REQUIRED_RUNTIME, docker
from infosec_harness.sandbox.errors import SandboxUnavailable
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import REPO_ROOT, get_settings

ExecutionStatus = Literal["passed", "failed", "not_checked"]


@dataclass(frozen=True)
class ExecutionCheckResult:
    status: ExecutionStatus
    check: str
    reason: str
    source_hash: str | None = None
    image_tag: str | None = None
    build_status: str = "not_started"
    build_exit_code: int | None = None
    build_duration_s: float | None = None
    check_exit_code: int | None = None
    check_duration_s: float | None = None
    timed_out: bool = False
    output_excerpt: str = ""
    execution_mode: str = "secure-sandbox-v1"

    @property
    def predicted(self) -> str:
        if self.status == "passed":
            return "addressed"
        if self.status == "failed":
            return "unaddressed"
        return "execution_not_checked"

    def as_score(self) -> dict[str, Any]:
        return asdict(self)


ExecutionEngine = Callable[
    [dict[str, Any], EnvironmentSpec, str], Awaitable[ExecutionCheckResult]
]


# --- The one path from a controller-owned fixture to a runsc-ready image -------------------


@dataclass(frozen=True)
class FixtureImage:
    """A fixture snapshotted and built (or found cached) for the enforced runsc sandbox."""

    source_hash: str
    image_tag: str
    build: ProcessResult | None
    """The build that produced the image; ``None`` when the image was already cached."""

    @property
    def cached(self) -> bool:
        return self.build is None

    @property
    def built(self) -> bool:
        return self.build is None or (self.build.exit_code == 0 and not self.build.timed_out)

    @property
    def build_output(self) -> str:
        return "" if self.build is None else self.build.stderr or self.build.stdout

    @property
    def infrastructure_failure(self) -> bool:
        """The builder itself failed, which says nothing about the environment it was given."""
        return not self.built and builder_infrastructure_failure(self.build_output)


def builder_infrastructure_failure(output: str) -> bool:
    """Recognise controller/daemon failures that say nothing about the returned spec."""
    lowered = output.lower()
    return any(marker in lowered for marker in (
        "cannot connect to the docker daemon",
        "error during connect",
        "failed to get info from",
        "lstat /var/folders:",  # host tempfile is outside the Lima shared filesystem
    ))


async def prepare_fixture_image(
    repo: str,
    spec: EnvironmentSpec,
    *,
    purpose: str,
    root: Path = REPO_ROOT,
    verify: Callable[[Path], str | None] | None = None,
) -> FixtureImage | str:
    """Snapshot ``root/repo`` and build ``spec`` over it, or say why no check can run.

    Every execution-backed evaluator goes through here, so the safety preconditions are one
    list: the fixture must stay inside ``root`` and exist, ``verify`` (the caller's own fixture
    identity check) must pass, and runsc must be the configured, registered and default runtime
    with the insecure fallback off. A returned string is the reason the check was not performed
    -- never evidence that it passed or failed.
    """
    source = (root / repo).resolve()
    if not source.is_relative_to(root.resolve()):
        return "execution fixture escapes the repository root"
    if not source.is_dir():
        return "execution fixture is missing"
    if verify is not None and (problem := verify(source)) is not None:
        return problem
    settings = get_settings()
    if settings.allow_insecure_runtime or settings.sandbox_runtime != REQUIRED_RUNTIME:
        return "execution checks require enforced runsc; the insecure fallback is disabled"
    try:
        # Registered *and* the daemon default; the configured name alone is not evidence.
        await docker.ensure_runtime_available(purpose)
        snapshot = await checkout(RepoRef(
            repo_url=str(source), revision="HEAD", source_mode=SourceMode.working_snapshot,
        ))
        image_tag = docker.image_tag_for(snapshot.content_hash, spec)
        build = (None if await docker.image_exists(image_tag)
                 else await docker.build_image(snapshot.path, spec, image_tag))
    except (FileNotFoundError, SandboxUnavailable) as exc:
        return str(exc)[:500]
    return FixtureImage(source_hash=snapshot.content_hash, image_tag=image_tag, build=build)


# --- The dependency check ------------------------------------------------------------------


_PERL_DBD_SQLITE_CHECK = r'''use strict;
use warnings;
use DBI;
use DBD::SQLite;
my $dbh = DBI->connect("dbi:SQLite:dbname=:memory:", "", "", { RaiseError => 1 });
$dbh->do("CREATE TABLE harness_check (value INTEGER NOT NULL)");
$dbh->do("INSERT INTO harness_check (value) VALUES (41)");
my ($value) = $dbh->selectrow_array("SELECT value + 1 FROM harness_check");
die "unexpected SQLite result" unless defined($value) && $value == 42;
print "HARNESS_EVAL_CHECK::perl-dbd-sqlite-v1\n";
'''


async def _secure_engine(
    case: dict[str, Any], spec: EnvironmentSpec, check_name: str
) -> ExecutionCheckResult:
    """Build the model output and run one controller-authored check without network access."""
    if check_name != "perl_dbd_sqlite_v1":
        return ExecutionCheckResult(
            status="not_checked", check=check_name,
            reason="unknown execution check; evaluator cannot claim coverage",
        )
    repo = case.get("repo")
    if not isinstance(repo, str) or not repo:
        return ExecutionCheckResult(
            status="not_checked", check=check_name,
            reason="execution check has no repository fixture",
        )
    image = await prepare_fixture_image(repo, spec, purpose="execute an evaluation check")
    if isinstance(image, str):
        return ExecutionCheckResult(status="not_checked", check=check_name, reason=image)
    if (build := image.build) is not None and not image.built:
        infrastructure = image.infrastructure_failure
        return ExecutionCheckResult(
            status="not_checked" if infrastructure else "failed", check=check_name,
            reason=("sandbox builder infrastructure failed before evaluation"
                    if infrastructure else "returned environment did not build"),
            source_hash=image.source_hash, image_tag=image.image_tag,
            build_status="failed", build_exit_code=build.exit_code,
            build_duration_s=build.duration_s, timed_out=build.timed_out,
            output_excerpt=docker.tail(image.build_output, 2000),
        )
    nonce = hashlib.sha256(
        f"{image.source_hash}:{image.image_tag}:{check_name}".encode()
    ).hexdigest()[:24]
    try:
        checked = await docker.run_probe(
            image.image_tag,
            "t/harness_eval_dependency_check.pl",
            _PERL_DBD_SQLITE_CHECK,
            "perl {test_file}",
            nonce,
            module_path=spec.module_path or "",
        )
    except (FileNotFoundError, SandboxUnavailable) as exc:
        return ExecutionCheckResult(status="not_checked", check=check_name, reason=str(exc)[:500])

    output = checked.stdout + "\n" + checked.stderr
    marker = "HARNESS_EVAL_CHECK::perl-dbd-sqlite-v1"
    passed = checked.exit_code == 0 and not checked.timed_out and marker in output
    return ExecutionCheckResult(
        status="passed" if passed else "failed",
        check=check_name,
        reason=("controller-authored dependency check passed" if passed
                else "controller-authored dependency check failed"),
        source_hash=image.source_hash,
        image_tag=image.image_tag,
        build_status="cached" if image.cached else "passed",
        build_exit_code=0,
        build_duration_s=0.0 if image.build is None else image.build.duration_s,
        check_exit_code=checked.exit_code,
        check_duration_s=checked.duration_s,
        timed_out=checked.timed_out,
        output_excerpt=docker.tail(output, 2000),
    )


async def run_execution_check(
    case: dict[str, Any], output: Any, *, stub: bool,
    engine: ExecutionEngine | None = None,
) -> ExecutionCheckResult | None:
    """Run a case's declared check, returning ``None`` for structurally scored cases."""
    check_name = case.get("execution_check")
    if not check_name:
        return None
    if stub:
        return ExecutionCheckResult(
            status="not_checked", check=str(check_name),
            reason="stub mode does not provide agent-quality execution evidence",
            execution_mode="stub-not-checked-v1",
        )
    spec = EnvironmentSpec.model_validate(output)
    return await (engine or _secure_engine)(case, spec, str(check_name))


__all__ = [
    "ExecutionCheckResult",
    "FixtureImage",
    "builder_infrastructure_failure",
    "prepare_fixture_image",
    "run_execution_check",
]
