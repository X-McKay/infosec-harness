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
from typing import Any, Literal

from infosec_harness.domain.models import EnvironmentSpec, RepoRef, SourceMode
from infosec_harness.settings import REPO_ROOT

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


def _builder_infrastructure_failure(output: str) -> bool:
    """Recognise controller/daemon failures that say nothing about the returned spec."""
    lowered = output.lower()
    return any(marker in lowered for marker in (
        "cannot connect to the docker daemon",
        "error during connect",
        "failed to get info from",
        "lstat /var/folders:",  # host tempfile is outside the Lima shared filesystem
    ))


async def _secure_engine(
    case: dict[str, Any], spec: EnvironmentSpec, check_name: str
) -> ExecutionCheckResult:
    """Build the model output and run one controller-authored check without network access."""
    from infosec_harness.repo.checkout import checkout
    from infosec_harness.sandbox import docker
    from infosec_harness.sandbox.policy import SandboxUnavailable, ensure_runtime_available
    from infosec_harness.settings import get_settings

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
    source = (REPO_ROOT / repo).resolve()
    try:
        source.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return ExecutionCheckResult(
            status="not_checked", check=check_name,
            reason="execution fixture escapes the repository root",
        )
    if not source.is_dir():
        return ExecutionCheckResult(
            status="not_checked", check=check_name,
            reason="execution fixture is missing",
        )

    try:
        settings = get_settings()
        if settings.allow_insecure_runtime or settings.sandbox_runtime != "runsc" \
                or not await docker.runtime_available("runsc"):
            return ExecutionCheckResult(
                status="not_checked", check=check_name,
                reason="execution evaluation requires an available default runsc runtime",
            )
        await ensure_runtime_available("execute an evaluation check")
        snapshot = await checkout(RepoRef(
            repo_url=str(source), revision="HEAD", source_mode=SourceMode.working_snapshot,
        ))
        image_tag = docker.image_tag_for(snapshot.content_hash, spec)
        cached = await docker.image_exists(image_tag)
        build_duration_s = 0.0
        if not cached:
            built = await docker.build_image(snapshot.path, spec, image_tag)
            if built.exit_code != 0 or built.timed_out:
                output = built.stderr or built.stdout
                infrastructure = _builder_infrastructure_failure(output)
                return ExecutionCheckResult(
                    status="not_checked" if infrastructure else "failed", check=check_name,
                    reason=("sandbox builder infrastructure failed before evaluation"
                            if infrastructure else "returned environment did not build"),
                    source_hash=snapshot.content_hash, image_tag=image_tag,
                    build_status="failed", build_exit_code=built.exit_code,
                    build_duration_s=built.duration_s,
                    timed_out=built.timed_out,
                    output_excerpt=docker.tail(output, 2000),
                )
            build_duration_s = built.duration_s
        nonce = hashlib.sha256(
            f"{snapshot.content_hash}:{image_tag}:{check_name}".encode()
        ).hexdigest()[:24]
        checked = await docker.run_probe(
            image_tag,
            "t/harness_eval_dependency_check.pl",
            _PERL_DBD_SQLITE_CHECK,
            "perl {test_file}",
            nonce,
            module_path=spec.module_path or "",
        )
    except (FileNotFoundError, SandboxUnavailable) as exc:
        return ExecutionCheckResult(
            status="not_checked", check=check_name,
            reason=str(exc)[:500],
        )

    output = checked.stdout + "\n" + checked.stderr
    marker = "HARNESS_EVAL_CHECK::perl-dbd-sqlite-v1"
    passed = checked.exit_code == 0 and not checked.timed_out and marker in output
    return ExecutionCheckResult(
        status="passed" if passed else "failed",
        check=check_name,
        reason=("controller-authored dependency check passed" if passed
                else "controller-authored dependency check failed"),
        source_hash=snapshot.content_hash,
        image_tag=image_tag,
        build_status="cached" if cached else "passed",
        build_exit_code=0,
        build_duration_s=build_duration_s,
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


__all__ = ["ExecutionCheckResult", "run_execution_check"]
