"""Real OpenShell acceptance through the same adapter used by investigation tools."""

import asyncio
import hashlib
import logging
import tempfile
from pathlib import Path
from uuid import uuid4

from infosec_harness._io import write_json
from infosec_harness.config import Settings, get_settings
from infosec_harness.contracts import GENERATION
from infosec_harness.sandbox import OpenShell, OpenShellConfig
from infosec_harness.sandbox.process import finish
from infosec_harness.workflows.worker import worker_identity

log = logging.getLogger(__name__)

# Read back the uploaded file; the identical second request must replay the saved receipt.
_ROUNDTRIP = [
    "python",
    "-I",
    "-c",
    "from pathlib import Path;print(Path('/workspace/qualification/input.txt').read_text(),end='')",
]
_EXPECTED = "native-roundtrip\n"
PROFILES = ("workspace", "probe")
# Per profile, in order. Each starts not_checked and is set only by its own outcome.
CHECKS = ("boundary", "roundtrip", "saved_operation", "sandbox_reuse", "cleanup")
# Bound on a recorded error message; the messages are harness-authored.
ERROR_CHARS = 300


def _bounded(error: BaseException) -> str:
    return "".join(c if c.isprintable() else " " for c in str(error))[:ERROR_CHARS]


async def qualify_runtime(output: Path, settings: Settings | None = None) -> dict:
    """Exercise both native profiles once; every check not reached stays ``not_checked``."""
    if output.exists():
        raise ValueError("Preserve previous qualification reports; select a new output path")
    settings = settings or get_settings()
    runtime = OpenShell(OpenShellConfig.load(settings.openshell_config))
    run_id = "qualification-" + uuid4().hex
    report = {
        "version": 1,
        "status": "running",
        "run_id": run_id,
        "generation": GENERATION,
        # The adapter code and isolation configuration this qualification exercised.
        "worker_identity": worker_identity(settings).model_dump(),
        "config_sha256": hashlib.sha256(settings.openshell_config.read_bytes()).hexdigest(),
        "model_calls": 0,
        "model_quality": "not_checked",
        "profiles": {profile: dict.fromkeys(CHECKS, "not_checked") for profile in PROFILES},
        "cleanup": "not_checked",
    }
    write_json(output, report, exclusive=True)
    step: tuple[str, str] | None = None
    created = False

    def passed(profile: str, check: str) -> None:
        report["profiles"][profile][check] = "passed"
        log.info("event=qualification_check run_id=%s profile=%s check=%s status=passed",
                 run_id, profile, check)

    try:
        for profile in PROFILES:
            step = (profile, "boundary")
            sandbox = await runtime.create(run_id, profile=profile)
            created = True
            # create() admits the sandbox only after verifying its native confinement.
            passed(profile, "boundary")
            step = (profile, "roundtrip")
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source"
                source.mkdir()
                (source / "input.txt").write_text(_EXPECTED)
                await runtime.upload(sandbox, source, "/workspace/qualification")
                result = await runtime.execute(
                    sandbox,
                    _ROUNDTRIP,
                    operation_id=f"roundtrip:{profile}",
                    timeout=30,
                )
                if (
                    result.exit_code != 0
                    or result.stdout != _EXPECTED
                    or result.output_truncated
                ):
                    raise RuntimeError(
                        f"Native execution roundtrip failed in {profile}: exit "
                        f"{result.exit_code}, truncated {result.output_truncated}, "
                        f"{len(result.stdout)} stdout characters (expected {len(_EXPECTED)})"
                    )
                passed(profile, "roundtrip")
                step = (profile, "saved_operation")
                again = await runtime.execute(
                    sandbox,
                    _ROUNDTRIP,
                    operation_id=f"roundtrip:{profile}",
                    timeout=30,
                )
                if again != result:
                    raise RuntimeError(
                        f"Saved operation roundtrip:{profile} returned a different result"
                    )
                passed(profile, "saved_operation")
            # A fresh adapter must consume the same durable confinement proof.
            # create() rechecks current native identity and fences on every reuse.
            step = (profile, "sandbox_reuse")
            recovered = OpenShell(OpenShellConfig.load(settings.openshell_config))
            if await recovered.create(run_id, profile=profile) != sandbox:
                raise RuntimeError(f"Sandbox reuse changed native identity in {profile}")
            passed(profile, "sandbox_reuse")
            step = (profile, "cleanup")
            await runtime.close(sandbox)
            # Closing again must be a no-op: close is idempotent for an owned sandbox.
            await runtime.close(sandbox)
            passed(profile, "cleanup")
            step = None
            write_json(output, report)
        report["status"] = "passed"
    except asyncio.CancelledError:
        report.update(status="cancelled", error_type="CancelledError")
        if step is not None:
            report.update(cancelled_profile=step[0], cancelled_check=step[1])
        raise
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=_bounded(exc))
        if step is not None:
            report["profiles"][step[0]][step[1]] = "failed"
            report.update(failed_profile=step[0], failed_check=step[1])
        log.warning("event=qualification_failed run_id=%s profile=%s check=%s error_type=%s",
                    run_id, *(step or ("-", "-")), type(exc).__name__)
    finally:
        # Always reconcile: a create that raised may still have left an owned record, and
        # close_run fails on any it cannot close. Without a returned sandbox there is no
        # owned sandbox to prove closed, so a clean reconcile is not_applicable, not passed.
        try:
            await finish(asyncio.ensure_future(runtime.close_run(run_id)))
            report["cleanup"] = "passed" if created else "not_applicable"
        except Exception as exc:
            report.update(status="failed", cleanup="failed", cleanup_error_type=type(exc).__name__,
                          cleanup_error=_bounded(exc))
            log.warning("event=qualification_cleanup_failed run_id=%s error_type=%s",
                        run_id, type(exc).__name__)
        write_json(output, report)
    return report
