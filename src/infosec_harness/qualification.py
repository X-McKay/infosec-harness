"""Real OpenShell acceptance through the same adapter used by investigation tools."""

import asyncio
import hashlib
import tempfile
from pathlib import Path
from uuid import uuid4

from infosec_harness._io import write_json
from infosec_harness.config import get_settings
from infosec_harness.openshell import OpenShell, OpenShellConfig
from infosec_harness.process import _finish


async def qualify_runtime(output: Path) -> dict:
    if output.exists():
        raise ValueError("Preserve previous qualification reports; select a new output path")
    settings = get_settings()
    runtime = OpenShell(OpenShellConfig.load(settings.openshell_config))
    run_id = "qualification-" + uuid4().hex
    report = {
        "version": 1,
        "status": "running",
        "run_id": run_id,
        "config_sha256": hashlib.sha256(settings.openshell_config.read_bytes()).hexdigest(),
        "model_calls": 0,
        "model_quality": "not_checked",
        "profiles": {},
        "cleanup": "not_checked",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, report, exclusive=True)
    try:
        for profile in ("workspace", "probe"):
            sandbox = await runtime.create(run_id, profile=profile)
            row = report["profiles"][profile] = {
                "boundary": "passed",
                "roundtrip": "not_checked",
                "saved_operation": "not_checked",
                "cleanup": "not_checked",
            }
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source"
                source.mkdir()
                (source / "input.txt").write_text("native-roundtrip\n")
                await runtime.upload(sandbox, source, "/workspace/qualification")
                result = await runtime.execute(
                    sandbox,
                    [
                        "python",
                        "-I",
                        "-c",
                        "from pathlib import Path;print(Path('/workspace/qualification/input.txt').read_text(),end='')",
                    ],
                    operation_id=f"roundtrip:{profile}",
                    timeout=30,
                )
                if (
                    result.exit_code != 0
                    or result.stdout != "native-roundtrip\n"
                    or result.output_truncated
                ):
                    raise RuntimeError("Native execution roundtrip failed")
                downloaded = Path(directory) / "download.txt"
                await runtime.download(sandbox, "/workspace/qualification/input.txt", downloaded)
                if downloaded.read_bytes() != (source / "input.txt").read_bytes():
                    raise RuntimeError("Native artifact download changed bytes")
                row["roundtrip"] = "passed"
                again = await runtime.execute(
                    sandbox,
                    [
                        "python",
                        "-I",
                        "-c",
                        "from pathlib import Path;print(Path('/workspace/qualification/input.txt').read_text(),end='')",
                    ],
                    operation_id=f"roundtrip:{profile}",
                    timeout=30,
                )
                if again != result:
                    raise RuntimeError("Saved operation changed")
                row["saved_operation"] = "passed"
            await runtime.close(sandbox)
            await runtime.close(sandbox)
            row["cleanup"] = "passed"
            write_json(output, report)
        report["status"] = "passed"
    except asyncio.CancelledError:
        report.update(status="cancelled", error_type="CancelledError")
        raise
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__)
    finally:
        try:
            await _finish(asyncio.ensure_future(runtime.close_run(run_id)))
            report["cleanup"] = "passed"
        except Exception as exc:
            report.update(status="failed", cleanup="failed", cleanup_error_type=type(exc).__name__)
        write_json(output, report)
    return report
