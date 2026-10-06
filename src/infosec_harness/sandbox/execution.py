"""Native exec behind a durable receipt fence: the sandbox handle, results and errors.

The lowest layer of the adapter. ``Execution`` is mixed into
:class:`~infosec_harness.sandbox.openshell.OpenShell` and relies on its lifecycle methods
(``_owned``, ``_corroborate``, ``close``, ``_record``, ``_save``): the intent of every command
is saved before dispatch, a completed receipt is replayed, and an interrupted dispatch is
never resent. OpenShell's generated gRPC bindings are used for exec because the SDK
convenience iterator retains an unbounded copy of stdout and stderr.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal

ProfileName = Literal["workspace", "probe", "model"]
_PYTHON = "/usr/local/bin/python"


class OpenShellError(RuntimeError):
    """A boundary could not be established or observed."""


class ExecutionUnknown(OpenShellError):
    """Dispatch may have happened. Never automatically resend this operation."""


@dataclass(frozen=True)
class Sandbox:
    id: str
    run_id: str
    name: str
    profile: ProfileName
    slot: str = ""


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    # Never set by native exec, whose overflow raises ExecutionUnknown instead; set only by
    # ``tools.execute.unwrap_output`` from the shell wrapper's cut marker. Saved receipts
    # carry the key, so it stays part of the receipt shape.
    output_truncated: bool = False


@dataclass(frozen=True)
class ExecutionReceipt:
    sandbox: Sandbox
    operation_id: str
    request_digest: str
    command: list[str]
    result: CommandResult
    workspace_digest: str | None = None
    source_verified: bool = False


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _request_id(key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "infosec-harness:" + key))


def _status(error: BaseException) -> str:
    """The gRPC status name of a native failure; its server-supplied details never leave."""
    code = getattr(error, "code", None)
    status = code() if callable(code) else None
    return getattr(status, "name", "UNKNOWN")


class Execution:
    """Bounded native exec with replayable receipts; a mixin of ``OpenShell``."""

    def _stream(self, sandbox: Sandbox, command: Sequence[str], timeout: int,
                stdin: bytes | None, request_id: str, limit: int, binary: bool = False) -> tuple[CommandResult, bytes]:
        """One native exec stream, bounded to ``limit`` output bytes.

        Every failure after the request is sent is ``ExecutionUnknown``: the stream may have
        dispatched. A gRPC failure reports only its status code.
        """
        import grpc

        # Pinned native RPC selectors are names, not immutable IDs. The trusted
        # worker corroborates exact ID/ownership before every dispatch.
        request = self._pb.ExecSandboxRequest(workspace_scope=self._scope, sandbox=sandbox.name,
            command=list(command), workdir="/workspace", stdin=stdin or b"",
            no_login_shell=True, request_id=request_id)
        request.execution_timeout.seconds = timeout
        try:
            stream = self._stub.ExecSandbox(request, timeout=timeout + 10)
        except grpc.RpcError as error:
            raise ExecutionUnknown(f"native exec stream failed: {_status(error)}") from None
        stdout, stderr = bytearray(), bytearray()
        code = None
        try:
            for event in stream:
                payload = event.WhichOneof("payload")
                if payload in ("stdout", "stderr"):
                    target = stdout if payload == "stdout" else stderr
                    chunk = getattr(event, payload).data
                    if len(chunk) > limit - len(stdout) - len(stderr):
                        # Cancel the native RPC on overflow; the caller closes the
                        # workload rather than assuming cancellation killed the process.
                        stream.cancel()
                        raise ExecutionUnknown("command output exceeded the boundary limit")
                    target.extend(chunk)
                elif payload == "exit":
                    code = int(event.exit.exit_code)
            if code is None:
                raise ExecutionUnknown("native exec ended without an exit receipt")
            if code == 124:
                # Pinned OpenShell also synthesizes 124 on timeout without native
                # terminal finalization. An explicit process exit 124 is ambiguous.
                raise ExecutionUnknown("native exit 124 cannot establish terminal execution")
            return CommandResult(code, "" if binary else stdout.decode(errors="replace"),
                                 stderr.decode(errors="replace")), bytes(stdout)
        except grpc.RpcError as error:
            raise ExecutionUnknown(f"native exec stream failed: {_status(error)}") from None
        finally:
            stream.cancel()

    async def execute(self, sandbox: Sandbox, command: Sequence[str] | str, *,
                      operation_id: str, timeout: int, stdin: bytes | None = None) -> CommandResult:
        if not operation_id or len(operation_id) > 1024:
            raise OpenShellError("stable operation_id is required")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 < timeout <= self.config.max_timeout_seconds:
            raise OpenShellError("execution timeout exceeds the configured bound")
        args = ["/bin/sh", "-c", command] if isinstance(command, str) else list(command)
        if not args or any(not isinstance(a, str) or "\x00" in a for a in args):
            raise OpenShellError("invalid command")
        if len(args) > 256 or sum(len(a.encode()) for a in args) > 65536:
            raise OpenShellError("command exceeds its input bound")
        if stdin is not None and len(stdin) > self.config.max_transfer_bytes:
            raise OpenShellError("stdin exceeds the transfer bound")
        request_digest = _digest([asdict(sandbox), args, timeout,
                                  hashlib.sha256(stdin or b"").hexdigest()])
        key = _digest([sandbox.run_id, operation_id])
        path = self._record("operations", key)
        receipt = {"sandbox": asdict(sandbox), "operation_id": operation_id,
                   "request_digest": request_digest, "command": args}

        def replay() -> CommandResult:
            saved = json.loads(path.read_bytes())
            if saved.get("request_digest") != request_digest:
                raise OpenShellError("operation_id was reused with a different request")
            if "result" not in saved:
                raise ExecutionUnknown("prior dispatch has no completed receipt; do not resend")
            return CommandResult(**saved["result"])

        async with self._locks.setdefault(key, asyncio.Lock()):
            if path.exists():
                return replay()
            self._owned(sandbox)
            try:
                self._save(path, receipt, exclusive=True)
            except FileExistsError:
                return replay()
            try:
                await self._corroborate(sandbox, "native workload identity changed")
                result, _ = await asyncio.to_thread(self._stream, sandbox, args, timeout, stdin,
                    _request_id(key), self.config.max_output_bytes)
            except asyncio.CancelledError as cancelled:
                await self._close_owned(sandbox, cancelled)
                raise
            except Exception as exc:
                unknown = ExecutionUnknown("native execution outcome unknown; sandbox closed")
                await self._close_owned(sandbox, unknown)
                raise unknown from exc
            self._save(path, {**receipt, "result": asdict(result)})
            return result

    def receipts(self, run_id: str) -> list[ExecutionReceipt]:
        values = []
        snapshots = {}
        verified = set()
        for path in (self.config.state_dir / "transfers").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved.get("restored") and saved.get("expected_source_digest"):
                snapshots[saved["probe"]["id"]] = saved["sha256"]
            if saved.get("source_verified"):
                verified.update((saved["source"]["id"], operation)
                                for operation in saved["verified_operations"])
        for path in (self.config.state_dir / "operations").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved["sandbox"]["run_id"] == run_id and "result" in saved:
                values.append(ExecutionReceipt(Sandbox(**saved["sandbox"]), saved["operation_id"],
                    saved["request_digest"], saved["command"], CommandResult(**saved["result"]),
                    snapshots.get(saved["sandbox"]["id"]),
                    (saved["sandbox"]["id"], saved["operation_id"]) in verified))
        return values
