"""The executor's lease settings and the owner-only file reads that deliver them.

Shared by the executor, which reads its uploaded lease, and the native adapter, which writes
it; neither imports the other.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from pydantic import Field

from infosec_harness.inference.wire.protocol import (
    LEDGER_CREDENTIAL_ENV,
    BrokerError,
    EnvName,
    ExecutorContract,
    HttpsOrigin,
    StrictModel,
)


def _check_private(status: os.stat_result, *, directory: bool, same_owner: bool,
                   message: str | None) -> None:
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(status.st_mode) or status.st_mode & 0o077
            or (same_owner and status.st_uid != os.getuid())):
        raise BrokerError("identity", message)


def require_private(path: Path, *, directory: bool = False, same_owner: bool = True,
                    message: str | None = None) -> None:
    """An existing owner-only regular file (or directory), never a symlink.

    ``same_owner`` additionally requires this process's user to own it.
    """
    try:
        status = path.lstat()
    except OSError:
        raise BrokerError("identity", message) from None
    _check_private(status, directory=directory, same_owner=same_owner, message=message)


def read_private(path: Path, *, same_owner: bool = True, message: str | None = None) -> bytes:
    """Read an owner-only regular file, checking the opened file itself (no symlink, no race)."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise BrokerError("identity", message) from None
    try:
        _check_private(os.fstat(descriptor), directory=False, same_owner=same_owner,
                       message=message)
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read()


class ExecutorSettings(StrictModel):
    run_id: str
    lease_id: str
    contract: ExecutorContract
    controller_origin: HttpsOrigin
    ingress_key_hex: str = Field(pattern=r"^[a-f0-9]{64}$", repr=False)
    provider_env: EnvName
    ledger_env: EnvName = LEDGER_CREDENTIAL_ENV
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
