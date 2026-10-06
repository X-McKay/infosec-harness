"""Native OpenShell sandboxes: lifecycle, exec receipts, transfers and the model executor.

Names resolve on first use, so that ``executor`` (shipped alone into the model image)
imports without the worker-side modules or their dependencies.
"""

from importlib import import_module

_EXPORTS = {
    "OpenShell": "openshell",
    "OpenShellConfig": "openshell",
    "Profile": "openshell",
    "native_operation_accounting": "openshell",
    "CommandResult": "execution",
    "ExecutionReceipt": "execution",
    "ExecutionUnknown": "execution",
    "OpenShellError": "execution",
    "Sandbox": "execution",
    "SourceChanged": "execution",
    "SourceRejected": "execution",
    "UnsafeSnapshotMetadata": "transfer",
}
__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> object:
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(f"{__name__}.{_EXPORTS[name]}"), name)
