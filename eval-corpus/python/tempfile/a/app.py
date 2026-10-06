import os
import tempfile


def export_report(rows: list[str]) -> str:
    """Write a CSV export to the shared temp directory and return its path."""
    fd, path = tempfile.mkstemp(prefix="report-export-", suffix=".csv")
    with os.fdopen(fd, "w") as handle:
        handle.write("\n".join(rows))
    return path
