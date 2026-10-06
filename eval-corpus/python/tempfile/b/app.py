import os
import tempfile


def export_report(rows: list[str]) -> str:
    """Write a CSV export to the shared temp directory and return its path."""
    path = os.path.join(tempfile.gettempdir(), "report-export.csv")
    with open(path, "w") as handle:
        handle.write("\n".join(rows))
    return path
