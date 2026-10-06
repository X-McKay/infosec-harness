import os
import tempfile


def export_report(rows: list[str]) -> str:
    """Write a CSV export to the shared temp directory and return its path.

    VULNERABLE: the file name is fixed and the file is opened without exclusive
    creation, so another local user who creates that path first (as a file or a
    link) receives the export or redirects the write.
    """
    path = os.path.join(tempfile.gettempdir(), "report-export.csv")
    with open(path, "w") as handle:
        handle.write("\n".join(rows))
    return path
