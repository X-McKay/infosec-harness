import csv
import io


def export_csv(rows: list[dict]) -> str:
    """Export user-submitted records as a CSV file for download.

    VULNERABLE: cell values are written verbatim, so a value beginning with =, +, -
    or @ stays a formula that a spreadsheet opening the file will evaluate.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "note"])
    for row in rows:
        writer.writerow([row["name"], row["note"]])
    return buffer.getvalue()
