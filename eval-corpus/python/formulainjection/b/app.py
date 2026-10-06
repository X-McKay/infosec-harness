import csv
import io

# Characters a spreadsheet treats as the start of a formula.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _neutralize(value: str) -> str:
    """Force a cell to be read as text rather than evaluated as a formula."""
    if value[:1] in FORMULA_TRIGGERS:
        return "'" + value
    return value


def export_csv(rows: list[dict]) -> str:
    """Export user-submitted records as a CSV file for download."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "note"])
    for row in rows:
        writer.writerow([_neutralize(row["name"]), _neutralize(row["note"])])
    return buffer.getvalue()
