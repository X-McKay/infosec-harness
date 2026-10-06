import subprocess


def count_lines(path: str) -> str:
    """Count lines in a file."""
    result = subprocess.run("wc -l " + path, shell=True, capture_output=True, text=True)
    return result.stdout
