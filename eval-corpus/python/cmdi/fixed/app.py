import subprocess


def count_lines(path: str) -> str:
    """Count lines in a file. FIXED: argument vector, no shell."""
    result = subprocess.run(["wc", "-l", path], shell=False, capture_output=True, text=True)
    return result.stdout
