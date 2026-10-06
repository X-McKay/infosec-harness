import re

# VULNERABLE: nested quantifier (([a-z0-9]+)+) backtracks catastrophically.
# On an input that cannot match (e.g. a run of allowed characters followed by a
# disallowed one), the match time grows exponentially with input length.
EMAIL_RE = re.compile(r"^(([a-zA-Z0-9]+)+)@example\.com$")


def is_valid_email(value: str) -> bool:
    """Return True when value is an @example.com address."""
    return EMAIL_RE.match(value) is not None
