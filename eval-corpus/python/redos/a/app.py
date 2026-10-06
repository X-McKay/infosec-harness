import re

# FIXED: a flat character class with a single quantifier matches in linear time;
# there is no nested repetition for the engine to backtrack over.
EMAIL_RE = re.compile(r"^[a-zA-Z0-9]+@example\.com$")


def is_valid_email(value: str) -> bool:
    """Return True when value is an @example.com address."""
    return EMAIL_RE.match(value) is not None
