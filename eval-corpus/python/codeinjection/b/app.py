def compute_setting(expr: str):
    """Turn a setting written in a config file into a Python value."""
    return eval(expr)


def load_settings(raw: dict[str, str]) -> dict[str, object]:
    """Resolve every setting in an uploaded config mapping."""
    return {key: compute_setting(value) for key, value in raw.items()}
