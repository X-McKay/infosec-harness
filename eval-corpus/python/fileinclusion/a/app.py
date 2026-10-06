import importlib

# The caller picks a report style by key; each key maps to one known plugin module.
ALLOWED_PLUGINS = {
    "summary": "reporting.summary",
    "detail": "reporting.detail",
}


def load_plugin(name: str):
    """Load the report plugin the caller named.

    FIXED: `name` selects from a fixed allowlist of known plugins, so the caller
    cannot cause an arbitrary module to be imported and executed.
    """
    if name not in ALLOWED_PLUGINS:
        raise ValueError("unknown plugin")
    return importlib.import_module(ALLOWED_PLUGINS[name])


def render(name: str, data: dict) -> str:
    plugin = load_plugin(name)
    return plugin.render(data)
