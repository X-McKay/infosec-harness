import importlib


def load_plugin(name: str):
    """Load the report plugin the caller named.

    VULNERABLE: `name` is imported directly, so the caller can cause any importable
    module on the path to be loaded and its top-level code executed.
    """
    return importlib.import_module(name)


def render(name: str, data: dict) -> str:
    plugin = load_plugin(name)
    return plugin.render(data)
