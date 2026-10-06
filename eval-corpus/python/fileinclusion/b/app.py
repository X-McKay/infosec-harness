import importlib


def load_plugin(name: str):
    """Load the report plugin the caller named."""
    return importlib.import_module(name)


def render(name: str, data: dict) -> str:
    plugin = load_plugin(name)
    return plugin.render(data)
