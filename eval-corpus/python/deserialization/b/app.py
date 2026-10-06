import io
import pickle

# A profile is plain data; these are the only classes a legitimate payload may name.
ALLOWED_CLASSES = {("builtins", "dict"), ("builtins", "list"), ("builtins", "str")}


class _AllowlistUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str):
        if (module, name) not in ALLOWED_CLASSES:
            raise pickle.UnpicklingError(f"refusing to load {module}.{name}")
        return super().find_class(module, name)


def load_profile(blob: bytes) -> object:
    """Restore a cached user profile."""
    return _AllowlistUnpickler(io.BytesIO(blob)).load()
