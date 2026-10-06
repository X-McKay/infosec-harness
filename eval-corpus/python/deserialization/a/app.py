import pickle


def load_profile(blob: bytes) -> object:
    """Restore a cached user profile."""
    return pickle.loads(blob)
