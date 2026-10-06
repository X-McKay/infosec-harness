import pickle


def load_profile(blob: bytes) -> object:
    """Restore a cached user profile.

    VULNERABLE: untrusted bytes are unpickled, so the payload chooses what gets constructed.
    """
    return pickle.loads(blob)
