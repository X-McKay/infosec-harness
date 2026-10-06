import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import Store, get_note  # noqa: E402


def test_cross_principal_read_is_blocked():
    store = Store()
    alice_note = store.add_note("alice", "alice-secret")
    bob_note = store.add_note("bob", "bob-secret-nonce")

    # positive control: Alice reads her own note.
    own = get_note(store, "alice", alice_note)
    assert own is not None and own["body"] == "alice-secret"

    # negative control: a nonexistent id returns nothing.
    assert get_note(store, "alice", 9999) is None

    # FIXED: Alice cannot read Bob's note.
    assert get_note(store, "alice", bob_note) is None
