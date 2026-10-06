"""A tiny notes service. Each note belongs to one user."""


class Store:
    def __init__(self):
        # note_id -> {"owner": username, "body": text}
        self.notes = {}
        self._next = 1

    def add_note(self, owner: str, body: str) -> int:
        note_id = self._next
        self._next += 1
        self.notes[note_id] = {"owner": owner, "body": body}
        return note_id


def get_note(store: Store, current_user: str, note_id: int):
    """Return a note by id for the authenticated caller."""
    note = store.notes.get(note_id)
    if note is None:
        return None
    if note["owner"] != current_user:
        return None
    return note
