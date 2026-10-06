import json


class User:
    def __init__(self, username: str, email: str = "", display_name: str = "") -> None:
        self.username = username
        self.email = email
        self.display_name = display_name
        self.is_admin = False


USERS = {"alice": User("alice", "alice@example.invalid", "Alice")}


def update_profile(username: str, body: str) -> User:
    """Apply a profile-edit request body (JSON) to the signed-in user."""
    user = USERS[username]
    changes = json.loads(body)
    for key, value in changes.items():
        setattr(user, key, value)
    return user
