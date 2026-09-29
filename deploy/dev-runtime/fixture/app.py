"""Controlled onboarding fixture: intentionally unsafe string interpolation."""


def lookup(db, username: str):
    return db.execute("SELECT * FROM users WHERE username = '" + username + "'")
