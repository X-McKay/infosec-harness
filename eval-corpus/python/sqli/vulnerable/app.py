import sqlite3


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'public')")
    conn.execute("INSERT INTO users VALUES (2, 'admin', 'TOP-SECRET')")
    conn.commit()
    return conn


def get_user(conn: sqlite3.Connection, name: str):
    """Look up a user by name. VULNERABLE: `name` is concatenated into the SQL text."""
    cur = conn.cursor()
    cur.execute("SELECT id, name, secret FROM users WHERE name = '%s'" % name)
    return cur.fetchall()
