import sqlite3


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.commit()
    return conn


def _run(conn, sql: str):
    return conn.execute(sql).fetchall()


def healthcheck(conn) -> list:
    """Only ever runs a fixed query; the sink is not reachable from untrusted input."""
    return _run(conn, "SELECT 1")
