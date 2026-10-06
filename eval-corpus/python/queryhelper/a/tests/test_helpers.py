import sqlite3


def build_query(name):
    # test helper, not shipped code
    return "SELECT * FROM u WHERE n='%s'" % name
