import sqlite3


def build_query(name):
    # test helper
    return "SELECT * FROM u WHERE n='%s'" % name
