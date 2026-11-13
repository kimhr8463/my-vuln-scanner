import sqlite3


def run_query(name):
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")  # vulnerable: two files
