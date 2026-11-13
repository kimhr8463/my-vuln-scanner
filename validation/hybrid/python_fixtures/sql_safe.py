"""SQL injection negative fixtures; never execute this file."""

import sqlite3
from flask import request


def fixed():
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM users")  # safe: fixed


def parameterized():
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),))  # safe: binding


def numeric():
    db = sqlite3.connect(":memory:")
    user_id = int(request.args.get("name"))
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")  # safe: numeric conversion


def no_sink():
    return request.args.get("name")  # safe: no sink
