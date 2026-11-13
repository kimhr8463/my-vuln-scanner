"""SQL injection: vulnerable and safe cases; never execute this fixture."""

import sqlite3
from flask import request
from sql_service import run_query


def direct():
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM users WHERE name = '" + request.args.get("name") + "'")  # vulnerable: direct


def intermediate():
    db = sqlite3.connect(":memory:")
    name = request.form.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)  # vulnerable: intermediate


def through_argument():
    helper(request.args.get("name"))


def helper(name):
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")  # vulnerable: argument


def across_files():
    run_query(request.args.get("name"))
