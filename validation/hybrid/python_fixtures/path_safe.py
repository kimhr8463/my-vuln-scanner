"""Path traversal negative fixtures; never execute this file."""

from flask import request


def fixed():
    return open("fixed.txt", encoding="utf-8").read()  # safe: fixed


def validated():
    choice = request.args.get("file")
    if choice not in ("a", "b"):
        return
    name = "a.txt" if choice == "a" else "b.txt"
    return open(name, encoding="utf-8").read()  # safe: allowlist mapping


def numeric():
    number = int(request.args.get("file"))
    return open(f"uploads/{number}.txt", encoding="utf-8").read()  # safe: numeric conversion


def no_sink():
    return request.args.get("file")  # safe: no sink
