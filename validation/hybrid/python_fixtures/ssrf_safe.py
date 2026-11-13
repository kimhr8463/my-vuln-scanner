"""SSRF negative fixtures; never execute this file."""

import requests
from flask import request


def fixed():
    return requests.get("https://example.org/fixed")  # safe: fixed


def validated():
    choice = request.args.get("url")
    if choice not in ("a", "b"):
        return
    url = "https://example.org/a" if choice == "a" else "https://example.org/b"
    return requests.get(url)  # safe: allowlist mapping


def numeric():
    number = int(request.args.get("url"))
    return requests.get(f"https://example.org/items/{number}")  # safe: fixed host


def no_sink():
    return request.args.get("url")  # safe: no sink
