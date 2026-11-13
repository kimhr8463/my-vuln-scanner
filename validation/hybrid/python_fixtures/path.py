"""Path traversal: vulnerable and safe cases; never execute this fixture."""

from flask import request
from path_service import read_file


def direct():
    return open(request.args.get("file"), encoding="utf-8").read()  # vulnerable: direct


def intermediate():
    name = request.form.get("file")
    path = "uploads/" + name
    return open(path, encoding="utf-8").read()  # vulnerable: intermediate


def through_argument():
    return helper(request.args.get("file"))


def helper(name):
    return open(name, encoding="utf-8").read()  # vulnerable: argument


def across_files():
    return read_file(request.args.get("file"))
