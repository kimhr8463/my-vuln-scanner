import os
from pathlib import Path

def vulnerable_input():
    filename = input("Filename: ")
    path = "/var/www/uploads/" + filename
    # ruleid: python-path-traversal-taint
    open(path, "r")

def vulnerable_flask():
    filename = request.args.get("file")
    path = "/var/www/uploads/" + filename
    # ruleid: python-path-traversal-taint
    open(path, "r")

def vulnerable_django():
    filename = request.GET.get("file")
    path = "/var/www/uploads/" + filename
    # ruleid: python-path-traversal-taint
    open(path, "r")

def vulnerable_pathlib():
    filename = input("Filename: ")
    path = Path("/var/www/uploads") / filename
    # ruleid: python-path-traversal-taint
    path.open("r")

def vulnerable_os_open():
    filename = input("Filename: ")
    path = "/var/www/uploads/" + filename
    # ruleid: python-path-traversal-taint
    os.open(path, os.O_RDONLY)

def safe_fixed_path():
    # ok: python-path-traversal-taint
    open("/var/www/uploads/default.txt", "r")

def safe_resolved_path(filename):
    base = Path("/var/www/uploads").resolve()
    target = (base / filename).resolve()

    if not target.is_relative_to(base):
        raise ValueError("Invalid path")

    # ok: python-path-traversal-taint
    return target.open("r")
