"""Command injection negative fixtures; never execute this file."""

import os
import subprocess
from flask import request


def fixed():
    os.system("echo fixed")  # safe: fixed


def validated():
    choice = request.args.get("command")
    if choice not in ("status", "version"):
        return
    command = "echo fixed" if choice == "status" else "echo version"
    os.system(command)  # safe: allowlist mapping


def numeric_argument():
    number = int(request.args.get("command"))
    subprocess.run(["echo", str(number)], shell=False)  # safe: numeric, no shell


def no_sink():
    return request.args.get("command")  # safe: no sink
