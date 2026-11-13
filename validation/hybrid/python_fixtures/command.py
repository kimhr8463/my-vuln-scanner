"""Command injection: vulnerable and safe cases; never execute this fixture."""

import os
import subprocess
from flask import request
from command_service import run_command


def direct():
    os.system(request.args.get("command"))  # vulnerable: direct


def intermediate():
    command = request.form.get("command")
    subprocess.run(command, shell=True)  # vulnerable: intermediate


def through_argument():
    command = request.args.get("command")
    helper(command)


def helper(command):
    os.system(command)  # vulnerable: argument


def across_files():
    run_command(request.args.get("command"))
