"""CLI 통합 검증용 Python 프로젝트."""

import os


def run_user_command():
    command = input("Command: ")
    os.system(command)
