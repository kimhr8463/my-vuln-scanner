import os
import subprocess

def popen_test():
    command = input("Command: ")
    os.popen(command)

def safe_subprocess():
    command = input("Command: ")
    subprocess.run([command], shell=False)

def safe_fixed_command():
    subprocess.run(["ls", "-al"], shell=False)
