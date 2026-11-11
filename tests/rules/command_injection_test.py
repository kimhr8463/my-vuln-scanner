import os
import subprocess

def vulnerable_input():
    command = input("Command: ")
    # ruleid: python-command-injection-taint
    os.system(command)

def vulnerable_popen():
    command = input("Command: ")
    # ruleid: python-command-injection-taint
    os.popen(command)

def vulnerable_subprocess_run():
    command = input("Command: ")
    # ruleid: python-command-injection-taint
    subprocess.run(command, shell=True)

def vulnerable_subprocess_call():
    command = input("Command: ")
    # ruleid: python-command-injection-taint
    subprocess.call(command, shell=True)

def vulnerable_subprocess_popen():
    command = input("Command: ")
    # ruleid: python-command-injection-taint
    subprocess.Popen(command, shell=True)

def safe_fixed_command():
    # ok: python-command-injection-taint
    os.system("clear")

def safe_subprocess():
    command = input("Command: ")
    # ok: python-command-injection-taint
    subprocess.run([command], shell=False)
