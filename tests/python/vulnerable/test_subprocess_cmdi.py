import subprocess
import os

def run_command():
    command = input("Enter command: ")

    subprocess.run(command, shell=True)

def call_command():
    command = input("Enter command: ")

    subprocess.call(command, shell=True)

def popen_command():
    command = input("Enter command: ")

    subprocess.Popen(command, shell=True)
