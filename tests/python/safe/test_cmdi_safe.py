import os
import subprocess

def clear_terminal():
    os.system("clear")

def list_files():
    subprocess.run(["ls", "-al"], check=True)
