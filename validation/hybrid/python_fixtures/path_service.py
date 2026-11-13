def read_file(name):
    return open(name, encoding="utf-8").read()  # vulnerable: two files
