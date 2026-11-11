import sqlite3

def vulnerable_concat():
    user_id = input("User ID: ")
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def vulnerable_fstring():
    user_id = input("User ID: ")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def vulnerable_format():
    user_id = input("User ID: ")
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def safe_parameterized():
    user_id = input("User ID: ")
    query = "SELECT * FROM users WHERE id = ?"
    # ok: python-sql-injection-taint
    cursor.execute(query, (user_id,))

def vulnerable_flask_get():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def vulnerable_flask_post():
    user_id = request.form.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def vulnerable_django_get():
    user_id = request.GET.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-taint
    cursor.execute(query)

def vulnerable_django_post():
    user_id = request.POST.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # ruleid: python-sql-injection-taint
    cursor.execute(query)
