import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return conn.execute(query).fetchone()

def render_page(content):
    # XSS vulnerability
    return "<html><body>" + content + "</body></html>"

def read_file(filename):
    # Path traversal vulnerability
    with open("/var/data/" + filename) as f:
        return f.read()

def execute_command(user_input):
    # Command injection vulnerability
    import os
    os.system("ls " + user_input)