# Test vulnerable Python code for security audit
import os
import pickle
import yaml
import subprocess
from flask import Flask, request

app = Flask(__name__)

# SQL Injection vulnerability
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection!
    return query

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system(f"ping -c 4 {host}")  # Command Injection!
    return str(result)

# Code Injection vulnerability
@app.route('/eval')
def evaluate():
    expr = request.args.get('expr')
    result = eval(expr)  # Code Injection!
    return str(result)

# Insecure Deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data')
    obj = pickle.loads(data.encode())  # Insecure Deserialization!
    return str(obj)

# YAML Deserialization
@app.route('/yaml')
def load_yaml():
    data = request.args.get('data')
    obj = yaml.load(data)  # Unsafe YAML load!
    return str(obj)

# Hardcoded credentials
DB_PASSWORD = "SuperSecretPassword123!"  # Hardcoded password!
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key!

# Path Traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    with open(f"/data/{filename}") as f:  # Path Traversal!
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)
