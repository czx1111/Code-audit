"""
Test Python application with intentional vulnerabilities
"""

import os
import pickle
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials - VULNERABILITY
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"

@app.route('/cmd')
def execute_command():
    # Command Injection vulnerability
    cmd = request.args.get('cmd')
    result = os.system(cmd)  # CRITICAL: Command injection
    return f"Result: {result}"

@app.route('/eval')
def evaluate_code():
    # Code Injection vulnerability
    code = request.args.get('code')
    result = eval(code)  # CRITICAL: Code injection
    return str(result)

@app.route('/sql')
def sql_query():
    # SQL Injection vulnerability
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # HIGH: SQL injection
    return query

@app.route('/xss')
def xss_example():
    # XSS vulnerability
    name = request.args.get('name')
    html = f"<h1>Hello, {name}</h1>"  # MEDIUM: XSS
    return html

@app.route('/deserialize')
def deserialize_data():
    # Insecure deserialization
    data = request.args.get('data')
    obj = pickle.loads(data.encode())  # CRITICAL: Insecure deserialization
    return str(obj)

@app.route('/subprocess')
def run_subprocess():
    # Subprocess with shell=True
    filename = request.args.get('file')
    subprocess.call(f"cat {filename}", shell=True)  # HIGH: Command injection
    return "Done"

def load_yaml_config(content):
    # Unsafe YAML loading
    import yaml
    config = yaml.load(content)  # HIGH: Unsafe YAML
    return config

if __name__ == '__main__':
    app.run(debug=True)
