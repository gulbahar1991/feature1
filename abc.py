import os
import sqlite3
import hashlib
import subprocess
import requests
import random
import json
import jwt  # PyJWT library for token handling (vulnerable example)

# Vulnerability 1: Hardcoded API Key (B105)
API_KEY = "123456789abcdef"

# Vulnerability 2: Weak hashing algorithm (B303)
def insecure_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()  # SHA-1 is insecure

# Vulnerability 3: Command Injection (B602)
def execute_user_command():
    user_input = input("Enter a shell command: ")
    subprocess.run(user_input, shell=True)  # User input passed directly to shell

# Vulnerability 4: SQL Injection (B608)
def search_user(db_connection, username):
    cursor = db_connection.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # Unsanitized input
    cursor.execute(query)  # Vulnerable to SQL injection
    return cursor.fetchall()

# Vulnerability 5: Sensitive Data Exposure in JWT (B106)
def generate_jwt_token(user_id):
    secret_key = "mysecret"  # Hardcoded and weak secret key
    payload = {"user_id": user_id, "role": "admin"}
    token = jwt.encode(payload, secret_key, algorithm="HS256")  # Weak secret key
    return token

# Vulnerability 6: SSL Certificate Validation Disabled (B501)
def fetch_external_data(url):
    response = requests.get(url, verify=False)  # Ignoring SSL certificate validation
    if response.status_code == 200:
        return response.json()
    return None

# Vulnerability 7: Insecure Random Number Generator (B311)
def generate_insecure_token():
    return random.randint(100000, 999999)  # Predictable randomness

# Main application
def main():
    print("Welcome to the insecure app!")

    # Vulnerable hashing
    password = input("Enter a password to hash: ")
    print(f"Insecure SHA-1 hash: {insecure_hash(password)}")

    # Vulnerable command execution
    execute_user_command()

    # SQL injection
    db_connection = sqlite3.connect(":memory:")  # In-memory database
    db_connection.execute("CREATE TABLE users (username TEXT, password TEXT)")
    db_connection.execute("INSERT INTO users VALUES ('admin', 'password')")
    db_connection.commit()

    username = input("Enter a username to search for: ")
    users = search_user(db_connection, username)
    print(f"User search results: {users}")

    # Generate JWT token
    token = generate_jwt_token(1)
    print(f"Generated JWT token: {token}")

    # Fetch external data with SSL disabled
    url = input("Enter URL to fetch data: ")
    data = fetch_external_data(url)
    print(f"Fetched data: {json.dumps(data, indent=2)}")

    # Insecure token generation
    print(f"Insecure token: {generate_insecure_token()}")

if __name__ == "__main__":
    main()
