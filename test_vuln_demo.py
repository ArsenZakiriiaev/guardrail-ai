"""Тестовый файл с кучей уязвимостей для проверки watcher."""

import os
import pickle
import subprocess
import hashlib
import yaml
import tempfile
import random
import sqlite3

# 1. Хардкод AWS ключа
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 2. Хардкод пароля
DB_PASSWORD = "super_secret_password_123"

# 3. eval от пользователя
user_input = input("Enter expression: ")
result = eval(user_input)

# 4. subprocess с shell=True
cmd = input("Enter command: ")
subprocess.call(cmd, shell=True)

# 5. os.system
os.system("rm -rf /tmp/data")

# 6. pickle.load из файла (десериализация)
with open("data.pkl", "rb") as f:
    data = pickle.load(f)

# 7. Небезопасный yaml.load
with open("config.yml") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

# 8. tempfile.mktemp (race condition)
tmp = tempfile.mktemp()

# 9. Слабый хеш MD5
password_hash = hashlib.md5(b"password").hexdigest()

# 10. Токен через random (не криптостойкий)
token = ''.join(random.choices('abcdef0123456789', k=32))

# 11. SQL injection через f-string
username = input("Username: ")
query = f"SELECT * FROM users WHERE name = '{username}'"
conn = sqlite3.connect("app.db")
conn.execute(query)
