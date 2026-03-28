import hashlib
import os
import pickle
import random
import subprocess
import tempfile

import yaml


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super-secret-password"


def run_user_expression(user_input: str) -> object:
    return eval(user_input)


def run_shell_command(command: str) -> None:
    subprocess.run(command, shell=True)


def load_pickle_blob(blob: bytes) -> object:
    return pickle.loads(blob)


def parse_yaml_document(document: str) -> object:
    return yaml.load(document)


def parse_yaml_document_full_loader(document: str) -> object:
    return yaml.load(document, Loader=yaml.FullLoader)


def build_temp_path() -> str:
    return tempfile.mktemp()


def run_system_command(command: str) -> int:
    return os.system(command)


def md5_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1_digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def issue_session_token() -> str:
    session_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return session_token


def query_user(cursor, user_id: str):
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
