import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import yaml
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super-secret-password"
DB_PATH = Path("/tmp/guardrail_demo.sqlite3")

app = FastAPI(title="Guardrail Vulnerable Demo")


@app.middleware("http")
async def insecure_headers(request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.on_event("startup")
def init_demo_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users(id, username, role) VALUES (?, ?, ?)",
        [
            (1, "alice", "admin"),
            (2, "bob", "analyst"),
            (3, "charlie", "guest"),
        ],
    )
    conn.commit()
    conn.close()


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
      <body>
        <h1>Guardrail vulnerable demo</h1>
        <p>Endpoints: /users, /shell, /fetch, /login, /health</p>
      </body>
    </html>
    """


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login")
def login(response: Response):
    response.set_cookie("sessionid", "demo-session-token")
    return {"ok": True}


@app.get("/users")
def query_user(user_id: str = "1"):
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(f"SELECT id, username, role FROM users WHERE id = {user_id}").fetchall()
        return [{"id": row[0], "username": row[1], "role": row[2]} for row in rows]
    finally:
        conn.close()


@app.post("/shell")
def run_shell_command(command: str):
    output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
    return PlainTextResponse(output)


@app.get("/fetch")
def fetch_url(url: str):
    content = urllib.request.urlopen(url, timeout=5).read().decode("utf-8", errors="replace")
    return PlainTextResponse(content)


@app.post("/eval")
def run_user_expression(user_input: str):
    return {"result": repr(eval(user_input))}


@app.post("/pickle")
def load_pickle_blob(blob_hex: str):
    blob = bytes.fromhex(blob_hex)
    data = pickle.loads(blob)
    return {"type": type(data).__name__}


@app.post("/yaml")
def parse_yaml_document(document: str):
    return {"parsed": str(yaml.load(document))}


@app.post("/yaml-full")
def parse_yaml_document_full_loader(document: str):
    return {"parsed": str(yaml.load(document, Loader=yaml.FullLoader))}


@app.get("/temp")
def build_temp_path():
    return {"tmp": tempfile.mktemp()}


@app.post("/system")
def run_system_command(command: str):
    return {"exit_code": os.system(command)}


@app.get("/md5")
def md5_digest(value: str = "hello"):
    return {"digest": hashlib.md5(value.encode()).hexdigest()}


@app.get("/sha1")
def sha1_digest(value: str = "hello"):
    return {"digest": hashlib.sha1(value.encode()).hexdigest()}


@app.get("/token")
def issue_session_token():
    session_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return JSONResponse({"token": session_token})
