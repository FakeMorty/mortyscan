"""Intentionally vulnerable Flask app for MortyScan testing.
DO NOT EXPOSE TO THE INTERNET. Educational use only."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)
DB = Path(__file__).parent / "lab.db"


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if DB.exists(): DB.unlink()
    c = db()
    c.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);
        INSERT INTO users(name,email,role) VALUES
          ('alice','alice@lab.local','admin'),
          ('bob','bob@lab.local','user'),
          ('carol','carol@lab.local','user');
    """)
    c.commit(); c.close()


init_db()

INDEX = """
<!doctype html><title>Lab</title>
<h1>Vulnerable Lab</h1>
<ul>
  <li><a href="/search?q=alice">/search?q=alice</a> — SQLi error-based</li>
  <li><a href="/user?id=1">/user?id=1</a> — SQLi boolean/time</li>
  <li><a href="/greet?name=Morty">/greet?name=Morty</a> — reflected XSS</li>
  <li><a href="/file?name=note.txt">/file?name=note.txt</a> — LFI</li>
  <li><a href="/go?url=/">/go?url=...</a> — open redirect</li>
  <li><a href="/fetch?url=https://example.com">/fetch?url=...</a> — SSRF</li>
  <li><a href="/.env">/.env</a> — exposed secret</li>
  <li><a href="/admin/">/admin/</a> — restricted</li>
  <li><a href="/api/v1/users">/api/v1/users</a> — JSON</li>
</ul>
<form action="/login" method="post">
  <input name="username"><input name="password" type="password">
  <button>login</button>
</form>
"""


@app.route("/")
def index():
    return INDEX


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.env\n"


# --- SQLi ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db()
    try:
        rows = conn.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'").fetchall()
        return "<br>".join(f"{r['id']} {r['name']} {r['email']}" for r in rows) or "no rows"
    except Exception as e:
        return f"<pre>You have an error in your SQL syntax: {e}</pre>", 500


@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    conn = db()
    try:
        # boolean-based + time-based via sleep
        if "SLEEP" in uid.upper():
            time.sleep(5)
            uid = "1"
        row = conn.execute(f"SELECT * FROM users WHERE id={uid}").fetchone()
        if row:
            return f"id={row['id']} name={row['name']} role={row['role']}"
        return "no user", 404
    except Exception as e:
        return f"<pre>sqlite3.OperationalError: {e}</pre>", 500


# --- XSS ---
@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    return render_template_string(f"<h1>Hello {name}!</h1>")  # unsafe interpolation


# --- LFI ---
@app.route("/file")
def file_view():
    name = request.args.get("name", "")
    try:
        path = os.path.join("/", name) if name.startswith("/") else os.path.join(
            str(Path(__file__).parent), name)
        with open(path, "rb") as f:
            return f.read()[:4096]
    except Exception as e:
        return f"err: {e}", 500


# --- Open redirect ---
@app.route("/go")
def go():
    return redirect(request.args.get("url", "/"), code=302)


# --- SSRF (reflective) ---
@app.route("/fetch")
def fetch():
    import urllib.request
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            return resp.read()[:5000]
    except Exception as e:
        return f"fetch err: {e}", 500


# --- Exposed secrets ---
@app.route("/.env")
def env():
    return ("DB_PASSWORD=hunter2\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "STRIPE_KEY=sk_test_FAKE1234MORTYSCAN_TESTONLY\n"), 200, {"Content-Type": "text/plain"}


@app.route("/admin/")
def admin():
    return "forbidden", 403


@app.route("/api/v1/users")
def api_users():
    conn = db()
    rows = conn.execute("SELECT id, name, email FROM users").fetchall()
    return {"users": [dict(r) for r in rows]}


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    return f"Welcome {u}"  # also reflected XSS in POST


# --- intentionally bad headers & cookie ---
@app.after_request
def hdr(resp):
    resp.headers["Server"] = "VulnLab/0.1 (Werkzeug)"
    resp.headers["X-Powered-By"] = "PHP/5.6.40"  # bait
    # Notice: NO CSP / HSTS / X-Frame-Options / X-Content-Type-Options
    if request.path == "/login":
        resp.set_cookie("session", "abc123")  # no HttpOnly, no Secure, no SameSite
    # CORS bad
    if request.headers.get("Origin"):
        resp.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
