"""Deliberately-vulnerable demo backend (DEMO ONLY — never deploy).

It exists so the RASP has real syscalls and real SQL to react to. Each endpoint
maps to one attack class (see demo/attacks/scenarios.yaml). It runs UNDER the
RASP LD_PRELOAD shim; a before/after request hook hands the shim the
X-WAF-Request-ID / -IP / -User the orchestrator injected, so the RASP can
attribute each effect to the originating IP / user.

Containment: binds only on the private demo network; /etc/passwd here is a
planted fake; the SSRF "metadata" target is an in-network stub.
"""
import ctypes
import os
import subprocess

import psycopg2
from flask import Flask, request, jsonify, g

# The RASP exec interposer emits its verdict from the fork child (between fork
# and exec). That is only safe with a real fork() -- which gives the child a
# private copy of memory and runs pthread_atfork handlers. CPython defaults to
# vfork() (shared address space, no atfork), under which instrumenting the child
# would corrupt this parent process. Disable it so RCE is caught without crashing
# the backend. (Demo backend only; a production RASP uses the kernel enforcement
# core, not LD_PRELOAD, and needs no such cooperation.)
subprocess._USE_VFORK = False
subprocess._USE_POSIX_SPAWN = False

app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://waf:waf@postgres:5432/shop")

# ── RASP context bridge (calls the LD_PRELOADed shim via ctypes) ─────────────
try:
    _rasp = ctypes.CDLL(None)  # process global symbol table; shim is preloaded
    _rasp.rasp_ctx_set.argtypes = [ctypes.c_char_p] * 4
    _rasp.rasp_ctx_clear.argtypes = []
    _RASP_OK = True
except Exception:
    _RASP_OK = False


def _b(s):
    return (s or "").encode()


@app.before_request
def _rasp_enter():
    if _RASP_OK:
        try:
            _rasp.rasp_ctx_set(
                _b(request.headers.get("X-WAF-Request-ID")),
                _b(request.headers.get("X-WAF-IP", request.remote_addr)),
                _b(request.headers.get("X-WAF-User")),
                _b(request.path))
        except Exception:
            pass


@app.teardown_request
def _rasp_exit(exc):
    if _RASP_OK:
        try:
            _rasp.rasp_ctx_clear()
        except Exception:
            pass


@app.teardown_request
def _close_db(exc):
    # CRITICAL: close the per-request DB connection. Without this every request
    # leaks a Postgres connection and the backend dies after ~100 requests.
    conn = g.pop("db", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = True   # each request is self-contained; no lingering txns
    return g.db


# ── benign endpoints (build trust) ───────────────────────────────────────────
@app.get("/")
def home():
    return "<h1>Demo Shop</h1><a href='/products?page=1'>products</a>"


@app.get("/products")
def products():
    page = request.args.get("page", "1")
    cur = db().cursor()
    cur.execute("SELECT id, name FROM products ORDER BY id LIMIT 10 OFFSET %s",
                (max(0, (int(page) - 1) * 10) if page.isdigit() else 0,))
    return jsonify(cur.fetchall())


@app.post("/login")
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    cur = db().cursor()
    cur.execute("SELECT id FROM users WHERE username=%s AND password=%s", (u, p))
    return ("ok", 200) if cur.fetchone() else ("bad credentials", 401)


# ── vulnerable endpoints (RASP catches the real effect) ──────────────────────
@app.get("/search")
def search():
    # SQLi: user input concatenated straight into the query (channel B).
    q = request.args.get("q", "")
    cur = db().cursor()
    cur.execute("SELECT id, name FROM products WHERE name LIKE '%" + q + "%'")
    return jsonify(cur.fetchall())


@app.get("/api/users/<uid>")
def get_user(uid):
    # Broken access control + SQLi: a product-facing route reading the users
    # table, with the id concatenated in (channel B: structural + db_unauth).
    cur = db().cursor()
    cur.execute("SELECT id, username FROM users WHERE id=" + uid)
    return jsonify(cur.fetchall())


@app.get("/ping")
def ping():
    # Command injection -> execve (channel A: RCE).
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run("ping -c1 " + host, shell=True, capture_output=True)
    return out.stdout or out.stderr or b"", 200


@app.get("/download")
def download():
    # Path traversal / LFI -> open() (channel A).
    name = request.args.get("file", "readme.txt")
    with open(name) as f:
        return f.read(), 200


@app.post("/upload")
def upload():
    # Web-shell upload -> executable write to a servable dir (channel A).
    name = request.form.get("name", "x.txt")
    data = request.form.get("data", "")
    os.makedirs("uploads", exist_ok=True)
    with open(os.path.join("uploads", name), "w") as f:
        f.write(data)
    return "stored", 200


@app.get("/fetch")
def fetch():
    # SSRF -> outbound connect() (channel A).
    import urllib.request
    url = request.args.get("url", "http://localhost/")
    with urllib.request.urlopen(url, timeout=2) as r:
        return r.read(), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9090")), threaded=True)
