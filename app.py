"""Gestion de salle de sport : Flask + SQLite, avec connexion.
Chaque compte = une salle, avec ses propres données (isolées des autres salles).

  pip install -r requirements.txt
  python app.py createuser <identifiant> <mot_de_passe> "<Nom de la salle>"
  python app.py            # http://127.0.0.1:5000
"""
import json
import os
import secrets
import sqlite3
import sys
import time

from flask import Flask, g, jsonify, redirect, render_template, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("GYM_DB", os.path.join(BASE, "gym.db"))
KEY_FILE = os.path.join(BASE, ".secret_key")
COLLECTIONS = {"members", "payments", "checkins", "settings"}

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "w") as f:
        f.write(secrets.token_hex(32))
app = Flask(__name__)
app.secret_key = open(KEY_FILE).read().strip()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("GYM_HTTPS")),  # mettre GYM_HTTPS=1 derrière HTTPS
    PERMANENT_SESSION_LIFETIME=14 * 24 * 3600,
)
FAILS = {}  # ip -> (nombre d'échecs, heure du dernier échec)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """CREATE TABLE IF NOT EXISTS users(
             id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL);
           CREATE TABLE IF NOT EXISTS docs(
             user_id INTEGER NOT NULL, col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
             PRIMARY KEY(user_id, col, id));"""
    )
    con.commit()
    con.close()


def create_user(username, password, gym):
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "INSERT INTO users(username, pw) VALUES(?, ?)",
        (username.strip().lower(), generate_password_hash(password)),
    )
    con.execute(
        "INSERT INTO docs VALUES(?, 'settings', 'main', ?)",
        (cur.lastrowid, json.dumps({"name": gym})),
    )
    con.commit()
    con.close()


# ---------- pages ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        n, last = FAILS.get(ip, (0, 0))
        if n >= 5 and time.time() - last < 60:
            error = "Trop d’essais. Réessayez dans une minute."
        else:
            u = db().execute(
                "SELECT * FROM users WHERE username=?",
                (request.form.get("username", "").strip().lower(),),
            ).fetchone()
            if u and check_password_hash(u["pw"], request.form.get("password", "")):
                FAILS.pop(ip, None)
                session.clear()
                session.permanent = True
                session["uid"] = u["id"]
                return redirect("/")
            FAILS[ip] = (n + 1, time.time())
            error = "Identifiant ou mot de passe incorrect."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
def index():
    if "uid" not in session:
        return redirect("/login")
    return send_file(os.path.join(BASE, "private", "app.html"))


# ---------- API ----------
@app.before_request
def guard_api():
    if request.path.startswith("/api/") and "uid" not in session:
        return jsonify(error="auth"), 401


def check(col):
    if col not in COLLECTIONS:
        raise KeyError(col)


@app.errorhandler(KeyError)
def bad_col(_):
    return jsonify(error="collection inconnue"), 400


@app.get("/api/<col>")
def list_docs(col):
    check(col)
    rows = db().execute(
        "SELECT id, data FROM docs WHERE user_id=? AND col=?", (session["uid"], col)
    ).fetchall()
    return jsonify([{"id": r["id"], "data": json.loads(r["data"])} for r in rows])


@app.route("/api/<col>/<doc_id>", methods=["PUT", "PATCH", "DELETE"])
def write_doc(col, doc_id):
    check(col)
    d, uid = db(), session["uid"]
    if request.method == "DELETE":
        d.execute("DELETE FROM docs WHERE user_id=? AND col=? AND id=?", (uid, col, doc_id))
    else:
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON attendu"), 400
        if request.method == "PATCH":
            row = d.execute(
                "SELECT data FROM docs WHERE user_id=? AND col=? AND id=?", (uid, col, doc_id)
            ).fetchone()
            body = {**(json.loads(row["data"]) if row else {}), **body}
        d.execute(
            "INSERT OR REPLACE INTO docs VALUES(?, ?, ?, ?)", (uid, col, doc_id, json.dumps(body))
        )
    d.commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    if len(sys.argv) == 5 and sys.argv[1] == "createuser":
        create_user(sys.argv[2], sys.argv[3], sys.argv[4])
        print("Compte créé :", sys.argv[2])
    else:
        app.run(host=os.environ.get("GYM_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
