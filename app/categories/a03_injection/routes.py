import subprocess

from flask import render_template, request, session
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import InjectionAccount
from app.extensions import db


@a03_bp.route("/")
def overview():
    return render_template("a03_injection/overview.html")


@a03_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: raw string-concatenated SQL, no parameterization -- this IS the lesson
        query = (
            f"SELECT * FROM injection_accounts "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = db.session.execute(text(query)).mappings().first()
        if row:
            session["a03_login_as"] = row["username"]
            session["a03_login_is_admin"] = row["is_admin"]
        else:
            error = "Invalid username or password."
    return render_template(
        "a03_injection/login.html",
        error=error,
        logged_in_as=session.get("a03_login_as"),
        is_admin=session.get("a03_login_is_admin", False),
    )


@a03_bp.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # VULNERABLE: raw string-concatenated SQL, no parameterization
        query = f"SELECT id, username FROM injection_accounts WHERE username LIKE '%{q}%'"
        results = db.session.execute(text(query)).all()
    return render_template("a03_injection/search.html", q=q, results=results)


@a03_bp.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    # VULNERABLE: HTML built by hand, then rendered with |safe -- no escaping at all
    greeting_html = f"<p>Hello, {name}! Welcome back.</p>"
    return render_template("a03_injection/greet.html", greeting_html=greeting_html, name=name)


@a03_bp.route("/check-username")
def check_username():
    username = request.args.get("username", "")
    exists = None
    if username:
        # VULNERABLE: raw string-concatenated SQL, no parameterization
        query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
        count = db.session.execute(text(query)).scalar()
        exists = bool(count)
    return render_template("a03_injection/check_username.html", username=username, exists=exists)


@a03_bp.route("/host-lookup", methods=["GET", "POST"])
def host_lookup():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            # VULNERABLE: shell=True with unsanitized, concatenated user input
            result = subprocess.run(
                f"getent hosts {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
        except subprocess.TimeoutExpired:
            output = "(lookup timed out)"
    return render_template("a03_injection/host_lookup.html", host=host, output=output)
