import os
import subprocess

from flask import redirect, render_template, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")


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


@a03_bp.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        body = request.form.get("body", "")
        db.session.add(Comment(author=author, body=body))
        db.session.commit()
        return redirect(url_for("a03_injection.comments"))
    all_comments = Comment.query.order_by(Comment.id.desc()).all()
    return render_template("a03_injection/comments.html", comments=all_comments)


@a03_bp.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    xml_input = ""
    result = None
    error = None
    if request.method == "POST":
        xml_input = request.form.get("xml_input", "")
        try:
            # VULNERABLE: resolve_entities=True allows external entities to be expanded
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.fromstring(xml_input.encode(), parser=parser)
            name_el = tree.find("name")
            result = name_el.text if name_el is not None else "(no <name> element found)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xml_import.html", xml_input=xml_input, result=result, error=error
    )


@a03_bp.route("/xxe-ssrf", methods=["GET", "POST"])
def xxe_ssrf():
    xml_input = ""
    result = None
    error = None
    if request.method == "POST":
        xml_input = request.form.get("xml_input", "")
        try:
            # VULNERABLE: same resolve_entities=True flaw as xml_import(), reused
            # in a different feature -- here the entity target is a URL, not a file.
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.fromstring(xml_input.encode(), parser=parser)
            message_el = tree.find("message")
            result = message_el.text if message_el is not None else "(no <message> element found)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xxe_ssrf.html", xml_input=xml_input, result=result, error=error
    )
