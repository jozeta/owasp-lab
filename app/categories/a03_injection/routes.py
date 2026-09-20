import os
import subprocess
import urllib.request

from flask import redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")


class _HttpFetchingResolver(etree.Resolver):
    """Fetches http(s) SYSTEM URIs directly, since PyPI's lxml wheels ship
    a libxml2 build with HTTP transport disabled by default. Falls through
    to libxml2's default resolution (e.g. file://) for anything else."""

    def resolve(self, url, pubid, context):
        if url.startswith("http://") or url.startswith("https://"):
            data = urllib.request.urlopen(url, timeout=5).read()
            return self.resolve_string(data, context)
        return None


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
            if name_el is None:
                result = "(no <name> element found)"
            elif name_el.text:
                result = name_el.text
            else:
                result = "(empty)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xml_import.html",
        xml_input=xml_input,
        result=result,
        error=error,
        secret_path=XXE_SECRET_PATH,
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
            # A custom resolver is registered to fetch http(s) URIs, since libxml2's
            # built-in HTTP transport is disabled by default in this environment --
            # this mirrors a real-world pattern: apps add custom entity resolvers for
            # legitimate reasons and forget to scope them to safe schemes.
            parser = etree.XMLParser(resolve_entities=True)
            parser.resolvers.add(_HttpFetchingResolver())
            tree = etree.fromstring(xml_input.encode(), parser=parser)
            message_el = tree.find("message")
            if message_el is None:
                result = "(no <message> element found)"
            elif message_el.text:
                result = message_el.text
            else:
                result = "(empty)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xxe_ssrf.html", xml_input=xml_input, result=result, error=error
    )


@a03_bp.route("/email-preview", methods=["GET", "POST"])
def email_preview():
    greeting_template = ""
    result = None
    error = None
    if request.method == "POST":
        greeting_template = request.form.get("greeting_template", "")
        try:
            # VULNERABLE: render_template_string renders user input as live
            # Jinja template SOURCE, not as inert data -- this app's Jinja
            # environment is not sandboxed, so any Jinja expression syntax
            # submitted here gets evaluated on the server.
            result = render_template_string(greeting_template)
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/email_preview.html",
        greeting_template=greeting_template,
        result=result,
        error=error,
    )


SSTI_BLOCKED_KEYWORDS = ["os", "import", "exec", "eval", "popen", "subprocess", "system"]


@a03_bp.route("/bio-preview", methods=["GET", "POST"])
def bio_preview():
    bio_template = ""
    result = None
    error = None
    if request.method == "POST":
        bio_template = request.form.get("bio_template", "")
        lowered = bio_template.lower()
        blocked_word = next((w for w in SSTI_BLOCKED_KEYWORDS if w in lowered), None)
        if blocked_word:
            error = f'Blocked: template text contains forbidden word "{blocked_word}"'
        else:
            try:
                # VULNERABLE: same render_template_string flaw as email_preview(),
                # "protected" only by a naive substring blacklist above -- that
                # doesn't fix the underlying bug (rendering attacker-controlled
                # text as template source at all), so it's bypassable.
                result = render_template_string(bio_template)
            except Exception as e:
                error = str(e)
    return render_template(
        "a03_injection/bio_preview.html",
        bio_template=bio_template,
        result=result,
        error=error,
    )
