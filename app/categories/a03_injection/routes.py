import csv
import io
import os
import re
import subprocess
import urllib.request

from flask import Response, redirect, render_template, render_template_string, request, session, url_for
from ldap3 import SUBTREE
from lxml import etree
from sqlalchemy import text

from app import BASE_DIR
from app.categories.a03_injection import a03_bp, ldap_client
from app.categories.a03_injection.models import Comment, Employee, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
CMD_SECRET_PATH = os.path.join(os.path.dirname(__file__), "cmd_secret.txt")
ACCOUNT_RECOVERY_PIN = "7429"

# File-backed, not session-backed: the leak request originates from a
# sandboxed data: URI iframe with an opaque origin, so the browser never
# sends the app's session cookie with it -- a session write there is a
# throwaway nobody reads back. A plain shared log file needs no cookie at
# all, avoids the lost-update race of concurrent session read-modify-writes,
# and (like A09's LOG_FILE_PATH) is visible across all gunicorn worker
# processes, unlike an in-memory list.
CSS_EXFIL_LOG_PATH = os.path.join(BASE_DIR, "instance", "a03_css_exfil.log")

ARCHIVE_EXPORT_DIR = os.path.join(BASE_DIR, "instance", "a03_archive_export")
ARGUMENT_INJECTION_PROOF_PATH = "/tmp/a03_argument_injection_proof.txt"


def _append_css_exfil_leak(value):
    os.makedirs(os.path.dirname(CSS_EXFIL_LOG_PATH), exist_ok=True)
    with open(CSS_EXFIL_LOG_PATH, "a") as f:
        f.write(value + "\n")


def _read_css_exfil_leaks():
    if not os.path.exists(CSS_EXFIL_LOG_PATH):
        return []
    with open(CSS_EXFIL_LOG_PATH) as f:
        return [line.rstrip("\n") for line in f if line.strip()]


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
        uploaded = request.files.get("xml_file")
        if uploaded and uploaded.filename:
            xml_input = uploaded.read().decode("utf-8", errors="replace")
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


@a03_bp.route("/xml-import/demo-payload.xml")
def xml_import_demo_payload():
    # A ready-to-upload copy of the exact payload shown in this example's
    # Exploitation section -- the secret path is resolved at request time
    # since it's an absolute filesystem path that varies by environment.
    payload = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE contact [\n"
        f'  <!ENTITY xxe SYSTEM "file://{XXE_SECRET_PATH}">\n'
        "]>\n"
        "<contact><name>&xxe;</name></contact>\n"
    )
    return Response(
        payload,
        mimetype="application/xml",
        headers={"Content-Disposition": "attachment; filename=xxe-file-disclosure-demo.xml"},
    )


@a03_bp.route("/xxe-ssrf", methods=["GET", "POST"])
def xxe_ssrf():
    xml_input = ""
    result = None
    error = None
    if request.method == "POST":
        uploaded = request.files.get("xml_file")
        if uploaded and uploaded.filename:
            xml_input = uploaded.read().decode("utf-8", errors="replace")
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


@a03_bp.route("/xxe-ssrf/demo-payload.xml")
def xxe_ssrf_demo_payload():
    # A ready-to-upload copy of the exact payload shown in this example's
    # Detect/Exploitation sections -- the target URL is fixed, not
    # environment-dependent, so this file is identical on every install.
    payload = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE status [<!ENTITY probe SYSTEM "http://127.0.0.1:5000/healthz">]>\n'
        "<status><message>&probe;</message></status>\n"
    )
    return Response(
        payload,
        mimetype="application/xml",
        headers={"Content-Disposition": "attachment; filename=xxe-ssrf-demo.xml"},
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


@a03_bp.route("/directory-login", methods=["GET", "POST"])
def directory_login():
    username = ""
    result = None
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = ldap_client.get_ldap_connection()
        try:
            # VULNERABLE: raw f-string interpolation into an LDAP filter, no escaping
            filt = f"(&(uid={username})(userPassword={password}))"
            conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["cn"])
            if conn.entries:
                cn = str(conn.entries[0].cn)
                result = f"Welcome, {cn}!"
            else:
                error = "Invalid username or password."
        finally:
            conn.unbind()
    return render_template(
        "a03_injection/directory_login.html", username=username, result=result, error=error
    )


@a03_bp.route("/directory-search", methods=["GET", "POST"])
def directory_search():
    target = ""
    query = ""
    result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        query = request.form.get("query", "")
        conn = ldap_client.get_ldap_connection()
        try:
            # VULNERABLE: same raw f-string interpolation flaw as directory_login(),
            # reused in a different feature -- here the response is BLIND (only
            # found/not-found is shown), not the matched value itself, which is
            # exactly what makes boolean-based blind injection extraction possible.
            filt = f"(&(uid={target})(description={query}*))"
            conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["uid"])
            result = "Match found" if conn.entries else "No match"
        finally:
            conn.unbind()
    return render_template(
        "a03_injection/directory_search.html", target=target, query=query, result=result
    )


@a03_bp.route("/roster")
def roster():
    sort = request.args.get("sort", "id")
    # VULNERABLE: raw string-concatenated SQL in the ORDER BY clause, no
    # parameterization -- ORDER BY targets are identifiers/expressions, not
    # literal values, so bound parameters (which only substitute literal
    # values) can't protect this clause the way they protect a WHERE clause.
    query = f"SELECT id, name, email, department FROM a03_employees ORDER BY {sort}"
    results = db.session.execute(text(query)).all()
    return render_template("a03_injection/roster.html", sort=sort, results=results)


@a03_bp.route("/roster-lookup")
def roster_lookup():
    emp_id = request.args.get("id", "")
    found = None
    if emp_id:
        # VULNERABLE: raw string-concatenated SQL in a NUMERIC context, no
        # parameterization -- unlike every other SQLi example in this lab,
        # there's no string literal to break out of here at all; the input
        # is substituted directly as a bare numeric/expression token.
        query = f"SELECT COUNT(*) FROM a03_employees WHERE id = {emp_id}"
        count = db.session.execute(text(query)).scalar()
        found = bool(count)
    return render_template("a03_injection/roster_lookup.html", emp_id=emp_id, found=found)


def filter_level_1(payload: str) -> str:
    # VULNERABLE: blocks only the literal substring "<script", nothing else
    if "<script" in payload.lower():
        return "[blocked: script tag detected]"
    return payload


def filter_level_2(payload: str) -> str:
    # VULNERABLE: strips "<script>" and "</script>" as two SEPARATE passes --
    # doesn't re-scan its own output, so nested/interleaved tags reconstruct
    # a real <script> tag from the leftover fragments
    payload = re.sub(r"<script>", "", payload, flags=re.IGNORECASE)
    payload = re.sub(r"</script>", "", payload, flags=re.IGNORECASE)
    return payload


def filter_level_3(payload: str) -> str:
    # VULNERABLE: escapes only angle brackets -- safe in a tag context, but
    # this value is reflected inside an HTML attribute, where an unescaped
    # quote is what actually needs escaping
    return payload.replace("<", "&lt;").replace(">", "&gt;")


@a03_bp.route("/filter-challenge")
def filter_challenge():
    level = request.args.get("level", "1")
    payload = request.args.get("payload", "")
    if level == "2":
        filtered = filter_level_2(payload)
    elif level == "3":
        filtered = filter_level_3(payload)
    else:
        level = "1"
        filtered = filter_level_1(payload)
    return render_template(
        "a03_injection/filter_challenge.html",
        level=level,
        payload=payload,
        filtered=filtered,
    )


@a03_bp.route("/filtered-host-lookup", methods=["GET", "POST"])
def filtered_host_lookup():
    host = ""
    output = None
    blocked = False
    if request.method == "POST":
        host = request.form.get("host", "")
        if any(bad in host for bad in (";", "&", "|")):
            blocked = True
            host = ""
        else:
            # VULNERABLE: blacklist checks only ";", "&", "|" -- a literal
            # newline is just as good a command separator to /bin/sh and
            # isn't checked for at all
            result = subprocess.run(
                f"getent hosts {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
    return render_template(
        "a03_injection/filtered_host_lookup.html",
        host=host,
        output=output,
        blocked=blocked,
    )


@a03_bp.route("/generate-report", methods=["GET", "POST"])
def generate_report():
    report_name = ""
    submitted = False
    if request.method == "POST":
        report_name = request.form.get("report_name", "")
        # VULNERABLE: raw string-concatenated shell command, output
        # discarded -- the response text below is identical no matter
        # what happens, so the ONLY signal available is how long the
        # request took to complete
        subprocess.run(
            f"touch /tmp/report_{report_name}.pdf",
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        submitted = True
    return render_template(
        "a03_injection/generate_report.html",
        report_name=report_name,
        submitted=submitted,
        secret_path=CMD_SECRET_PATH,
    )


@a03_bp.route("/product-lookup", methods=["GET", "POST"])
def product_lookup():
    product_id = ""
    result = None
    error = None
    if request.method == "POST":
        product_id = request.form.get("product_id", "")
        try:
            # VULNERABLE: raw string-concatenated SQL, no parameterization
            # -- and the raw database exception is shown directly to the
            # user as "helpful" debugging output, turning a syntax or
            # type-mismatch error into a data-exfiltration channel.
            query = f"SELECT * FROM a03_secrets WHERE id = {product_id}"
            result = db.session.execute(text(query)).mappings().first()
        except Exception as e:
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/product_lookup.html",
        product_id=product_id,
        result=result,
        error=error,
    )


@a03_bp.route("/inventory-lookup", methods=["GET", "POST"])
def inventory_lookup():
    sku = ""
    count = None
    error = None
    if request.method == "POST":
        sku = request.form.get("sku", "")
        try:
            # VULNERABLE: raw string-concatenated SQL passed to a driver
            # that permits multiple, semicolon-separated statements in
            # one call -- there is no query-count restriction, so an
            # attacker who can inject one statement can inject an
            # unlimited chain of them.
            query = f"SELECT COUNT(*) FROM a03_secrets WHERE id = {sku}"
            count = db.session.execute(text(query)).scalar()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/inventory_lookup.html",
        sku=sku,
        count=count,
        error=error,
    )


@a03_bp.route("/theme-preview", methods=["GET", "POST"])
def theme_preview():
    custom_css = ""
    if request.method == "POST":
        # VULNERABLE: the submitted CSS is rendered verbatim with no
        # sanitization, no disallowed-property filter, and no CSP header
        # anywhere in this app to fall back on.
        custom_css = request.form.get("custom_css", "")
    return render_template(
        "a03_injection/theme_preview.html",
        custom_css=custom_css,
        account_recovery_pin=ACCOUNT_RECOVERY_PIN,
    )


@a03_bp.route("/css-exfil-demo")
def css_exfil_demo():
    leaked = _read_css_exfil_leaks()
    return render_template(
        "a03_injection/css_exfil_demo.html",
        account_recovery_pin=ACCOUNT_RECOVERY_PIN,
        leaked=leaked,
    )


@a03_bp.route("/css-exfil-collector")
def css_exfil_collector():
    # VULNERABLE: accepts and stores whatever "leak" value arrives with
    # zero validation that it corresponds to any real, correct guess and
    # zero authentication -- proving the exfiltration channel itself is
    # wide open, not just one lucky guess.
    leak_value = request.args.get("leak", "")
    if leak_value:
        _append_css_exfil_leak(leak_value)
    return Response(status=204)


@a03_bp.route("/csv-injection")
def csv_injection():
    return render_template("a03_injection/csv_injection.html")


@a03_bp.route("/export-comments-csv")
def export_comments_csv():
    all_comments = Comment.query.order_by(Comment.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Author", "Comment"])
    for c in all_comments:
        # VULNERABLE: no neutralization of leading formula characters
        # (=, +, -, @) before writing user-controlled fields into the CSV --
        # a spreadsheet application that opens this export treats any cell
        # starting with one of those characters as a formula to evaluate,
        # not as literal text.
        writer.writerow([c.author, c.body])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=comments_export.csv"},
    )


@a03_bp.route("/export-archive", methods=["GET", "POST"])
def export_archive():
    filename = ""
    output = None
    error = None
    proof = None
    if request.method == "POST":
        filename = request.form.get("filename", "")
        os.makedirs(ARCHIVE_EXPORT_DIR, exist_ok=True)
        sample_path = os.path.join(ARCHIVE_EXPORT_DIR, "notes.txt")
        with open(sample_path, "w") as f:
            f.write("export placeholder\n")
        archive_path = os.path.join(ARCHIVE_EXPORT_DIR, "export.tar")
        try:
            # VULNERABLE: shell=False and the list-argument form genuinely
            # block every shell-metacharacter technique this lab's other
            # command-injection examples rely on -- but `filename` is still
            # passed straight through as a single, unvalidated argv element.
            # GNU tar treats any value starting with "--" as a long option,
            # not a filename, no matter how it arrived in argv. "notes.txt"
            # is included as a second, fixed operand so tar always has a
            # real archive member to work with -- without it, a malicious
            # `filename` alone leaves tar with zero real members and it
            # refuses to create an "empty archive" before ever spawning the
            # injected compress-program, masking the vulnerability entirely.
            result = subprocess.run(
                ["tar", "-cf", archive_path, "notes.txt", filename],
                shell=False,
                cwd=ARCHIVE_EXPORT_DIR,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
        except Exception as e:
            error = str(e)
        if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
            with open(ARGUMENT_INJECTION_PROOF_PATH) as f:
                proof = f.read()
    return render_template(
        "a03_injection/export_archive.html",
        filename=filename,
        output=output,
        error=error,
        proof=proof,
    )
