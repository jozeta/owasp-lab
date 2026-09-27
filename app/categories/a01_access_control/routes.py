import os
import secrets

from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash

from app import BASE_DIR
from app.categories.a01_access_control import a01_bp
from app.core.auth import get_current_user
from app.core.models import User
from app.extensions import db


DOCUMENTS_DIR = os.path.join(BASE_DIR, "instance", "a01_documents")


def _ensure_seed_document():
    os.makedirs(DOCUMENTS_DIR, exist_ok=True)
    welcome_path = os.path.join(DOCUMENTS_DIR, "welcome.txt")
    if not os.path.exists(welcome_path):
        with open(welcome_path, "w") as f:
            f.write("Welcome to the OWASP Lab document center!\n")


@a01_bp.route("/")
def overview():
    return render_template("a01_access_control/overview.html")


@a01_bp.route("/profile")
@a01_bp.route("/profile/<int:user_id>")
def idor(user_id=1):
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    profile = db.get_or_404(User, user_id)
    return render_template("a01_access_control/idor.html", profile=profile, viewer=viewer)


@a01_bp.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if request.method == "POST":
        target = db.get_or_404(User, int(request.form["user_id"]))
        target.role = request.form["role"]
        db.session.commit()
    users = User.query.order_by(User.username).all()
    return render_template("a01_access_control/admin_users.html", users=users, viewer=viewer)


@a01_bp.route("/account/update", methods=["GET", "POST"])
def account_update():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if request.method == "POST":
        for key, value in request.form.items():
            if key == "id":
                continue
            setattr(viewer, key, value)
        db.session.commit()
        flash("Account updated.")
        return redirect(url_for("a01_access_control.account_update"))
    return render_template("a01_access_control/account_update.html", viewer=viewer)


@a01_bp.route("/change-email", methods=["GET", "POST"])
def change_email():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    changed = False
    if request.method == "POST":
        # VULNERABLE: no CSRF token, no confirmation of the current
        # email/password -- any POST that arrives carrying the victim's
        # session cookie succeeds, including one triggered by an
        # auto-submitting form on an attacker's own page.
        viewer.email = request.form.get("new_email", "")
        db.session.commit()
        changed = True
    return render_template("a01_access_control/change_email.html", viewer=viewer, changed=changed)


@a01_bp.route("/api/password-change", methods=["GET", "POST"])
def password_change_api():
    if request.method == "GET":
        return render_template("a01_access_control/password_change_api.html")
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    new_password = data.get("new_password", "")
    # VULNERABLE: trusts the client-supplied "email" field to pick which
    # account to update -- no session, no ownership check, no
    # confirmation that the caller is the account holder at all.
    target = User.query.filter_by(email=email).first()
    if target is None:
        return jsonify({"error": "No account with that email."}), 404
    target.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
    db.session.commit()
    return jsonify({"status": "password updated"})


@a01_bp.route("/change-display-name", methods=["GET", "POST"])
def change_display_name():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if "a01_csrf_token" not in session:
        session["a01_csrf_token"] = secrets.token_hex(16)
    changed = False
    if request.method == "POST":
        # VULNERABLE: a CSRF token IS required to be present in the
        # submitted form, but its VALUE is never compared against the
        # real per-session token stored above -- any non-empty string
        # satisfies this check, including one an attacker's cross-site
        # page could never actually know.
        submitted_token = request.form.get("csrf_token", "")
        if submitted_token:
            viewer.display_name = request.form.get("display_name", "")
            db.session.commit()
            changed = True
    return render_template(
        "a01_access_control/change_display_name.html",
        viewer=viewer,
        changed=changed,
        csrf_token=session["a01_csrf_token"],
    )


@a01_bp.route("/download-document")
def download_document():
    _ensure_seed_document()
    name = request.args.get("name", "welcome.txt")
    content = None
    error = None
    # VULNERABLE: os.path.join() silently discards DOCUMENTS_DIR entirely
    # if `name` is an absolute path, and a relative "../../../" climbs
    # straight out of this directory just as easily -- there is no
    # check of any kind on `name` here.
    path = os.path.join(DOCUMENTS_DIR, name)
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        error = str(e)
    return render_template(
        "a01_access_control/download_document.html", name=name, content=content, error=error
    )


@a01_bp.route("/download-document-filtered")
def download_document_filtered():
    _ensure_seed_document()
    name = request.args.get("name", "welcome.txt")
    content = None
    error = None
    blocked = ".." in name
    if not blocked:
        # VULNERABLE: this filter only ever checks for the substring
        # "..", never considering that os.path.join() discards
        # DOCUMENTS_DIR entirely when `name` is an absolute path -- an
        # absolute path contains no ".." at all and sails straight
        # through this check.
        path = os.path.join(DOCUMENTS_DIR, name)
        try:
            with open(path) as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template(
        "a01_access_control/download_document_filtered.html",
        name=name,
        content=content,
        error=error,
        blocked=blocked,
    )


@a01_bp.route("/lookup-account", methods=["GET", "POST"])
def lookup_account():
    username = ""
    results = []
    if request.method == "POST":
        username = request.form.get("username", "")
        # VULNERABLE: uses SQL LIKE-style pattern matching instead of an
        # exact equality check -- a bare wildcard character matches
        # every row in the table, not just the one account the caller
        # claims to be looking up.
        results = User.query.filter(User.username.like(username)).all()
    return render_template(
        "a01_access_control/lookup_account.html", username=username, results=results
    )


@a01_bp.route("/continue")
def continue_redirect():
    next_url = request.args.get("next")
    if next_url is None:
        return render_template("a01_access_control/continue_redirect.html")
    # VULNERABLE: redirects to any URL at all, with zero validation --
    # Flask's redirect() sends whatever string it's given as the
    # Location header, external URLs included.
    return redirect(next_url)


@a01_bp.route("/continue-filtered")
def continue_redirect_filtered():
    next_url = request.args.get("next")
    if next_url is None:
        return render_template("a01_access_control/continue_redirect_filtered.html")
    # VULNERABLE: only checks whether the trusted hostname appears
    # ANYWHERE in the string, never that it's genuinely the URL's host --
    # a URL whose real host is entirely different can still contain this
    # substring, e.g. as part of a longer, attacker-controlled subdomain.
    if "trusted-partner.example" in next_url:
        return redirect(next_url)
    return "Invalid redirect target", 400


@a01_bp.route("/update-preferences", methods=["GET", "POST"])
def update_preferences():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    updated = False
    if request.method == "POST":
        # VULNERABLE: the authorization check below reads only the
        # FIRST occurrence of a duplicated "role" field
        # (request.form.get()'s documented behavior for repeated keys),
        # but the actual write a few lines later deliberately reads the
        # LAST occurrence instead (request.form.getlist()[-1]) -- a
        # "let a later resubmitted field override an earlier one"
        # convention meant for a legitimate multi-step form. An
        # attacker who submits role=user&role=admin passes the check
        # (which only ever sees "user") while the write applies "admin".
        submitted_role = request.form.get("role", "user")
        if submitted_role not in ("user", "premium"):
            abort(403)
        viewer.role = request.form.getlist("role")[-1]
        db.session.commit()
        updated = True
    return render_template(
        "a01_access_control/update_preferences.html", viewer=viewer, updated=updated
    )
