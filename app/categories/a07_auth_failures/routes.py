import secrets
import unicodedata

from flask import jsonify, make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.categories.a07_auth_failures import a07_bp
from app.categories.a07_auth_failures.models import A07Account
from app.categories.a07_auth_failures.session_store import SID_COOKIE, get_or_create_session
from app.extensions import db


def _render(template_name, session_row, **context):
    resp = make_response(render_template(template_name, session_row=session_row, **context))
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


def _redirect(endpoint, session_row, **kwargs):
    resp = make_response(redirect(url_for(endpoint, **kwargs)))
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


@a07_bp.route("/")
def overview():
    return render_template("a07_auth_failures/overview.html")


@a07_bp.route("/account")
def account():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/account.html", session_row)


@a07_bp.route("/customer-login", methods=["GET", "POST"])
def brute_force_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        # VULNERABLE: no rate limiting, no lockout, no delay -- unlimited
        # login attempts against any username, forever.
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            db.session.commit()
            return _redirect("a07_auth_failures.account", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/brute_force_login.html", session_row, error=error)


@a07_bp.route("/loyalty-portal-login", methods=["GET", "POST"])
def credential_stuffing():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        # VULNERABLE: the exact same unprotected check as customer-login,
        # reused against a different set of seeded accounts -- proving
        # the missing protection isn't specific to one login form.
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            db.session.commit()
            return _redirect("a07_auth_failures.account", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/credential_stuffing.html", session_row, error=error)


@a07_bp.route("/share-session-link")
def share_session_link():
    session_row = get_or_create_session()
    share_url = url_for("a07_auth_failures.account", sid=session_row.id)
    return _render("a07_auth_failures/session_in_url.html", session_row, share_url=share_url)


@a07_bp.route("/logout", methods=["POST"])
def logout():
    # VULNERABLE: only clears the CLIENT's cookie -- the server-side
    # AuthSession row is never deleted, so a separately-held copy of the
    # old id keeps working indefinitely.
    resp = make_response(redirect(url_for("a07_auth_failures.session_survives_logout")))
    resp.set_cookie(SID_COOKIE, "", expires=0)
    return resp


@a07_bp.route("/session-survives-logout")
def session_survives_logout():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/session_survives_logout.html", session_row)


@a07_bp.route("/session-fixation-demo")
def session_fixation_demo():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/session_fixation.html", session_row)


MFA_DEMO_CODE = "482913"


@a07_bp.route("/mfa-login", methods=["GET", "POST"])
def mfa_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login.html", session_row, error=error)


@a07_bp.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        if code == MFA_DEMO_CODE:
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_verify.html", session_row, error=error, demo_code=MFA_DEMO_CODE)


@a07_bp.route("/mfa-dashboard")
def mfa_dashboard():
    session_row = get_or_create_session()
    if not session_row.username:
        return _redirect("a07_auth_failures.mfa_login", session_row)
    # VULNERABLE: only checks that a username is set on the session --
    # never checks session_row.mfa_verified, so step 2 (the code) can be
    # skipped entirely and this destination reached right after step 1.
    return _render("a07_auth_failures/mfa_dashboard.html", session_row)


@a07_bp.route("/register", methods=["GET", "POST"])
def register():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if A07Account.query.filter_by(username=username).first() is not None:
            error = "That username is already taken."
        else:
            # VULNERABLE: stores the username exactly as submitted, with no
            # whitespace stripping or normalization -- "admin" and "admin "
            # are treated as two entirely distinct accounts here.
            account_row = A07Account(
                username=username, password_hash=generate_password_hash(password, method="pbkdf2:sha256")
            )
            db.session.add(account_row)
            db.session.commit()
            session_row.username = username
            db.session.commit()
            return _redirect("a07_auth_failures.forgot_password_self", session_row)
    return _render("a07_auth_failures/register.html", session_row, error=error)


@a07_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_self():
    session_row = get_or_create_session()
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        # VULNERABLE: strips whitespace when looking up which account to
        # reset, but registration stored the username with no such
        # normalization -- if another account exists whose username
        # exactly equals yours after stripping, THAT account gets reset
        # instead of the one you actually registered.
        target_username = (session_row.username or "").strip()
        target = A07Account.query.filter_by(username=target_username).first()
        if target is None:
            error = "No matching account found."
        else:
            target.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            db.session.commit()
            success = True
    return _render(
        "a07_auth_failures/forgot_password_self.html", session_row, error=error, success=success
    )


def _normalize_username(value):
    return unicodedata.normalize("NFKC", value).casefold()


@a07_bp.route("/account-lookup", methods=["GET", "POST"])
def account_lookup():
    session_row = get_or_create_session()
    error = None
    matched_username = None
    if request.method == "POST":
        query_username = request.form.get("username", "")
        normalized_query = _normalize_username(query_username)
        # VULNERABLE: treats any two usernames that normalize to the same
        # string as the SAME account for recovery purposes -- a Unicode
        # lookalike character that NFKC-normalizes to an ASCII letter
        # collides with a completely different, real ASCII-only account.
        for account_row in A07Account.query.all():
            if _normalize_username(account_row.username) == normalized_query:
                matched_username = account_row.username
                session_row.username = account_row.username
                db.session.commit()
                break
        if matched_username is None:
            error = "No account found."
    return _render(
        "a07_auth_failures/account_lookup.html",
        session_row,
        error=error,
        matched_username=matched_username,
    )


@a07_bp.route("/mfa-forgot-password", methods=["GET", "POST"])
def mfa_forgot_password():
    session_row = get_or_create_session()
    error = None
    success = False
    if request.method == "POST":
        username = request.form.get("username", "")
        new_password = request.form.get("new_password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row is None:
            error = "No account with that username."
        else:
            account_row.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            session_row.username = account_row.username
            # VULNERABLE: completing a password reset marks this session as
            # already MFA-verified -- the code-entry step (the actual
            # second factor) is never required at all after a reset,
            # silently disabling MFA protection for the account.
            session_row.mfa_verified = True
            db.session.commit()
            success = True
    return _render(
        "a07_auth_failures/mfa_forgot_password.html", session_row, error=error, success=success
    )


@a07_bp.route("/mfa-leaked-code/login", methods=["GET", "POST"])
def mfa_leaked_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            session_row.pending_mfa_code = f"{secrets.randbelow(1_000_000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_leaked_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_leaked_login.html", session_row, error=error)


@a07_bp.route("/mfa-leaked-code/api/send-code", methods=["POST"])
def mfa_leaked_send_code_api():
    session_row = get_or_create_session()
    # VULNERABLE: this API exists to trigger sending the code via a real
    # SMS/email provider server-side -- but a leftover debug field echoes
    # the real code straight back in the JSON response. Any client that can
    # call this endpoint (no proof of phone/email ownership required at
    # all, just an in-progress session) gets the code directly, with no
    # need to intercept an SMS or email at all.
    resp = jsonify({"status": "sent", "debug_code": session_row.pending_mfa_code})
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


@a07_bp.route("/mfa-leaked-code/verify", methods=["GET", "POST"])
def mfa_leaked_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        if code and code == session_row.pending_mfa_code:
            session_row.mfa_verified = True
            session_row.pending_mfa_code = None
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_leaked_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_leaked_verify.html", session_row, error=error)


@a07_bp.route("/mfa-leaked-code/dashboard")
def mfa_leaked_dashboard():
    session_row = get_or_create_session()
    if not session_row.username or not session_row.mfa_verified:
        return _redirect("a07_auth_failures.mfa_leaked_login", session_row)
    return _render("a07_auth_failures/mfa_leaked_dashboard.html", session_row)


@a07_bp.route("/mfa-reusable-code/login", methods=["GET", "POST"])
def mfa_reusable_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            session_row.pending_mfa_code = f"{secrets.randbelow(1_000_000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_reusable_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_reusable_login.html", session_row, error=error)


@a07_bp.route("/mfa-reusable-code/verify", methods=["GET", "POST"])
def mfa_reusable_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        # VULNERABLE: checks the code but never invalidates it afterward --
        # pending_mfa_code is left in place even after a successful
        # verification, so the exact same code keeps working for every
        # future verification attempt on this session, indefinitely.
        if code and code == session_row.pending_mfa_code:
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_reusable_dashboard", session_row)
        error = "Incorrect code."
    return _render(
        "a07_auth_failures/mfa_reusable_verify.html",
        session_row,
        error=error,
        demo_code=session_row.pending_mfa_code,
    )


@a07_bp.route("/mfa-reusable-code/dashboard")
def mfa_reusable_dashboard():
    session_row = get_or_create_session()
    if not session_row.username or not session_row.mfa_verified:
        return _redirect("a07_auth_failures.mfa_reusable_login", session_row)
    return _render("a07_auth_failures/mfa_reusable_dashboard.html", session_row)
