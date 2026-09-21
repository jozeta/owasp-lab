from flask import make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

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
    session_row = get_or_create_session()
    session_row.username = None
    db.session.commit()
    return _redirect("a07_auth_failures.account", session_row)
