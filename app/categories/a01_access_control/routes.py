import secrets

from flask import flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash

from app.categories.a01_access_control import a01_bp
from app.core.auth import get_current_user
from app.core.models import User
from app.extensions import db


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
