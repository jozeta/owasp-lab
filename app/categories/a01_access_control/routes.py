from flask import flash, redirect, render_template, request, url_for

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
