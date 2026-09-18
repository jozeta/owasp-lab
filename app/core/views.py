from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import Settings, User
from app.core.seed import reset_database
from app.extensions import db

core_bp = Blueprint("core", __name__, template_folder="templates")


def _is_safe_redirect_target(target):
    return bool(target) and target.startswith("/") and not target.startswith("//")


@core_bp.route("/")
def home():
    return render_template("core/home.html")


@core_bp.route("/switch-user", methods=["GET", "POST"])
def switch_user():
    if request.method == "POST":
        session["user_id"] = int(request.form["user_id"])
        next_url = request.args.get("next")
        if _is_safe_redirect_target(next_url):
            return redirect(next_url)
        return redirect(url_for("core.home"))
    users = User.query.order_by(User.username).all()
    return render_template("core/switch_user.html", users=users)


@core_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return redirect(url_for("core.home"))


@core_bp.route("/settings", methods=["GET", "POST"])
def settings_page():
    settings = Settings.get()
    if request.method == "POST":
        settings.show_explanations = "show_explanations" in request.form
        settings.show_exploit_instructions = "show_exploit_instructions" in request.form
        db.session.commit()
        flash("Settings updated.")
        return redirect(url_for("core.settings_page"))
    return render_template("core/settings.html", settings=settings)


@core_bp.route("/settings/reset", methods=["POST"])
def reset_lab():
    reset_database(current_app)
    flash("Lab reset to clean state.")
    return redirect(url_for("core.settings_page"))


@core_bp.route("/force-reset")
def force_reset():
    """Safety-net reset reachable by URL alone.

    Deliberately GET, self-contained (no template inheritance), and requires
    no working nav/context processor -- if the app itself is broken and the
    normal Settings page can't be reached, this route still resets the DB
    and clears the session.
    """
    reset_database(current_app)
    session.clear()
    return Response(
        "<!doctype html><title>Lab reset</title>"
        "<p>The lab has been force-reset: the database was restored to its "
        "clean seeded state and your session was cleared.</p>"
        '<p><a href="/">Return to the lab</a></p>',
        mimetype="text/html",
    )


@core_bp.route("/tools")
def tools_page():
    return render_template("core/tools.html")
