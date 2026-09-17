from flask import render_template

from app.categories.a01_access_control import a01_bp


@a01_bp.route("/")
def overview():
    return render_template("a01_access_control/overview.html")
