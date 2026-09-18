from flask import render_template

from app.categories.a03_injection import a03_bp


@a03_bp.route("/")
def overview():
    return render_template("a03_injection/overview.html")
