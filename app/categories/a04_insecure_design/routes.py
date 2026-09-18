from flask import render_template

from app.categories.a04_insecure_design import a04_bp


@a04_bp.route("/")
def overview():
    return render_template("a04_insecure_design/overview.html")
