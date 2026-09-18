from flask import render_template

from app.categories.a02_crypto_failures import a02_bp


@a02_bp.route("/")
def overview():
    return render_template("a02_crypto_failures/overview.html")
