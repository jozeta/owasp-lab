from flask import render_template

from app.categories.a02_crypto_failures import a02_bp
from app.categories.a02_crypto_failures.models import LegacyCredential


@a02_bp.route("/")
def overview():
    return render_template("a02_crypto_failures/overview.html")


@a02_bp.route("/credential-dump")
def credential_dump():
    credentials = LegacyCredential.query.order_by(LegacyCredential.username).all()
    return render_template("a02_crypto_failures/credential_dump.html", credentials=credentials)
