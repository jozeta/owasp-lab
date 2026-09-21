import base64
import pickle

from flask import make_response, redirect, render_template, request, url_for

from app.categories.a08_integrity_failures import a08_bp
from app.categories.a08_integrity_failures.models import RceProof
from app.extensions import db

CART_COOKIE = "a08_cart"
DEFAULT_CART = {"item": "Widget", "price": 49.99}


def write_rce_proof(message):
    # This is the "arbitrary code" a malicious payload can run when it
    # executes -- deliberately safe and contained: it writes a database
    # row, not a shell command or subprocess. DB-backed so the proof is
    # visible regardless of which gunicorn worker handles a later request.
    db.session.add(RceProof(message=message))
    db.session.commit()
    return "proof-written"


def serialize_cart(cart):
    return base64.b64encode(pickle.dumps(cart)).decode()


def deserialize_cart(token):
    # VULNERABLE: no HMAC/signature check at all -- the app trusts
    # whatever pickle bytes the client sends back.
    return pickle.loads(base64.b64decode(token))


@a08_bp.route("/")
def overview():
    return render_template("a08_integrity_failures/overview.html")


@a08_bp.route("/cart", methods=["GET", "POST"])
def cart():
    if request.method == "POST":
        resp = make_response(redirect(url_for("a08_integrity_failures.cart")))
        resp.set_cookie(CART_COOKIE, serialize_cart(dict(DEFAULT_CART)))
        return resp

    token = request.cookies.get(CART_COOKIE)
    error = None
    cart_data = None
    if token:
        try:
            cart_data = deserialize_cart(token)
            if not isinstance(cart_data, dict) or "item" not in cart_data:
                error = "Cart data was corrupted -- resetting to default."
                cart_data = None
        except Exception as e:
            error = f"Could not read cart cookie: {e}"
    if cart_data is None:
        cart_data = dict(DEFAULT_CART)

    resp = make_response(
        render_template("a08_integrity_failures/cart.html", cart=cart_data, error=error)
    )
    resp.set_cookie(CART_COOKIE, serialize_cart(cart_data))
    return resp
