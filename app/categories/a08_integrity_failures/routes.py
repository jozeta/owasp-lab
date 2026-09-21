import base64
import hashlib
import hmac
import json
import pickle
import urllib.error
import urllib.request

from flask import make_response, redirect, render_template, request, url_for, Response

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


OFFICIAL_PLUGIN_SOURCE = (
    "# Official Widget Theme Plugin v1.0\n"
    'PLUGIN_NAME = "Widget Theme"\n'
    'PLUGIN_VERSION = "1.0"\n'
)

MALICIOUS_PLUGIN_SOURCE = (
    "# \"Widget Theme\" -- served from a compromised mirror\n"
    'PLUGIN_NAME = "Widget Theme"\n'
    'PLUGIN_VERSION = "1.0"\n'
    'write_rce_proof("PWNED-VIA-UNSIGNED-PLUGIN-INSTALL")\n'
)


@a08_bp.route("/plugin-marketplace", methods=["GET", "POST"])
def plugin_marketplace():
    installed_content = None
    error = None
    plugin_url = ""
    if request.method == "POST":
        plugin_url = request.form.get("plugin_url", "")
        try:
            with urllib.request.urlopen(plugin_url, timeout=5) as resp:
                source = resp.read().decode("utf-8", errors="replace")
            installed_content = source
            # VULNERABLE: "installing" a plugin means running its source
            # immediately, with no checksum/signature check against any
            # known-good/trusted-source registry -- any URL's content is
            # trusted equally.
            exec(source, {"__builtins__": __builtins__, "write_rce_proof": write_rce_proof})
        except Exception as e:
            error = f"Could not install plugin: {e}"
    return render_template(
        "a08_integrity_failures/plugin_marketplace.html",
        installed_content=installed_content,
        error=error,
        plugin_url=plugin_url,
    )


@a08_bp.route("/plugin-marketplace/official-plugin.py")
def official_plugin_download():
    return Response(OFFICIAL_PLUGIN_SOURCE, mimetype="text/x-python")


@a08_bp.route("/plugin-marketplace/malicious-plugin-demo.py")
def malicious_plugin_demo_download():
    return Response(MALICIOUS_PLUGIN_SOURCE, mimetype="text/x-python")


PREFS_COOKIE = "a08_prefs"
PREFS_SECRET = "prefs-signing-key-2026"


def _sign_prefs(data):
    payload = json.dumps(data, sort_keys=True).encode()
    return hmac.new(PREFS_SECRET.encode(), payload, hashlib.sha256).hexdigest()


def _verify_prefs_signature(data, sig):
    # This check exists in the codebase -- it's just never actually
    # called anywhere. A realistic "we meant to verify this" bug.
    expected = _sign_prefs(data)
    return hmac.compare_digest(expected, sig)


@a08_bp.route("/preferences", methods=["GET", "POST"])
def preferences():
    if request.method == "POST":
        prefs = {
            "theme": request.form.get("theme", "light"),
            "premium_unlocked": False,
        }
        sig = _sign_prefs(prefs)
        cookie_value = json.dumps({**prefs, "sig": sig})
        resp = make_response(redirect(url_for("a08_integrity_failures.preferences")))
        resp.set_cookie(PREFS_COOKIE, cookie_value)
        return resp

    raw = request.cookies.get(PREFS_COOKIE)
    prefs = {"theme": "light", "premium_unlocked": False}
    if raw:
        try:
            parsed = json.loads(raw)
            # VULNERABLE: _verify_prefs_signature() is never called here --
            # the "sig" field is parsed out and ignored, and every other
            # field is trusted directly.
            prefs = {
                "theme": parsed.get("theme", "light"),
                "premium_unlocked": parsed.get("premium_unlocked", False),
            }
        except Exception:
            pass
    return render_template("a08_integrity_failures/preferences.html", prefs=prefs)
