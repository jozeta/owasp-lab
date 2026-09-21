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


class _EvilCartPayload:
    def __reduce__(self):
        # __reduce__ tells pickle "to reconstruct me, call this function
        # with these args" -- pickle calls it during LOADING, which is
        # what makes this genuine remote code execution, not just data
        # tampering.
        return (write_rce_proof, ("PWNED-VIA-PICKLE-RCE",))


@a08_bp.route("/cart-rce-demo")
def cart_rce_demo():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    malicious_cookie_value = serialize_cart(_EvilCartPayload())
    resp = make_response(
        render_template(
            "a08_integrity_failures/cart_rce_demo.html",
            proofs=proofs,
            malicious_cookie_value=malicious_cookie_value,
        )
    )
    # Plant the malicious payload as this browser's cart cookie -- visiting
    # /a08/cart next is what actually triggers pickle.loads() on it.
    resp.set_cookie(CART_COOKIE, malicious_cookie_value)
    return resp


@a08_bp.route("/rce-proof")
def rce_proof():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    return render_template("a08_integrity_failures/rce_proof.html", proofs=proofs)


@a08_bp.route("/plugin-marketplace-rce-demo")
def plugin_marketplace_rce_demo():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    return render_template(
        "a08_integrity_failures/plugin_marketplace_rce_demo.html", proofs=proofs
    )


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


JWT_SECRET = "a08-jwt-signing-key-2026"


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s):
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def issue_token(payload, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    header_seg = _b64url_encode(json.dumps(header).encode())
    payload_seg = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_seg}.{payload_seg}".encode()
    if alg == "HS256":
        sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        sig_seg = _b64url_encode(sig)
    else:
        sig_seg = ""
    return f"{header_seg}.{payload_seg}.{sig_seg}"


def verify_token(token):
    # VULNERABLE: reads the algorithm from the token's OWN header instead
    # of pinning to a fixed expected algorithm -- the classic alg
    # confusion / alg:none bug class.
    header_seg, payload_seg, sig_seg = token.split(".")
    header = json.loads(_b64url_decode(header_seg))
    payload = json.loads(_b64url_decode(payload_seg))
    signing_input = f"{header_seg}.{payload_seg}".encode()
    alg = header.get("alg")
    if alg == "HS256":
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_seg) if sig_seg else b""
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("bad signature")
    elif alg == "none":
        pass
    else:
        raise ValueError("unsupported alg")
    return payload


@a08_bp.route("/api-token")
def api_token():
    token = issue_token({"user": "guest", "role": "guest"})
    return render_template("a08_integrity_failures/api_token.html", token=token)


@a08_bp.route("/admin-api", methods=["GET", "POST"])
def admin_api():
    result = None
    error = None
    if request.method == "POST":
        token = request.form.get("token", "")
        try:
            payload = verify_token(token)
            if payload.get("role") == "admin":
                result = f"ADMIN ACCESS GRANTED -- welcome, {payload.get('user')}"
            else:
                error = f"Access denied -- role '{payload.get('role')}' is not admin."
        except Exception as e:
            error = f"Invalid token: {e}"
    return render_template("a08_integrity_failures/admin_api.html", result=result, error=error)
