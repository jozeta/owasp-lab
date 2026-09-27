import hashlib
import random
import time

from flask import jsonify, render_template, request

from app.categories.a02_crypto_failures import a02_bp
from app.categories.a02_crypto_failures.crypto import decrypt_ecb, encrypt_ecb
from app.categories.a02_crypto_failures.models import LegacyCredential
from app.extensions import db

SECURITY_ANSWERS = [
    ("alice", "Rex"),
    ("bob", "Milo"),
    ("carol", "Rex"),
    ("admin", "Shadow"),
]


@a02_bp.route("/")
def overview():
    return render_template("a02_crypto_failures/overview.html")


@a02_bp.route("/credential-dump")
def credential_dump():
    credentials = LegacyCredential.query.order_by(LegacyCredential.username).all()
    return render_template("a02_crypto_failures/credential_dump.html", credentials=credentials)


@a02_bp.route("/encrypted-notes", methods=["GET", "POST"])
def encrypted_notes():
    encrypted_rows = [(username, encrypt_ecb(answer)) for username, answer in SECURITY_ANSWERS]
    decrypted_result = None
    decrypt_error = None
    if request.method == "POST":
        ciphertext_hex = request.form.get("ciphertext_hex", "").strip()
        try:
            decrypted_result = decrypt_ecb(ciphertext_hex)
        except Exception:
            decrypt_error = "Could not decrypt that value — check the hex string."
    return render_template(
        "a02_crypto_failures/encrypted_notes.html",
        encrypted_rows=encrypted_rows,
        decrypted_result=decrypted_result,
        decrypt_error=decrypt_error,
    )


RESET_TOKEN_SALT = "resetSalt2024"


def generate_reset_token(username):
    return hashlib.md5(f"{username}:{RESET_TOKEN_SALT}".encode()).hexdigest()[:10]


@a02_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    submitted = request.method == "POST"
    return render_template("a02_crypto_failures/forgot_password.html", submitted=submitted)


@a02_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        matched_credential = None
        for credential in LegacyCredential.query.all():
            if generate_reset_token(credential.username) == token:
                matched_credential = credential
                break
        if matched_credential is None:
            error = "This reset token is invalid or expired."
        else:
            matched_credential.weak_password_hash = hashlib.md5(new_password.encode()).hexdigest()
            db.session.commit()
            success = True
    return render_template(
        "a02_crypto_failures/reset_password.html", token=token, error=error, success=success
    )


@a02_bp.route("/legacy-login", methods=["GET", "POST"])
def legacy_login():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        credential = LegacyCredential.query.filter_by(username=username).first()
        if credential and hashlib.md5(password.encode()).hexdigest() == credential.weak_password_hash:
            result = "success"
        else:
            result = "failure"
    return render_template("a02_crypto_failures/legacy_login.html", result=result)


@a02_bp.route("/reset-password-referrer", methods=["GET", "POST"])
def reset_password_referrer():
    # A demo token for the seeded "admin" account is used when none is
    # supplied, so this page is directly viewable without first walking
    # through a real "request a reset" step.
    token = request.args.get("token") or generate_reset_token("admin")
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        matched_credential = None
        for credential in LegacyCredential.query.all():
            if generate_reset_token(credential.username) == token:
                matched_credential = credential
                break
        if matched_credential is None:
            error = "This reset token is invalid or expired."
        else:
            matched_credential.weak_password_hash = hashlib.md5(new_password.encode()).hexdigest()
            db.session.commit()
            success = True
    # VULNERABLE: the reset token lives in this page's own URL (query
    # string), and nothing anywhere in this app sets a Referrer-Policy
    # header -- any outbound link on this page (see the "Security Tips"
    # link below) carries the full current URL, token included, to
    # whatever it links to.
    return render_template(
        "a02_crypto_failures/reset_password_referrer.html", token=token, error=error, success=success
    )


@a02_bp.route("/external-referrer-sink")
def external_referrer_sink():
    # Plays the role of a third-party page (an analytics widget, an ad, a
    # "security tips" article -- anything embeddable or linkable) that the
    # reset-password page above links out to. In a real deployment this
    # would live on an attacker-controlled domain, silently logging every
    # visitor's in-flight reset token via the Referer header their browser
    # sends automatically.
    captured_referer = request.headers.get("Referer", "")
    return render_template(
        "a02_crypto_failures/external_referrer_sink.html", captured_referer=captured_referer
    )


@a02_bp.route("/api/forgot-password", methods=["GET", "POST"])
def forgot_password_api():
    if request.method == "GET":
        return render_template("a02_crypto_failures/forgot_password_api.html")
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    credential = LegacyCredential.query.filter_by(username=username).first()
    if credential is None:
        return jsonify({"error": "No account with that username."}), 404
    # VULNERABLE: returns the actual reset token directly in the API
    # response instead of only ever delivering it through a real
    # email/SMS channel -- anyone who can guess or already knows a
    # username gets a working reset token immediately, with no access to
    # that user's inbox required at all.
    token = generate_reset_token(username)
    return jsonify({"status": "ok", "resetToken": token})


@a02_bp.route("/generate-api-key", methods=["GET", "POST"])
def generate_api_key():
    api_key = None
    if request.method == "POST":
        # VULNERABLE: seeds Python's RNG with the current Unix
        # timestamp before generating the key -- anyone who knows (or
        # can narrow down) the second this happened can re-seed with
        # that same integer and reproduce the exact same "random" key.
        # random is a Mersenne Twister: fully deterministic given the
        # same seed. No brute-force over the key space itself is ever
        # needed, only over a small window of candidate timestamps.
        random.seed(int(time.time()))
        api_key = "".join(random.choices("0123456789abcdef", k=32))
    return render_template("a02_crypto_failures/generate_api_key.html", api_key=api_key)
