import hashlib

from flask import render_template, request

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
