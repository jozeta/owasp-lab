from flask import render_template, request

from app.categories.a02_crypto_failures import a02_bp
from app.categories.a02_crypto_failures.crypto import decrypt_ecb, encrypt_ecb
from app.categories.a02_crypto_failures.models import LegacyCredential

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
