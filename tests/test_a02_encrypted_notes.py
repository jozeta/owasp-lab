from app.core.seed import seed_database


def test_encrypted_notes_shows_identical_ciphertext_for_shared_answer(app, client):
    seed_database(app)

    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200

    from app.categories.a02_crypto_failures.crypto import encrypt_ecb

    shared_ciphertext = encrypt_ecb("Rex")
    assert response.data.count(shared_ciphertext.encode()) == 2


def test_encrypted_notes_decrypt_tool_recovers_plaintext(client):
    from app.categories.a02_crypto_failures.crypto import encrypt_ecb

    ciphertext_hex = encrypt_ecb("Rex")

    response = client.post("/a02/encrypted-notes", data={"ciphertext_hex": ciphertext_hex})
    assert response.status_code == 200
    assert b"Rex" in response.data


def test_encrypted_notes_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Weak Encryption (ECB Mode)" in response.data
    assert b'href="/a02/encrypted-notes"' in response.data


def test_encrypted_notes_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    from app.categories.a02_crypto_failures.crypto import encrypt_ecb

    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data
    shared_ciphertext = encrypt_ecb("Rex")
    assert response.data.count(shared_ciphertext.encode()) == 2

    ciphertext_hex = encrypt_ecb("Rex")
    post_response = client.post("/a02/encrypted-notes", data={"ciphertext_hex": ciphertext_hex})
    assert post_response.status_code == 200
    assert b"Rex" in post_response.data


def test_encrypted_notes_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"MODE_GCM" in response.data


def test_encrypted_notes_shows_detect_content(client):
    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200
    assert b"any two identical values" in response.data
