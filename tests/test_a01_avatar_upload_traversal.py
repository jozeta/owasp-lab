import io
import os

from app import BASE_DIR
from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        seed_database(app)
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_avatar_upload_traversal_writes_outside_avatars_dir(app, client):
    _login_as(client, app, "alice")
    # Ensure a01_documents/ already exists on disk before the exploit
    # tries to write into it via traversal (mirrors _ensure_seed_document()
    # already running once via a normal document-center visit).
    client.get("/a01/download-document")

    malicious_content = b"OVERWRITTEN BY AVATAR UPLOAD TRAVERSAL\n"
    data = {
        "avatar": (io.BytesIO(malicious_content), "../a01_documents/pwned_by_avatar_upload.txt"),
    }
    response = client.post("/a01/avatar-upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 200

    # Prove the write landed in a01_documents/, NOT a01_avatars/, using
    # this app's own EXISTING, unrelated document-download feature.
    proof_response = client.get("/a01/download-document?name=pwned_by_avatar_upload.txt")
    assert proof_response.status_code == 200
    assert malicious_content.decode() in proof_response.data.decode()

    documents_dir = os.path.join(BASE_DIR, "instance", "a01_documents")
    avatars_dir = os.path.join(BASE_DIR, "instance", "a01_avatars")
    assert os.path.exists(os.path.join(documents_dir, "pwned_by_avatar_upload.txt"))
    assert not os.path.exists(os.path.join(avatars_dir, "pwned_by_avatar_upload.txt"))


def test_avatar_upload_normal_filename_saves_inside_avatars_dir(app, client):
    _login_as(client, app, "bob")
    data = {"avatar": (io.BytesIO(b"fake image bytes"), "myavatar.png")}
    response = client.post("/a01/avatar-upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"myavatar.png" in response.data

    avatars_dir = os.path.join(BASE_DIR, "instance", "a01_avatars")
    assert os.path.exists(os.path.join(avatars_dir, "myavatar.png"))
