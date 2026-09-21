import os

from app import BASE_DIR


def test_comment_preview_page_renders(client):
    response = client.get("/a06/comment-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "comment-preview" in body
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body


def test_comment_preview_wires_up_the_vulnerable_html_call(client):
    response = client.get("/a06/comment-preview")
    body = response.data.decode()
    # The live wiring script must load the vendored 1.12.4 file (not a
    # patched/newer copy) and must call the vulnerable .html() on raw
    # input -- .text() would not be exploitable.
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body
    assert "$('#comment-preview').html(raw)" in body
    assert "jquery-vulnerable/jquery-3" not in body


def test_vendored_jquery_file_is_the_real_vulnerable_release():
    path = os.path.join(BASE_DIR, "static", "vendor", "jquery-vulnerable", "jquery-1.12.4.js")
    with open(path, encoding="utf-8") as f:
        header = f.read(200)
    assert "jQuery JavaScript Library v1.12.4" in header
