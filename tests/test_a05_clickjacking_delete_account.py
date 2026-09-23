def test_delete_account_page_renders(client):
    response = client.get("/a05/delete-account")
    assert response.status_code == 200
    assert b"Delete my account" in response.data


def test_delete_account_page_has_no_frame_protection(client):
    response = client.get("/a05/delete-account")
    assert "X-Frame-Options" not in response.headers
    csp = response.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors" not in csp


def test_delete_account_post_deletes_immediately(client):
    response = client.post("/a05/delete-account")
    assert response.status_code == 200
    assert b"Account deleted" in response.data


def test_clickjack_demo_embeds_real_delete_page_in_iframe(client):
    response = client.get("/a05/delete-account-clickjack-demo")
    assert response.status_code == 200
    assert b"<iframe" in response.data
    assert b"/a05/delete-account" in response.data
