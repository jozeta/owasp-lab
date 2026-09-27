def test_feedback_page_renders(client):
    response = client.get("/a03/feedback")
    assert response.status_code == 200


def test_literal_script_tag_is_blocked(client):
    payload = "<script>alert(1)</script>"
    response = client.post("/a03/feedback", data={"feedback": payload})
    assert response.status_code == 200
    assert b"Blocked" in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_fullwidth_lookalike_bypasses_filter_and_normalizes_to_real_script_tag(client):
    payload = "＜script＞alert(document.domain)＜/script＞"
    response = client.post("/a03/feedback", data={"feedback": payload})
    assert response.status_code == 200
    assert b"Blocked" not in response.data
    assert b"<script>alert(document.domain)</script>" in response.data
