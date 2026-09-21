import json


def test_preferences_page_renders_with_defaults(client):
    response = client.get("/a08/preferences")
    assert response.status_code == 200
    assert b"theme = light" in response.data


def test_preferences_set_legitimately_round_trip(client):
    client.post("/a08/preferences", data={"theme": "dark"})
    response = client.get("/a08/preferences")
    assert b"theme = dark" in response.data
    assert b"Premium: No" in response.data


def test_preferences_honors_tampered_flag_with_invalid_signature(client):
    tampered = json.dumps(
        {"theme": "dark", "premium_unlocked": True, "sig": "not-a-real-signature"}
    )
    client.set_cookie("a08_prefs", tampered, domain="localhost")
    response = client.get("/a08/preferences")
    assert response.status_code == 200
    assert b"Premium: Yes" in response.data


def test_unchecked_signature_cookie_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unchecked Signature on Preferences Cookie" in response.data
    assert b'href="/a08/preferences"' in response.data
