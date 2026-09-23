def test_forgot_password_page_renders(client):
    response = client.get("/a04/forgot-password")
    assert response.status_code == 200
    assert b"Password Reset Poisoning" in response.data


def test_forgot_password_uses_request_host_unvalidated(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "attacker.evil.test"},
    )
    assert response.status_code == 200
    assert b"http://attacker.evil.test/a04/reset-password-confirm" in response.data


def test_forgot_password_honors_x_forwarded_host_over_host(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "real-app.local", "X-Forwarded-Host": "attacker.evil.test"},
    )
    assert response.status_code == 200
    assert b"http://attacker.evil.test/a04/reset-password-confirm" in response.data


def test_forgot_password_uses_real_host_when_nothing_forged(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "127.0.0.1:5001"},
    )
    assert response.status_code == 200
    assert b"http://127.0.0.1:5001/a04/reset-password-confirm" in response.data
