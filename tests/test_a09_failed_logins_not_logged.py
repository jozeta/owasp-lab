def test_successful_login_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/login", data={"username": "demo", "password": "demo-password"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "user_login_success"


def test_failed_logins_are_never_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    for _ in range(10):
        response = client.post(
            "/a09/login", data={"username": "demo", "password": "wrong-password"}
        )
        assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_security_events_page_renders_with_empty_alerts_panel(client):
    response = client.get("/a09/security-events")
    assert response.status_code == 200
    assert b"Active Alerts (0)" in response.data


def test_failed_logins_not_logged_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Failed Login Attempts Never Logged" in response.data
    assert b'href="/a09/login"' in response.data
