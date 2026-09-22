def test_monitored_login_success_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/monitored-login", data={"username": "demo", "password": "demo-password"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "monitored_login_success"


def test_monitored_login_logs_every_failed_attempt(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before_total = SecurityEvent.query.count()
        before_failed = SecurityEvent.query.filter_by(
            event_type="monitored_login_failed"
        ).count()

    for _ in range(20):
        response = client.post(
            "/a09/monitored-login", data={"username": "demo", "password": "wrong"}
        )
        assert response.status_code == 200

    with app.app_context():
        after_total = SecurityEvent.query.count()
        after_failed = SecurityEvent.query.filter_by(
            event_type="monitored_login_failed"
        ).count()

    assert after_total == before_total + 20
    assert after_failed == before_failed + 20


def test_no_alert_appears_no_matter_how_many_failures(client):
    for _ in range(20):
        client.post(
            "/a09/monitored-login", data={"username": "demo", "password": "wrong"}
        )

    response = client.get("/a09/security-events")
    assert response.status_code == 200
    assert b"Active Alerts (0)" in response.data


def test_no_alert_threshold_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"No Alert Threshold for Repeated Failures" in response.data
    assert b'href="/a09/monitored-login"' in response.data
