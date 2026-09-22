def test_create_user_action_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/admin-actions", data={"action": "create", "username": "carol"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "admin_user_created"
    assert "carol" in latest.detail


def test_delete_user_action_is_never_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    client.post("/a09/admin-actions", data={"action": "create", "username": "carol"})

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/admin-actions", data={"action": "delete", "username": "carol"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_admin_action_no_audit_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"High-Value Admin Action With No Audit Trail" in response.data
    assert b'href="/a09/admin-actions"' in response.data
