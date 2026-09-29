from flask import url_for

from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def _safe_test_example():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def test_anonymous_progress_toggle_works_directly(app, client):
    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.completed_at is not None


def test_anonymous_hint_reveal_works_directly(app, client):
    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/hints/reveal", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.hints_used == 1


def test_progress_completed_as_one_identity_is_visible_as_another(app, client):
    seed_database(app)
    example = _safe_test_example()
    examples = [e for category in CATEGORIES for e in category.examples]

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    response = client.get("/")
    body = response.data.decode()
    assert f"1<small>/{len(examples)}</small>" in body


def test_completing_the_example_as_different_identities_toggles_the_same_row(app, client):
    seed_database(app)
    example = _safe_test_example()

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.count() == 1
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.completed_at is None
