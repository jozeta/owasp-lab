from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database


def _safe_test_example():
    # Same rationale as tests/test_progress.py's helper: sqli-login has no
    # login/session requirement of its own to VIEW, unlike CATEGORIES[0]'s
    # first example.
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_anonymous_progress_toggle_redirects_to_switch_user(app, client):
    seed_database(app)
    example = _safe_test_example()
    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_anonymous_hint_reveal_redirects_to_switch_user(app, client):
    seed_database(app)
    example = _safe_test_example()
    response = client.post("/hints/reveal", data={"example_id": example.id})
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_two_users_progress_on_the_same_example_is_isolated(app, client):
    seed_database(app)
    example = _safe_test_example()
    examples = [e for category in CATEGORIES for e in category.examples]

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    response = client.get("/")
    body = response.data.decode()
    # Same text format as test_progress.py's
    # test_home_page_shows_zero_percent_when_nothing_completed: bob's own
    # progress is untouched by alice's completion above.
    assert f"0 of {len(examples)} completed — 0%" in body

    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
        bob_id = User.query.filter_by(username="bob").first().id
        alice_progress = ExampleProgress.query.filter_by(
            user_id=alice_id, example_id=example.id
        ).first()
        bob_progress = ExampleProgress.query.filter_by(
            user_id=bob_id, example_id=example.id
        ).first()
        assert alice_progress is not None
        assert alice_progress.completed_at is not None
        assert bob_progress is None


def test_bob_completing_the_example_does_not_affect_alice(app, client):
    seed_database(app)
    example = _safe_test_example()

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
        bob_id = User.query.filter_by(username="bob").first().id
        alice_progress = ExampleProgress.query.filter_by(
            user_id=alice_id, example_id=example.id
        ).first()
        bob_progress = ExampleProgress.query.filter_by(
            user_id=bob_id, example_id=example.id
        ).first()
        assert alice_progress.completed_at is not None
        assert bob_progress.completed_at is not None
