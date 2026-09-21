from app.core.models import ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _safe_test_example():
    # Deliberately NOT "the first registered example" -- CATEGORIES[0] is
    # A01, whose first example (idor) requires being "logged in" as a
    # seeded user (redirects to /switch-user otherwise), which would make
    # every plain client.get() in this file 302 instead of 200. sqli-login
    # is a standalone A03 route with no login/session requirement at all
    # -- confirmed live before writing this test file.
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def test_toggle_progress_marks_example_complete(app, client):
    seed_database(app)
    example = _safe_test_example()

    response = client.post(
        "/progress/toggle", data={"example_id": example.id}, follow_redirects=True
    )
    assert response.status_code == 200

    with app.app_context():
        assert ExampleProgress.query.filter_by(example_id=example.id).first() is not None


def test_toggle_progress_unmarks_on_second_toggle(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.filter_by(example_id=example.id).first() is None


def test_toggle_progress_rejects_unknown_example_id(app, client):
    seed_database(app)
    response = client.post("/progress/toggle", data={"example_id": "not-a-real-example"})
    assert response.status_code == 404

    with app.app_context():
        assert ExampleProgress.query.count() == 0


def test_toggle_progress_redirects_to_the_example_page(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()

    # url_for() needs a request context to build a relative URL (this app
    # has no SERVER_NAME configured, so app_context() alone raises
    # RuntimeError) -- test_request_context() provides one without making
    # a real HTTP request.
    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected


def test_mark_as_done_button_appears_on_example_page(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        path = url_for(example.endpoint)

    response = client.get(path)
    assert response.status_code == 200
    assert b"Mark as done" in response.data


def test_completed_example_shows_checkmark_button(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)

    response = client.get(path)
    assert "✓ Completed".encode() in response.data


def test_mark_as_done_button_absent_on_category_overview_page(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Mark as done" not in response.data
    assert "✓ Completed".encode() not in response.data


def test_mark_as_done_button_absent_on_settings_page(client):
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"Mark as done" not in response.data


def test_reset_lab_clears_progress(app, client):
    seed_database(app)
    example = _safe_test_example()
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.count() == 1

    client.post("/settings/reset")

    with app.app_context():
        assert ExampleProgress.query.count() == 0


def test_stats_page_loads(client):
    response = client.get("/stats")
    assert response.status_code == 200
    assert b"Your Progress" in response.data


def test_stats_page_shows_zero_percent_when_nothing_completed(app, client):
    seed_database(app)
    response = client.get("/stats")
    assert b"0%" in response.data


def test_stats_page_shows_correct_overall_count(app, client):
    seed_database(app)
    examples = [e for category in CATEGORIES for e in category.examples]
    assert len(examples) >= 2

    client.post("/progress/toggle", data={"example_id": examples[0].id})
    client.post("/progress/toggle", data={"example_id": examples[1].id})

    response = client.get("/stats")
    body = response.data.decode()
    assert f"2 of {len(examples)} completed" in body


def test_stats_page_shows_correct_per_category_count(app, client):
    seed_database(app)
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    example = a03.examples[0]

    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/stats")
    body = response.data.decode()
    assert f"1 of {len(a03.examples)} completed" in body
    assert "A03: Injection" in body


def test_stats_link_appears_in_dropdown_menu(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'class="dropdown-item" href="/stats"' in response.data.decode()
