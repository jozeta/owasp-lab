from flask import url_for

from app.core.models import ExampleProgress, Settings
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _a10_example(example_id):
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return next(e for e in a10.examples if e.id == example_id)


def _enable_scoring(app):
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()


def test_reveal_hint_increments_hints_used(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 1


def test_reveal_hint_is_capped_at_the_examples_hint_count(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    assert len(example.hints) == 3

    for _ in range(5):
        client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 3


def test_revealed_hint_text_appears_on_the_example_page(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert example.hints[0].encode() in response.data
    assert example.hints[1].encode() not in response.data


def test_mark_as_done_button_previews_exact_point_value(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b"Mark as done (earn 7 pts)" in response.data


def test_points_freeze_at_completion_and_survive_later_hint_reveals(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("fetch-based-port-scan")

    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15


def test_unmarking_and_recompleting_recomputes_points_fresh(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("blocklist-redirect-bypass")

    client.post("/progress/toggle", data={"example_id": example.id})
    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 30

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 18


def test_scoring_enabled_hides_exploit_instructions_regardless_of_stored_value(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = True
        db.session.commit()
    example = _a10_example("webhook-internal-metadata")

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b'card-header bg-danger text-white">Exploitation' not in response.data


def test_settings_post_does_not_clear_show_exploit_instructions_while_enabling_scoring(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        db.session.commit()

    # Simulates the browser: the exploit-instructions checkbox is disabled
    # while scoring is being turned on, so it is omitted from the submitted
    # form data entirely.
    client.post(
        "/settings",
        data={"show_explanations": "on", "scoring_enabled": "on"},
    )

    with app.app_context():
        settings = Settings.get()
        assert settings.show_exploit_instructions is True
        assert settings.scoring_enabled is True


def test_home_page_shows_score_totals_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/")
    body = response.data.decode()
    assert "Score: 10 / 1620 points" in body


def test_nav_bar_shows_running_score_on_any_page_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for("a10_ssrf.overview")
    response = client.get(path)
    assert b"Score: 10 / 1620" in response.data


def test_score_ui_absent_when_scoring_disabled(client):
    response = client.get("/")
    assert b"Score:" not in response.data
