from datetime import datetime

from app.core.models import ExampleProgress, Settings
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def test_badge_case_shows_all_visible_badges_locked_by_default(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert body.count('class="badge-chip earned"') == 1  # only participation-trophy
    assert body.count('class="badge-chip locked"') >= 20


def test_earning_a_category_badge_marks_its_chip_earned(app, client):
    seed_database(app)
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        for example in a10.examples:
            db.session.add(
                ExampleProgress(
                    example_id=example.id,
                    completed_at=datetime.utcnow(),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert ">Request Forger<" in body
    # Anchor on the closing tag boundary, not a bare substring search: the
    # A10 category card's title "Server-Side Request Forgery" contains
    # "Request Forger" as a substring (Forge-ry), so a plain body.index()
    # for "Request Forger" can match inside that card's title instead of
    # the badge chip's name once the dash-grid renders before the badge
    # case. ">Request Forger<" only matches the badge-chip-name span's
    # exact text, never "...Request Forgery</div>".
    request_forger_index = body.index(">Request Forger<")
    # Note: search for the enclosing chip *div*'s opening tag specifically
    # (trailing space after "badge-chip"), not just the substring
    # 'class="badge-chip' -- that substring also matches the nested
    # `class="badge-chip-name"` span immediately wrapping the badge name
    # text, which is closer to request_forger_index and would otherwise be
    # picked up by a plain rindex instead of the actual chip div.
    chip_start = body.rindex('<div class="badge-chip ', 0, request_forger_index)
    assert "earned" in body[chip_start:request_forger_index]


def test_leet_badge_hidden_when_scoring_disabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/")
    assert b"Cross 1337 points" not in response.data


def test_leet_badge_shown_when_scoring_enabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()

    response = client.get("/")
    assert b"Cross 1337 points" in response.data
