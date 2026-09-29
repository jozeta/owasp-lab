from app.core.seed import seed_database


def test_comments_page_shows_seeded_comment(app, client):
    seed_database(app)
    response = client.get("/a03/comments")
    assert response.status_code == 200
    assert b"Nice site" in response.data


def test_comments_stores_and_reflects_unescaped_script(app, client):
    seed_database(app)
    response = client.post(
        "/a03/comments",
        data={"author": "Attacker", "body": "<script>alert('xss')</script>"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<script>alert('xss')</script>" in response.data


def test_comments_stored_xss_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/comments",
        data={"author": "Attacker", "body": "<script>alert('xss')</script>"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<script>alert('xss')</script>" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_comments_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Stored XSS in Comments" in response.data
    assert b'href="/a03/comments"' in response.data


def test_comments_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/comments")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"comment.body|safe" in response.data


def test_comments_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a03/comments")
    assert response.status_code == 200
    assert b"the comment body is being interpreted as" in response.data
