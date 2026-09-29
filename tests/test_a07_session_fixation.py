from app.core.seed import seed_database


def test_session_fixation_demo_page_renders(app, client):
    seed_database(app)
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a07/session-fixation-demo")
    assert response.status_code == 200
    assert b"sid=attacker-planted-9f8e7d" in response.data


def test_full_session_fixation_chain(app, client):
    seed_database(app)
    planted_sid = "planted-by-attacker-1234"

    # Step 1: attacker visits with a chosen sid, gets it registered as a
    # live (unauthenticated) session.
    client.get(f"/a07/account?sid={planted_sid}")

    # Step 2: victim visits the same URL (adopting the planted id as their
    # own cookie), then logs in -- the id is NOT rotated on login.
    client.get(f"/a07/account?sid={planted_sid}")
    client.set_cookie("a07_session_id", planted_sid, domain="localhost")
    client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
    )

    # Step 3: attacker, who never submitted any credentials, presents the
    # SAME planted sid directly and is authenticated as the victim.
    client.set_cookie("a07_session_id", planted_sid, domain="localhost")
    response = client.get("/a07/account")
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_fixation_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Fixation" in response.data
    assert b'href="/a07/session-fixation-demo"' in response.data
