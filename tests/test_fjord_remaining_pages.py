from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_leaderboard_table_uses_fjord_card_wrapper(app, client):
    seed_database(app)
    response = client.get("/leaderboard")
    assert response.status_code == 200
    assert b"fjord-card" in response.data


def test_instructor_view_table_uses_fjord_card_wrapper(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert response.status_code == 200
    assert b"fjord-card" in response.data


def test_switch_user_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"Choose Who You're Logged In As" in response.data


def test_settings_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/settings")
    assert response.status_code == 200


def test_tools_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/tools")
    assert response.status_code == 200


def test_about_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/about")
    assert response.status_code == 200
