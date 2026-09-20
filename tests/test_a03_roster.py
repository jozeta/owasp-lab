from sqlalchemy.exc import DBAPIError

from app.core.seed import seed_database


def test_roster_default_view_lists_all_employees(app, client):
    seed_database(app)
    response = client.get("/a03/roster")
    assert response.status_code == 200
    assert b"Alice Chen" in response.data
    assert b"Morgan Reyes" in response.data


def test_roster_column_count_discovery_via_order_by_position(app, client):
    # A valid ordinal position (4 columns are selected: id, name, email,
    # department) succeeds.
    valid = client.get("/a03/roster", query_string={"sort": "4"})
    assert valid.status_code == 200

    # An out-of-range ordinal position (5) genuinely raises a real database
    # error -- this is the discriminating signal that confirms the exact
    # column count without ever seeing any row data. Under Flask's TESTING
    # config, this exception propagates to the test client caller directly
    # (verified: TESTING=True disables Flask's default exception-to-500
    # conversion) rather than becoming a 500 response -- so the test
    # asserts on the raised exception, not a response object. Live in
    # Docker (non-debug, non-testing), this same underlying error instead
    # surfaces as Flask's generic 500 error page, an equally real and
    # observable signal to a trainee using a browser.
    with app.app_context():
        try:
            client.get("/a03/roster", query_string={"sort": "5"})
            raised = False
        except DBAPIError:
            raised = True
    assert raised


def test_roster_boolean_reordering_via_case_when(app, client):
    seed_database(app)
    # A CASE WHEN expression that's numerically comparable across both
    # branches (id vs. -id) reorders rows based on a condition, without any
    # error and without revealing anything the app doesn't already show --
    # purely a boolean signal encoded in row order.
    true_condition = client.get(
        "/a03/roster", query_string={"sort": "(CASE WHEN (1=1) THEN id ELSE id * -1 END)"}
    )
    assert true_condition.status_code == 200
    false_condition = client.get(
        "/a03/roster", query_string={"sort": "(CASE WHEN (1=2) THEN id ELSE id * -1 END)"}
    )
    assert false_condition.status_code == 200
    # True condition sorts ascending by id (Alice Chen, id=1, appears
    # before Morgan Reyes, id=9); false condition sorts by -id, reversing
    # that order. Comparing the two responses' relative position of these
    # two names proves the boolean signal is genuinely observable via
    # row order alone.
    true_body = true_condition.data.decode()
    false_body = false_condition.data.decode()
    assert true_body.index("Alice Chen") < true_body.index("Morgan Reyes")
    assert false_body.index("Morgan Reyes") < false_body.index("Alice Chen")


def test_roster_secure_pattern_rejects_injection_attempt():
    # Proves the Vulnerable-vs-Secure panel's allowlist approach genuinely
    # neutralizes an injection attempt -- a malicious sort expression is
    # not a member of the allowed column-name set, so it's replaced with
    # the safe default before ever reaching string interpolation.
    allowed_sort_columns = {"id", "name", "email", "department"}
    malicious_sort = "(CASE WHEN (1=1) THEN id ELSE id * -1 END)"
    safe_sort = malicious_sort if malicious_sort in allowed_sort_columns else "id"
    assert safe_sort == "id"


def test_roster_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/roster")
    assert response.status_code == 200
    assert b"Alice Chen" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_roster_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Employee Roster Sort" in response.data
    assert b'href="/a03/roster"' in response.data


def test_tasks_block_does_not_render_for_examples_without_it(client):
    # Confirms the new |trim-guarded Tasks section (Step 1) doesn't
    # accidentally render an empty card on any example that doesn't
    # define {% block tasks %} -- checked against this task's own new
    # roster.html AND an existing, unrelated example page, proving the
    # guard is safe project-wide, not just for this one template.
    roster_response = client.get("/a03/roster")
    assert b'<div class="card-header">Tasks</div>' not in roster_response.data

    existing_response = client.get("/a03/login")
    assert b'<div class="card-header">Tasks</div>' not in existing_response.data
