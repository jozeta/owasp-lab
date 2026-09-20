def test_filter_challenge_level1_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "1", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_level1_blocks_naive_script_tag(client):
    # Assert the full live-output wrapper, not a bare substring match --
    # "[blocked: script tag detected]" also appears, unconditionally, in
    # this page's own static vulnerable_code sample (rendered on every
    # page load regardless of what payload was submitted), so a bare
    # substring assertion would pass vacuously even if the filter were
    # broken or removed entirely.
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "1", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"[blocked: script tag detected]</div>"
    ) in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level1_bypass_executes(client):
    payload = "<img src=x onerror=console.log('LEVEL-1-BYPASS')>"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "1", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"<img src=x onerror=console.log('LEVEL-1-BYPASS')></div>"
    ) in response.data


def test_filter_challenge_level2_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "2", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_level2_strips_naive_script_tag(client):
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "2", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">alert(1)</div>' in response.data
    )
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level2_bypass_reconstructs_script_tag(client):
    # After the filter strips "<script>" and "</script>" as two separate,
    # non-recursive passes, the leftover fragments recombine into a real
    # <script> tag the filter never gets to re-scan.
    payload = "<scr<script>ipt>console.log('LEVEL-2-BYPASS')</scr</script>ipt>"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "2", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"<script>console.log('LEVEL-2-BYPASS')</script></div>"
    ) in response.data


def test_filter_challenge_level3_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "3", "payload": "hello"}
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" value="hello" '
        b'placeholder="Your name" readonly>'
    ) in response.data


def test_filter_challenge_level3_escapes_naive_script_tag(client):
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "3", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" '
        b'value="&lt;script&gt;alert(1)&lt;/script&gt;" '
        b'placeholder="Your name" readonly>'
    ) in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level3_bypass_breaks_out_of_attribute(client):
    # The filter's replace() calls only ever touch "<" and ">" -- a lone
    # double-quote sails through untouched and closes the value="..."
    # attribute early, turning the rest of the payload into two brand-new
    # attributes (autofocus + onfocus) on the same <input> tag.
    payload = "\" autofocus onfocus=\"console.log('LEVEL-3-BYPASS')"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "3", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" value="" autofocus '
        b"onfocus=\"console.log('LEVEL-3-BYPASS')\" "
        b'placeholder="Your name" readonly>'
    ) in response.data


def test_filter_challenge_invalid_level_defaults_to_level_1(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "9", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_tasks_hidden_when_exploit_instructions_off(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/filter-challenge")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data
    assert b"Tasks" not in response.data


def test_filter_challenge_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Filter Bypass Challenge" in response.data
    assert b'href="/a03/filter-challenge"' in response.data
