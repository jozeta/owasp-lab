def test_csv_injection_explanation_page_renders_html(client):
    response = client.get("/a03/csv-injection")
    assert response.status_code == 200
    assert b"CSV Formula Injection" in response.data


def test_csv_export_headers(client):
    response = client.get("/a03/export-comments-csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert response.headers["Content-Disposition"] == "attachment; filename=comments_export.csv"


def test_csv_export_contains_unneutralized_basic_formula_payload(client):
    payload = "=1+1"
    client.post("/a03/comments", data={"author": "Attacker", "body": payload})

    response = client.get("/a03/export-comments-csv")
    body = response.data.decode()
    # the raw, unmodified formula text appears in the CSV -- no leading
    # single-quote or other character was prepended to neutralize it
    assert f",{payload}" in body


def test_csv_export_preserves_dde_calc_spawn_payload_unmodified(client):
    payload = "=cmd|'/C calc'!A0"
    client.post("/a03/comments", data={"author": "Attacker", "body": payload})

    response = client.get("/a03/export-comments-csv")
    body = response.data.decode()
    assert payload in body
