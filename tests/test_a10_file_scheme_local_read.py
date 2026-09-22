def test_pdf_generator_page_renders(client):
    response = client.get("/a10/pdf-generator")
    assert response.status_code == 200


def test_pdf_generator_fetches_a_normal_url(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"NORMAL-WEBPAGE-CONTENT")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a10/pdf-generator", data={"page_url": f"http://127.0.0.1:{port}/"}
        )
        assert response.status_code == 200
        assert b"NORMAL-WEBPAGE-CONTENT" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_file_scheme_reads_the_real_local_secret_file(client):
    from app.categories.a10_ssrf.routes import FAKE_SECRET_FILE_PATH

    with open(FAKE_SECRET_FILE_PATH) as f:
        expected_content = f.read()

    response = client.post(
        "/a10/pdf-generator", data={"page_url": f"file://{FAKE_SECRET_FILE_PATH}"}
    )
    assert response.status_code == 200
    assert expected_content.encode() in response.data


def test_file_scheme_local_read_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"PDF Generator Reads Local Files via" in response.data
    assert b'href="/a10/pdf-generator"' in response.data
