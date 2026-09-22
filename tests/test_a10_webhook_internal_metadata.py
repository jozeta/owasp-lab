def test_webhook_tester_page_renders(client):
    response = client.get("/a10/webhook-tester")
    assert response.status_code == 200


def test_webhook_tester_genuinely_fetches_an_arbitrary_url(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"FETCHED-VIA-WEBHOOK-TESTER-PROBE")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{port}/"}
        )
        assert response.status_code == 200
        assert b"FETCHED-VIA-WEBHOOK-TESTER-PROBE" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_internal_metadata_rejects_a_simulated_external_caller(client):
    response = client.get(
        "/a10/internal/metadata", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}
    )
    assert response.status_code == 403


def test_internal_metadata_trusts_a_localhost_origin_request(client):
    response = client.get("/a10/internal/metadata")
    assert response.status_code == 200
    assert b"AKIAFAKESSRFPROOF1234" in response.data


def test_webhook_internal_metadata_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Webhook Tester Reaches Internal Metadata Endpoint" in response.data
    assert b'href="/a10/webhook-tester"' in response.data
