def test_import_avatar_page_renders(client):
    response = client.get("/a10/import-avatar")
    assert response.status_code == 200


def test_import_avatar_blocks_literal_127_0_0_1(client):
    response = client.post(
        "/a10/import-avatar", data={"avatar_url": "http://127.0.0.1:9999/"}
    )
    assert response.status_code == 200
    assert b"That host is not allowed" in response.data


def test_import_avatar_blocks_literal_localhost(client):
    response = client.post(
        "/a10/import-avatar", data={"avatar_url": "http://localhost:9999/"}
    )
    assert response.status_code == 200
    assert b"That host is not allowed" in response.data


def test_alternate_ip_encodings_bypass_the_blocklist(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"REACHED-VIA-ALTERNATE-ENCODING")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # These four are live-verified to all resolve to 127.0.0.1 and to
        # NOT be members of BLOCKED_HOSTS -- see the plan's Global
        # Constraints. Do not add "0177.0.0.1" here; it does not work.
        for host in ["2130706433", "0x7f000001", "127.1", "0"]:
            response = client.post(
                "/a10/import-avatar", data={"avatar_url": f"http://{host}:{port}/"}
            )
            assert response.status_code == 200
            assert b"REACHED-VIA-ALTERNATE-ENCODING" in response.data, (
                f"payload {host!r} did not bypass the blocklist"
            )
            assert b"That host is not allowed" not in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_blocklist_alternate_ip_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Alternate IP Representation Bypasses a Naive Blocklist" in response.data
    assert b'href="/a10/import-avatar"' in response.data
