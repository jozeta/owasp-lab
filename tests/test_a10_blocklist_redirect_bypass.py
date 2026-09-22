def test_mirror_fetcher_page_renders(client):
    response = client.get("/a10/mirror-fetcher")
    assert response.status_code == 200


def test_mirror_fetcher_rejects_a_non_allowlisted_host(client):
    response = client.post(
        "/a10/mirror-fetcher", data={"mirror_url": "http://evil.example/"}
    )
    assert response.status_code == 200
    assert b"Only approved content mirrors are allowed" in response.data


def test_mirror_fetcher_fetches_a_directly_allowlisted_host(client, monkeypatch):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    real_getaddrinfo = socket.getaddrinfo

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DIRECT-MIRROR-CONTENT")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "trusted-mirror.example":
            host = "127.0.0.1"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        response = client.post(
            "/a10/mirror-fetcher",
            data={"mirror_url": f"http://trusted-mirror.example:{port}/"},
        )
        assert response.status_code == 200
        assert b"DIRECT-MIRROR-CONTENT" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_redirect_from_allowlisted_host_bypasses_validation(client, monkeypatch):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    real_getaddrinfo = socket.getaddrinfo

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"REACHED-INTERNAL-TARGET-VIA-REDIRECT")

        def log_message(self, *args):
            pass

    target = HTTPServer(("127.0.0.1", 0), TargetHandler)
    target_port = target.server_address[1]
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target_port}/")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirector_port = redirector.server_address[1]
    redirector_thread = threading.Thread(target=redirector.serve_forever, daemon=True)
    redirector_thread.start()

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "trusted-mirror.example":
            host = "127.0.0.1"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        response = client.post(
            "/a10/mirror-fetcher",
            data={"mirror_url": f"http://trusted-mirror.example:{redirector_port}/"},
        )
        assert response.status_code == 200
        assert b"REACHED-INTERNAL-TARGET-VIA-REDIRECT" in response.data
    finally:
        redirector.shutdown()
        redirector_thread.join(timeout=5)
        target.shutdown()
        target_thread.join(timeout=5)


def test_blocklist_redirect_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Open Redirect Bypasses a Trusted-Domain Allowlist" in response.data
    assert b'href="/a10/mirror-fetcher"' in response.data
