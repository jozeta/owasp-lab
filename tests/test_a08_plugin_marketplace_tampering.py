import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _PluginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        if self.path == "/official.py":
            self.wfile.write(b'PLUGIN_NAME = "Official Theme"\n')
        elif self.path == "/substituted.py":
            self.wfile.write(b'PLUGIN_NAME = "Substituted Theme -- not the real one"\n')
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


def _start_plugin_server():
    server = HTTPServer(("127.0.0.1", 0), _PluginHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def test_plugin_marketplace_page_renders(client):
    response = client.get("/a08/plugin-marketplace")
    assert response.status_code == 200


def test_plugin_marketplace_installs_content_from_any_url_with_no_verification(client):
    server, thread, port = _start_plugin_server()
    try:
        official = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/official.py"},
        )
        assert official.status_code == 200
        assert b"Official Theme" in official.data

        substituted = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/substituted.py"},
        )
        assert substituted.status_code == 200
        # Both installed identically (neither produced an error), proving
        # there is no signature/checksum verification distinguishing a
        # legitimate source from a substituted one.
        assert b"Substituted Theme -- not the real one" in substituted.data
        assert b"Could not install plugin" not in substituted.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_plugin_marketplace_tampering_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unsigned Plugin Content Trust" in response.data
    assert b'href="/a08/plugin-marketplace"' in response.data


def test_official_plugin_download_is_served(client):
    response = client.get("/a08/plugin-marketplace/official-plugin.py")
    assert response.status_code == 200
    assert b"PLUGIN_NAME" in response.data


def test_malicious_plugin_demo_download_is_served(client):
    response = client.get("/a08/plugin-marketplace/malicious-plugin-demo.py")
    assert response.status_code == 200
    assert b"write_rce_proof" in response.data
