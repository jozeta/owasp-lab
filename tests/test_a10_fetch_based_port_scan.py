def test_port_scan_demo_page_renders(client):
    response = client.get("/a10/port-scan-demo")
    assert response.status_code == 200


def test_port_scan_demo_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Same Fetcher Enables Internal Port Scanning" in response.data
    assert b'href="/a10/port-scan-demo"' in response.data


def test_webhook_tester_differentiates_open_and_closed_internal_ports(client):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OPEN-PORT-RESPONSE")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    open_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # A "definitely closed" port: bind an ephemeral socket, read back the
    # port the OS assigned, then close it immediately. Nothing else should
    # grab it in the brief window before this test uses it.
    closed_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_socket.bind(("127.0.0.1", 0))
    closed_port = closed_socket.getsockname()[1]
    closed_socket.close()

    try:
        open_response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{open_port}/"}
        )
        assert open_response.status_code == 200
        assert b"OPEN-PORT-RESPONSE" in open_response.data

        closed_response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{closed_port}/"}
        )
        assert closed_response.status_code == 200
        assert b"Could not reach webhook URL" in closed_response.data
        assert b"OPEN-PORT-RESPONSE" not in closed_response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)
