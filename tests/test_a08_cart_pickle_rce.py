from app.categories.a08_integrity_failures.models import RceProof


def test_cart_rce_demo_page_renders_and_plants_the_payload_cookie(client):
    response = client.get("/a08/cart-rce-demo")
    assert response.status_code == 200
    assert "a08_cart" in response.headers.get("Set-Cookie", "")


def test_cart_rce_demo_genuinely_executes_code_on_deserialization(app, client):
    with app.app_context():
        before_count = RceProof.query.count()

    # Visiting the demo page plants the malicious cart cookie; visiting
    # /a08/cart next is what actually calls pickle.loads() on it.
    demo_response = client.get("/a08/cart-rce-demo")
    assert demo_response.status_code == 200

    cart_response = client.get("/a08/cart")
    assert cart_response.status_code == 200

    with app.app_context():
        after_count = RceProof.query.count()
        latest = RceProof.query.order_by(RceProof.id.desc()).first()

    assert after_count == before_count + 1
    assert latest.message == "PWNED-VIA-PICKLE-RCE"


def test_rce_proof_page_shows_recorded_proofs(app, client):
    client.get("/a08/cart-rce-demo")
    client.get("/a08/cart")

    response = client.get("/a08/rce-proof")
    assert response.status_code == 200
    assert b"PWNED-VIA-PICKLE-RCE" in response.data


def test_cart_pickle_rce_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Pickle Deserialization RCE" in response.data
    assert b'href="/a08/cart-rce-demo"' in response.data
