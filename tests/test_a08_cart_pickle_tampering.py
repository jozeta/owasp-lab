import base64
import pickle


def test_cart_shows_default_price_with_no_cookie(client):
    response = client.get("/a08/cart")
    assert response.status_code == 200
    assert b"49.99" in response.data


def test_cart_honors_a_legitimately_issued_cookie(client):
    import base64
    import pickle

    first = client.get("/a08/cart")
    set_cookie_header = first.headers.get("Set-Cookie", "")
    assert set_cookie_header.startswith("a08_cart=")
    cookie_value = set_cookie_header.split("a08_cart=", 1)[1].split(";", 1)[0]
    decoded_cart = pickle.loads(base64.b64decode(cookie_value))
    assert decoded_cart == {"item": "Widget", "price": 49.99}

    second = client.get("/a08/cart")
    assert b"49.99" in second.data


def test_cart_honors_a_client_crafted_tampered_price(client):
    # The attacker never needs the server's own token -- pickle has no
    # integrity protection to defeat, so knowing the expected shape is
    # enough to forge one independently.
    tampered = base64.b64encode(pickle.dumps({"item": "Widget", "price": 0.01})).decode()
    client.set_cookie("a08_cart", tampered, domain="localhost")
    response = client.get("/a08/cart")
    assert response.status_code == 200
    assert b"$0.01" in response.data
    assert b"49.99" not in response.data


def test_cart_pickle_tampering_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Pickle Cart Tampering" in response.data
    assert b'href="/a08/cart"' in response.data
