def test_limited_stock_cart_page_renders(client):
    response = client.get("/a04/limited-stock-cart")
    assert response.status_code == 200
    assert b"Only 3 left in stock" in response.data


def test_ordering_within_stock_succeeds(client):
    response = client.post("/a04/limited-stock-cart", data={"quantity": "2"})
    assert response.status_code == 200
    assert b"Order confirmed: 2" in response.data


def test_ordering_far_more_than_stock_is_never_rejected(client):
    # VULNERABLE: the page advertises only 3 in stock, but the handler
    # never checks the submitted quantity against that count at all.
    response = client.post("/a04/limited-stock-cart", data={"quantity": "500"})
    assert response.status_code == 200
    assert b"Order confirmed: 500" in response.data
    assert b"$14995.00" in response.data  # 500 * $29.99
