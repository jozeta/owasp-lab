def test_shipping_select_page_renders(client):
    response = client.get("/a04/shipping-select")
    assert response.status_code == 200
    assert b"Free Shipping" in response.data


def test_default_paid_shipping_total_includes_shipping_cost(client):
    response = client.post("/a04/shipping-select", data={"shipping_cost_cents": "599"})
    assert response.status_code == 200
    assert b"$35.98" in response.data  # $29.99 product + $5.99 shipping


def test_client_supplied_zero_shipping_cost_is_trusted_under_threshold(client):
    # Cart total ($29.99) is well under the page's own stated $50 free-shipping
    # threshold, yet the server trusts a client-submitted shipping_cost_cents=0
    # with no server-side check of that threshold at all.
    response = client.post("/a04/shipping-select", data={"shipping_cost_cents": "0"})
    assert response.status_code == 200
    assert b"$29.99" in response.data
    assert b"Free shipping applied" in response.data


def test_button_label_matches_what_it_submits(client):
    response = client.get("/a04/shipping-select")
    assert response.status_code == 200
    # Initial state: shipping_cost_cents=599 will be submitted, so the button
    # should invite the user toward the free-shipping exploit, not claim to
    # already be selecting it.
    assert b"Select Standard Shipping" in response.data
