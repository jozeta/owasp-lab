def test_premium_content_locked_before_subscribing(client):
    response = client.get("/a04/premium/content")
    assert response.status_code == 200
    assert b"Subscribe to see premium content" in response.data


def test_subscribing_unlocks_premium_content(client):
    client.post("/a04/premium/subscribe")
    response = client.get("/a04/premium/content")
    assert response.status_code == 200
    assert b"Premium content unlocked" in response.data


def test_cancelling_does_not_clear_the_premium_cookie(client):
    client.post("/a04/premium/subscribe")
    cancel_response = client.post("/a04/premium/cancel", follow_redirects=True)
    assert b"cancelled" in cancel_response.data.lower()

    # VULNERABLE: the premium-content route checks only the cookie set at
    # subscribe time, which cancellation never clears or invalidates.
    content_response = client.get("/a04/premium/content")
    assert content_response.status_code == 200
    assert b"Premium content unlocked" in content_response.data
