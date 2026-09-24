def test_coupon_stack_page_renders(client):
    response = client.get("/a04/coupon-stack")
    assert response.status_code == 200
    assert b"Discount Code Stacking" in response.data


def test_single_code_applies_normally(client):
    response = client.post("/a04/coupon-stack", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"$24.99" in response.data  # $29.99 - $5.00


def test_submitting_both_codes_as_duplicate_form_fields_stacks_both(client):
    # HTTP parameter pollution: two "code" values in one POST body.
    response = client.post(
        "/a04/coupon-stack",
        data="code=WELCOME10&code=SAVE20",
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 200
    assert b"$14.99" in response.data  # $29.99 - $5.00 - $10.00, both discounts stacked
