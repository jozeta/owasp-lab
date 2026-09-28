from app.core.seed import seed_database


def test_example_page_has_no_structural_regression(app, client):
    """Sanity check: an example page still renders its six-block structure
    (this test does not assert on new Fjord markup -- it just confirms the
    existing page didn't break)."""
    seed_database(app)
    response = client.get("/a03/login")
    assert response.status_code == 200
    assert b"Explanation" in response.data


def test_overview_page_shows_its_category_icon(app, client):
    seed_database(app)
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"#icon-a03" in response.data


def test_overview_page_for_every_category_shows_matching_icon(app, client):
    seed_database(app)
    category_paths_and_icons = [
        ("/a01/", "#icon-a01"),
        ("/a02/", "#icon-a02"),
        ("/a03/", "#icon-a03"),
        ("/a04/", "#icon-a04"),
        ("/a05/", "#icon-a05"),
        ("/a06/", "#icon-a06"),
        ("/a07/", "#icon-a07"),
        ("/a08/", "#icon-a08"),
        ("/a09/", "#icon-a09"),
        ("/a10/", "#icon-a10"),
    ]
    for path, icon_ref in category_paths_and_icons:
        response = client.get(path)
        assert response.status_code == 200
        assert icon_ref.encode() in response.data, f"{path} missing {icon_ref}"
