from app.core.nav import CategoryNav, ExampleNav


def test_example_nav_difficulty_badge_classes():
    easy = ExampleNav(id="x", title="X", difficulty="Easy", endpoint="core.home")
    medium = ExampleNav(id="y", title="Y", difficulty="Medium", endpoint="core.home")
    hard = ExampleNav(id="z", title="Z", difficulty="Hard", endpoint="core.home")

    assert easy.difficulty_badge_class() == "text-bg-success"
    assert medium.difficulty_badge_class() == "text-bg-warning"
    assert hard.difficulty_badge_class() == "text-bg-danger"


def test_category_nav_holds_ordered_examples():
    category = CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(id="idor", title="IDOR", difficulty="Easy", endpoint="a01_access_control.idor"),
        ],
    )
    assert category.examples[0].difficulty == "Easy"
    assert category.seed_fn is None


def test_category_nav_defaults_to_empty_blurb():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
    )
    assert category.blurb == ""


def test_every_registered_category_has_a_nonempty_blurb(app):
    # `app` fixture forces create_app() to run, which is what actually
    # imports every category blueprint and populates CATEGORIES -- without
    # it this test could vacuously pass on an empty list depending on
    # pytest's collection order.
    from app.core.nav import CATEGORIES

    for category in CATEGORIES:
        assert category.blurb.strip() != "", f"{category.short_id} is missing a blurb"
