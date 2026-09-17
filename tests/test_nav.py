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
