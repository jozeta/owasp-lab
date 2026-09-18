from app.core.nav import CategoryNav, ExampleNav


def test_example_nav_difficulty_badge_classes():
    easy = ExampleNav(id="x", title="X", group="G", difficulty="Easy", endpoint="core.home")
    medium = ExampleNav(id="y", title="Y", group="G", difficulty="Medium", endpoint="core.home")
    hard = ExampleNav(id="z", title="Z", group="G", difficulty="Hard", endpoint="core.home")

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
            ExampleNav(id="idor", title="IDOR", group="IDOR", difficulty="Easy", endpoint="a01_access_control.idor"),
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


def test_grouped_examples_orders_by_first_occurrence():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
        examples=[
            ExampleNav(id="a", title="A", group="Group B", difficulty="Easy", endpoint="core.home"),
            ExampleNav(id="b", title="B", group="Group A", difficulty="Easy", endpoint="core.home"),
            ExampleNav(id="c", title="C", group="Group B", difficulty="Hard", endpoint="core.home"),
        ],
    )
    grouped = category.grouped_examples()
    assert [name for name, _ in grouped] == ["Group B", "Group A"]
    assert [e.id for e in grouped[0][1]] == ["a", "c"]
    assert [e.id for e in grouped[1][1]] == ["b"]


def test_grouped_examples_single_example_category():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
        examples=[
            ExampleNav(id="a", title="A", group="Only Group", difficulty="Easy", endpoint="core.home"),
        ],
    )
    grouped = category.grouped_examples()
    assert grouped == [("Only Group", [category.examples[0]])]


def test_grouped_examples_empty_category():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
    )
    assert category.grouped_examples() == []


def test_every_example_has_a_nonempty_group(app):
    # Same rationale as test_every_registered_category_has_a_nonempty_blurb:
    # the `app` fixture forces create_app() to run, populating CATEGORIES.
    from app.core.nav import CATEGORIES

    for category in CATEGORIES:
        for example in category.examples:
            assert example.group.strip() != "", (
                f"{category.short_id}/{example.id} is missing a group"
            )
