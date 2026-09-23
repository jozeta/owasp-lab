from app.core.nav import CATEGORIES


def test_every_example_across_every_category_has_a_well_formed_hint_sequence():
    total = 0
    for category in CATEGORIES:
        for example in category.examples:
            total += 1
            assert 3 <= len(example.hints) <= 5, (
                f"{category.short_id}/{example.id} has {len(example.hints)} hints"
            )
            assert all(hint.strip() for hint in example.hints), (
                f"{category.short_id}/{example.id} has an empty hint"
            )
            assert len(set(example.hints)) == len(example.hints), (
                f"{category.short_id}/{example.id} has duplicate hints"
            )
    assert total == 69
