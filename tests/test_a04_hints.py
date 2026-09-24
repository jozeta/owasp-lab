from app.core.nav import CATEGORIES


def test_a04_examples_have_well_formed_hint_sequences():
    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert len(a04.examples) == 9
    for example in a04.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
