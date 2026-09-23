from app.core.nav import CATEGORIES


def test_a07_examples_have_well_formed_hint_sequences():
    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert len(a07.examples) == 9
    for example in a07.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
