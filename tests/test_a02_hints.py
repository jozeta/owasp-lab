from app.core.nav import CATEGORIES


def test_a02_examples_have_well_formed_hint_sequences(app):
    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert len(a02.examples) == 5
    for example in a02.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
