from app.core.nav import CATEGORIES


def test_a05_examples_have_well_formed_hint_sequences():
    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert len(a05.examples) == 10
    for example in a05.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
