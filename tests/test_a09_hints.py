from app.core.nav import CATEGORIES


def test_a09_examples_have_well_formed_hint_sequences():
    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    assert len(a09.examples) == 6
    for example in a09.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
