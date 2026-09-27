from app.core.nav import CATEGORIES

SQLI_GROUP_IDS = [
    "sqli-login",
    "union-exfiltration",
    "roster-sort",
    "error-based-sqli",
    "blind-sqli",
    "roster-lookup",
    "sqli-to-rce",
    "second-order-sqli-department-report",
]


def test_a03_sqli_group_examples_have_well_formed_hint_sequences():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    examples_by_id = {e.id: e for e in a03.examples}
    for example_id in SQLI_GROUP_IDS:
        example = examples_by_id[example_id]
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
