from app.core.nav import CATEGORIES

REMAINING_GROUP_IDS = [
    "reflected-xss",
    "stored-xss",
    "filter-challenge",
    "unicode-normalization-xss-bypass",
    "filtered-host-lookup",
    "command-injection",
    "blind-report-injection",
    "argument-injection-tar-export",
    "xml-import",
    "xxe-ssrf",
    "ssti-email-preview",
    "ssti-blacklist-bypass",
    "ldap-directory-login",
    "ldap-directory-search",
    "css-attribute-exfil",
    "csv-formula-injection",
    "file-inclusion-lfi-ssti",
    "svg-upload-stored-xss",
]


def test_a03_remaining_groups_examples_have_well_formed_hint_sequences():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    examples_by_id = {e.id: e for e in a03.examples}
    for example_id in REMAINING_GROUP_IDS:
        example = examples_by_id[example_id]
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
