import pathlib

STATIC_ROOT = pathlib.Path(__file__).resolve().parent.parent / "static"


def test_line_numbers_plugin_is_vendored():
    path = STATIC_ROOT / "vendor" / "highlightjs" / "highlightjs-line-numbers.min.js"
    assert path.exists(), f"expected vendored file at {path}"
    content = path.read_text()
    assert len(content) > 1000
    assert "hljs-ln" in content
