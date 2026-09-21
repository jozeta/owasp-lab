import pathlib

STATIC_ROOT = pathlib.Path(__file__).resolve().parent.parent / "static"


def test_line_numbers_plugin_is_not_vendored():
    # The line-numbers plugin was intentionally removed so code blocks match
    # highlightjs.org's default usage-page look (no line numbers).
    path = STATIC_ROOT / "vendor" / "highlightjs" / "highlightjs-line-numbers.min.js"
    assert not path.exists(), f"line-numbers plugin should have been removed: {path}"


def test_github_dark_theme_is_vendored():
    path = STATIC_ROOT / "vendor" / "highlightjs" / "github-dark.min.css"
    assert path.exists(), f"expected vendored file at {path}"
    content = path.read_text()
    assert "Theme: GitHub Dark" in content
