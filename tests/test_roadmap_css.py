from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _lab_css():
    return (REPO_ROOT / "static/css/lab.css").read_text()


def test_roadmap_classes_defined():
    css = _lab_css()
    for cls in (
        ".roadmap {",
        ".roadmap-track,",
        ".roadmap-track-fill {",
        ".roadmap-node {",
        ".roadmap-node-ring {",
        ".roadmap-node-inner {",
        ".roadmap-badge {",
        ".roadmap-node-info {",
        ".roadmap-node-title {",
    ):
        assert cls in css, f"missing rule: {cls}"


def test_roadmap_ring_uses_conic_gradient_and_pct_variable():
    css = _lab_css()
    assert "conic-gradient(var(--fjord-accent) calc(var(--pct) * 1%)" in css


def test_roadmap_has_desktop_zigzag_breakpoint():
    css = _lab_css()
    assert "@media (min-width: 768px) {" in css
    assert "grid-template-columns: 1fr 1fr;" in css
    assert ":nth-of-type(odd)" in css
    assert ":nth-of-type(even)" in css


def test_roadmap_track_fill_uses_fjord_accent():
    css = _lab_css()
    assert ".roadmap-track-fill {\n  background: var(--fjord-accent);" in css


def test_lab_css_original_content_untouched():
    """Sanity check: the file has grown, not been rewritten -- the
    pre-existing sidebar/card/font-face rules from earlier sub-projects
    must still be present verbatim."""
    css = _lab_css()
    assert "#sidebar .nav-link {" in css
    assert '@font-face {\n  font-family: "IBM Plex Sans";' in css
    assert "@keyframes fjord-fill {" in css
