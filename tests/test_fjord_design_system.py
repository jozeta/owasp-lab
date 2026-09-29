import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_FONT_CHECKSUMS = {
    "static/vendor/ibm-plex/IBMPlexSans-Regular.woff2": "ba711a3085ff9f27440b6b9c4550cfc47c97bf36591d5da958b975bb3add8c1a",
    "static/vendor/ibm-plex/IBMPlexSans-Medium.woff2": "5660f8a658f8bb50dbc005232f885eadffd2bc1c235c4f6fbb63469d1f9cde6d",
    "static/vendor/ibm-plex/IBMPlexSans-SemiBold.woff2": "f78048030eab62e860efa39a0df79e2e5581bf122eb95b9bc42c0b8a4988d205",
    "static/vendor/ibm-plex/IBMPlexMono-Regular.woff2": "ba204497f16b6d334cee9d1e963a831b73e3a56e1d6300a8489d18df7214b350",
}


def test_font_files_exist_with_correct_checksums():
    for relative_path, expected_sha256 in EXPECTED_FONT_CHECKSUMS.items():
        path = REPO_ROOT / relative_path
        assert path.is_file(), f"missing vendored font: {relative_path}"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected_sha256, f"{relative_path} checksum mismatch"


def test_font_license_files_exist():
    assert (REPO_ROOT / "static/vendor/ibm-plex/LICENSE-IBM-Plex-Sans.txt").is_file()
    assert (REPO_ROOT / "static/vendor/ibm-plex/LICENSE-IBM-Plex-Mono.txt").is_file()


def test_icon_sprite_has_all_ten_category_icons():
    sprite = (REPO_ROOT / "static/icons/category-icons.svg").read_text()
    for n in range(1, 11):
        assert f'id="icon-a{n:02d}"' in sprite


def test_icon_sprite_has_shield_mark():
    sprite = (REPO_ROOT / "static/icons/category-icons.svg").read_text()
    assert 'id="icon-shield"' in sprite


def test_lab_css_defines_fjord_tokens_for_both_themes():
    css = (REPO_ROOT / "static/css/lab.css").read_text()
    assert '[data-bs-theme="light"] {' in css
    assert '[data-bs-theme="dark"] {' in css
    assert "--bs-body-bg: #f4f6f7;" in css
    assert "--bs-body-bg: #10151c;" in css
    assert "--fjord-accent: #19756c;" in css
    assert "--fjord-accent: #6dd3c9;" in css


def test_lab_css_defines_font_faces_and_animation():
    css = (REPO_ROOT / "static/css/lab.css").read_text()
    assert '@font-face' in css
    assert '"IBM Plex Sans"' in css
    assert '"IBM Plex Mono"' in css
    assert "@keyframes fjord-fill" in css
    assert ".fjord-fill" in css
    assert "prefers-reduced-motion" in css
