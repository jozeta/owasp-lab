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


@a06_bp.route("/")
def overview():
    return render_template("a06_vulnerable_components/overview.html")


@a06_bp.route("/component-inventory")
def component_inventory():
    # VULNERABLE: a leftover internal "component inventory" page, meant for
    # an ops dashboard, reachable by anyone with no authentication at all --
    # it hands an attacker exactly what they need before searching a CVE
    # database for each exact version.
    component_versions = {
        "Flask": version("flask"),
        "jQuery (Legacy Widgets bundle)": "1.12.4",
        "Lodash (Legacy Widgets bundle)": "4.17.11",
        "Python": platform.python_version(),
    }
    return render_template(
        "a06_vulnerable_components/component_inventory.html",
        component_versions=component_versions,
    )


@a06_bp.route("/legacy-widgets")
def legacy_widgets():
    return render_template("a06_vulnerable_components/legacy_widgets.html")


@a06_bp.route("/comment-preview")
def comment_preview():
    return render_template("a06_vulnerable_components/comment_preview.html")


@a06_bp.route("/notification-preferences")
def notification_preferences():
    return render_template("a06_vulnerable_components/notification_preferences.html")


@a06_bp.route("/account-preview")
def account_preview():
    return render_template("a06_vulnerable_components/account_preview.html")


@a06_bp.route("/admin-tools-panel")
def admin_tools_panel():
    return render_template("a06_vulnerable_components/admin_tools_panel.html")


@a06_bp.route("/thumbnail-generator", methods=["GET", "POST"])
def thumbnail_generator():
    output = None
    error = None
    proof = None
    if request.method == "POST":
        os.makedirs(THUMBNAILS_DIR, exist_ok=True)
        image = request.files.get("image")
        if image and image.filename:
            input_path = os.path.join(THUMBNAILS_DIR, image.filename)
            image.save(input_path)
            output_path = os.path.join(THUMBNAILS_DIR, "thumbnail.png")
            try:
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
            except Exception as e:
                error = str(e)
            if os.path.exists(IMAGETRAGICK_PROOF_PATH):
                with open(IMAGETRAGICK_PROOF_PATH) as f:
                    proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator.html",
        output=output,
        error=error,
        proof=proof,
    )


@a06_bp.route("/thumbnail-generator-filtered", methods=["GET", "POST"])
def thumbnail_generator_filtered():
    output = None
    error = None
    blocked = False
    proof = None
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
                try:
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
                except Exception as e:
                    error = str(e)
                if os.path.exists(IMAGETRAGICK_PROOF_PATH):
                    with open(IMAGETRAGICK_PROOF_PATH) as f:
                        proof = f.read()
    return render_template(
        "a06_vulnerable_components/thumbnail_generator_filtered.html",
        output=output,
        error=error,
        blocked=blocked,
        proof=proof,
    )
