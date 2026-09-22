import urllib.request

from flask import Response, abort, render_template, request

from app.categories.a10_ssrf import a10_bp


@a10_bp.route("/")
def overview():
    return render_template("a10_ssrf/overview.html")


@a10_bp.route("/internal/metadata")
def internal_metadata():
    # VULNERABLE from the attacker's point of view, but INTENTIONALLY
    # restrictive here: only requests that arrive from localhost are
    # trusted. This is what every A10 example exploits -- the vulnerable
    # routes' own outbound fetches arrive here via the loopback interface,
    # inheriting a trust boundary an external attacker could never cross
    # directly.
    if request.remote_addr != "127.0.0.1":
        abort(403)
    return Response(
        "instance-id: i-0a1b2c3d4e5f6g7h8\n"
        "iam-role: training-lab-admin\n"
        "access-key: AKIAFAKESSRFPROOF1234\n"
        "secret-key: fake-secret-do-not-use-ssrf-proof-9f3c2b1a\n",
        mimetype="text/plain",
    )


@a10_bp.route("/webhook-tester", methods=["GET", "POST"])
def webhook_tester():
    result = None
    error = None
    webhook_url = ""
    if request.method == "POST":
        webhook_url = request.form.get("webhook_url", "")
        try:
            # VULNERABLE: fetches whatever URL the client supplies, with no
            # validation of scheme, host, or destination at all.
            with urllib.request.urlopen(webhook_url, timeout=5) as resp:
                result = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            error = f"Could not reach webhook URL: {e}"
    return render_template(
        "a10_ssrf/webhook_tester.html",
        webhook_url=webhook_url,
        result=result,
        error=error,
    )


@a10_bp.route("/port-scan-demo")
def port_scan_demo():
    return render_template("a10_ssrf/port_scan_demo.html")
