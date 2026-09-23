from flask import Blueprint

a10_bp = Blueprint(
    "a10_ssrf", __name__, template_folder="templates", url_prefix="/a10"
)

from app.categories.a10_ssrf import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a10_ssrf",
        short_id="A10",
        title="Server-Side Request Forgery",
        blurb="A URL field the server fetches on your behalf, an unrestricted scheme, or a blocklist/allowlist with a gap wide enough to reach an internal-only endpoint that should never have been visible from outside.",
        blueprint_name="a10_ssrf",
        overview_endpoint="a10_ssrf.overview",
        examples=[
            ExampleNav(
                id="webhook-internal-metadata",
                title="Webhook Tester Reaches Internal Metadata Endpoint",
                group="Unrestricted Server-Side Fetch",
                difficulty="Easy",
                endpoint="a10_ssrf.webhook_tester",
                hints=[
                    "This form fetches whatever URL you give it, server-side, with no restriction on the destination. Think about what other addresses the SERVER itself can reach that you, as an outside visitor, normally cannot.",
                    "The server can always reach itself over its own loopback interface — and the internal metadata endpoint at /a10/internal/metadata only trusts requests that arrive from 127.0.0.1.",
                    "Submit http://127.0.0.1:5000/a10/internal/metadata as the webhook URL — the server fetches it on your behalf and shows you the response, including fake access-key/secret-key data an internal-only endpoint was never meant to expose.",
                ],
            ),
            ExampleNav(
                id="fetch-based-port-scan",
                title="Same Fetcher Enables Internal Port Scanning",
                group="Unrestricted Server-Side Fetch",
                difficulty="Medium",
                endpoint="a10_ssrf.port_scan_demo",
                hints=[
                    "This page teaches a different use of the SAME unrestricted fetch you already found in Webhook Tester. What can you learn about the internal network just from how a request to a DIFFERENT internal port behaves?",
                    "A port with something listening behaves differently (returns content) than a port with nothing listening (connection refused) — even without understanding the internal service's protocol at all.",
                    "In the Webhook Tester, submit http://127.0.0.1:5000/a10/internal/metadata (real service, responds) and then http://127.0.0.1:9999/ (nothing listening, immediate connection error) — comparing the two responses lets you map which internal ports are open, one request at a time.",
                ],
            ),
            ExampleNav(
                id="file-scheme-local-read",
                title="PDF Generator Reads Local Files via file:// URL",
                group="Unsafe URL Scheme Handling",
                difficulty="Easy",
                endpoint="a10_ssrf.pdf_generator",
                hints=[
                    "This 'PDF generator' fetches whatever URL you give it and renders the response. urllib's urlopen() supports more than just http:// and https:// — what other URL schemes might it accept?",
                    "Python's urllib supports the file:// scheme, which reads a local file directly off the server's own filesystem instead of making a network request at all.",
                    "Submit a file:// URL pointing at a file on the server (the page itself shows you the exact local path to try) as the 'page URL' — the server reads and returns that local file's contents instead of fetching a web page.",
                ],
            ),
            ExampleNav(
                id="blocklist-alternate-ip-bypass",
                title="Alternate IP Representation Bypasses a Naive Blocklist",
                group="Blocklist Bypass Techniques",
                difficulty="Medium",
                endpoint="a10_ssrf.import_avatar",
                hints=[
                    "This form blocks the literal strings '127.0.0.1' and 'localhost'. Is there more than one way to write the loopback address that doesn't contain either of those exact strings?",
                    "IP addresses can be written in several equivalent forms — decimal integer, hexadecimal, or a shortened dotted form — that all resolve to the exact same address but don't match a blocklist doing exact string comparison.",
                    "Try http://2130706433:5000/a10/internal/metadata (decimal form of 127.0.0.1) or http://0x7f000001:5000/a10/internal/metadata (hex form) or http://127.1:5000/a10/internal/metadata (short form) as the avatar URL — none of these contain the strings '127.0.0.1' or 'localhost', so the blocklist never blocks them, but they all resolve to the same loopback address.",
                ],
            ),
            ExampleNav(
                id="blocklist-redirect-bypass",
                title="Open Redirect Bypasses a Trusted-Domain Allowlist",
                group="Blocklist Bypass Techniques",
                difficulty="Hard",
                endpoint="a10_ssrf.mirror_fetcher",
                hints=[
                    "This form only allows fetching from trusted-mirror.example — checked once, before the request is made. What happens if the URL you submit is allowed, but it doesn't serve the final content itself?",
                    "urlopen() follows HTTP redirects automatically by default, and this code never re-checks the Location header's destination against the allowlist — only the URL you originally submitted gets checked.",
                    "You need a domain that resolves to trusted-mirror.example (e.g. by editing your own /etc/hosts to point trusted-mirror.example at a server you control) and a server at that address that responds with an HTTP redirect (a 3xx status plus a Location header) pointing at the real internal target.",
                    "Point /etc/hosts's trusted-mirror.example entry at 127.0.0.1, run a small local HTTP server that responds to any request with a 302 redirect to http://127.0.0.1:5000/a10/internal/metadata, then submit http://trusted-mirror.example:8080/ (or wherever your redirect server listens) as the mirror URL — the allowlist check passes on the original hostname, but the fetch itself follows the redirect straight to the internal endpoint.",
                ],
            ),
        ],
    )
)
