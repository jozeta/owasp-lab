from flask import Blueprint

a08_bp = Blueprint(
    "a08_integrity_failures", __name__, template_folder="templates", url_prefix="/a08"
)

from app.categories.a08_integrity_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a08_integrity_failures",
        short_id="A08",
        title="Software and Data Integrity Failures",
        blurb="Deserialized data, installed code, and signed tokens trusted without ever verifying they weren't tampered with.",
        blueprint_name="a08_integrity_failures",
        overview_endpoint="a08_integrity_failures.overview",
        examples=[
            ExampleNav(
                id="cart-pickle-tampering",
                title="Pickle Cart Tampering",
                group="Insecure Deserialization",
                difficulty="Easy",
                endpoint="a08_integrity_failures.cart",
                hints=[
                    "The cart's contents are stored client-side in a cookie. What happens if you fully control the bytes you send back — does the server ever verify they haven't been altered before trusting them?",
                    "The a08_cart cookie is just base64-encoded pickle data with no HMAC or signature attached — the server deserializes whatever it receives, no questions asked.",
                    "Craft your own pickle payload locally: python3 -c \"import pickle, base64; print(base64.b64encode(pickle.dumps({'item': 'Widget', 'price': 0.01})).decode())\" — then set your a08_cart cookie to that printed value and reload the page. The price shows $0.01, fully accepted.",
                ],
            ),
            ExampleNav(
                id="plugin-marketplace-tampering",
                title="Unsigned Plugin Content Trust",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Medium",
                endpoint="a08_integrity_failures.plugin_marketplace",
                hints=[
                    "This marketplace installs a plugin from any URL you give it. What's missing between 'fetch some code from a URL' and 'trust it's the real thing'?",
                    "There's no checksum or signature check comparing the fetched content against any known-good source — any URL serving Python-shaped text is treated as equally official.",
                    "Download both the 'official' plugin and the deliberately substituted demo plugin from this same app, compare their content, then install the substituted one via the form using its own download URL — the marketplace accepts it exactly as readily as the real one, with zero warning.",
                    "Exact URLs: install http://127.0.0.1:5000/a08/plugin-marketplace/official-plugin.py first, then http://127.0.0.1:5000/a08/plugin-marketplace/malicious-plugin-demo.py — both install identically even though their content differs.",
                ],
            ),
            ExampleNav(
                id="unchecked-signature-cookie",
                title="Unchecked Signature on Preferences Cookie",
                group="Broken Signature Verification",
                difficulty="Easy",
                endpoint="a08_integrity_failures.preferences",
                hints=[
                    "This preferences cookie includes a signature field. Does the code that reads the cookie back actually check it, or just read the other fields and move on?",
                    "A verification function for this signature exists elsewhere in the codebase — but look at where the cookie is actually parsed on page load, and check whether that verification function is ever called there.",
                    "Set your a08_prefs cookie directly to {\"theme\": \"dark\", \"premium_unlocked\": true, \"sig\": \"not-a-real-signature\"} and reload — premium unlocks despite an obviously fake signature, because the code path that reads the cookie never calls the verification function at all.",
                ],
            ),
            ExampleNav(
                id="jwt-alg-none-bypass",
                title="JWT alg:none Signature Bypass",
                group="Broken Signature Verification",
                difficulty="Medium",
                endpoint="a08_integrity_failures.admin_api",
                hints=[
                    "This token's verifier decides HOW to check the signature based on something inside the token itself. What happens if the token gets to choose 'don't check anything'?",
                    "The verifier reads the algorithm to use from the token's own header field rather than always expecting one fixed algorithm — an attacker who crafts their own header controls how their own token gets verified.",
                    "Build a token with header {\"alg\": \"none\", \"typ\": \"JWT\"} and a payload claiming an admin role, base64url-encode each part, and join them with dots — but leave the signature segment empty, since alg:none means no signature is checked at all.",
                    "In Python: header = b64url(json.dumps({'alg':'none','typ':'JWT'}).encode()); payload = b64url(json.dumps({'user':'attacker','role':'admin'}).encode()); submit f'{header}.{payload}.' (note the trailing dot — empty signature) to the admin API form. The verifier sees alg:none in the header and skips verification entirely, exactly as instructed.",
                ],
            ),
            ExampleNav(
                id="cart-pickle-rce",
                title="Pickle Deserialization RCE",
                group="Insecure Deserialization",
                difficulty="Hard",
                endpoint="a08_integrity_failures.cart_rce_demo",
                hints=[
                    "The Easy-tier cart example proved you can tamper with pickled data. Pickle's real danger goes deeper than data tampering — what does a Python object's __reduce__ method control during unpickling?",
                    "__reduce__ tells pickle 'to reconstruct me, call this function with these arguments' — and pickle calls that function the moment pickle.loads() runs, on the server, not in your own process.",
                    "Define a class whose __reduce__ method returns a tuple of (some_callable, (args,)) — when the server deserializes an instance of that class from your cookie, it calls that function with those arguments as part of loading, not construction.",
                    "This page already plants a crafted cookie for you (its raw value is shown in the exploitation section), built from a class whose __reduce__ returns (write_rce_proof, (\"PWNED-VIA-PICKLE-RCE\",)). Simply visit /a08/cart next — the same vulnerable deserialize_cart() from the Easy-tier example processes your cookie, and the function call inside __reduce__ genuinely executes, confirmable on the RCE Proof page.",
                ],
            ),
            ExampleNav(
                id="plugin-marketplace-rce",
                title="Unsigned Plugin Installation Leads to RCE",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Hard",
                endpoint="a08_integrity_failures.plugin_marketplace_rce_demo",
                hints=[
                    "The Medium-tier plugin-marketplace example proved the marketplace installs unverified content. This route doesn't just display what it fetches though — check what it actually does with the plugin source after downloading it.",
                    "'Installing' a plugin here means calling exec() on its fetched source immediately, with no checksum check — so installing isn't just trusting untrusted content, it's running it with full application privileges.",
                    "Install the substituted plugin demo (http://127.0.0.1:5000/a08/plugin-marketplace/malicious-plugin-demo.py) at /a08/plugin-marketplace exactly as in the Medium-tier example — its source contains a call that writes an RCE proof, and because installing means executing, that call genuinely runs. Confirm it on the RCE Proof page.",
                ],
            ),
        ],
    )
)
