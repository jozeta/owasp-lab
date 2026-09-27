from flask import Blueprint

a02_bp = Blueprint(
    "a02_crypto_failures", __name__, template_folder="templates", url_prefix="/a02"
)

from app.categories.a02_crypto_failures import routes  # noqa: E402,F401
from app.categories.a02_crypto_failures.seed import seed_legacy_credentials  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blurb="Weak or misused cryptography that exposes passwords and sensitive data instead of protecting them.",
        blueprint_name="a02_crypto_failures",
        overview_endpoint="a02_crypto_failures.overview",
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                group="Weak Hashing",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
                hints=[
                    "This page 'leaked' a dump of stored credentials. Look closely at the hash column — what hashing algorithm produces output that length and format?",
                    "These are unsalted MD5 hashes (32 hex characters, no per-user salt visible anywhere). MD5 is fast to compute and has no protection against precomputed lookup tables.",
                    "Take any hash from the dump and look it up in an online MD5 reverse-lookup / rainbow-table service, or run it through hashcat -m 0 with a wordlist — common/weak passwords crack in seconds.",
                    "Once you've recovered a plaintext password from its hash, log in with it at /a02/legacy-login using the matching username — the login route re-hashes your submitted password with the same weak MD5 and compares.",
                ],
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                group="Weak Encryption",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
                hints=[
                    "This page shows encrypted security answers, and ALSO provides a form to decrypt some ciphertext. What happens if you use that decrypt form on a ciphertext already shown on the same page?",
                    "The 'decrypt' feature has no restriction on WHOSE ciphertext it will decrypt — the encryption key is shared, and this page holds it server-side for anyone to use.",
                    "Copy the hex ciphertext shown next to any username, paste it into the 'decrypt' form, and submit — the page decrypts it and shows you that user's real security answer, no key needed on your end at all.",
                    "Even without decrypting: this is ECB mode, which encrypts identical plaintext blocks to identical ciphertext blocks. Compare the ciphertexts for two different usernames byte-for-byte — if they match, their security answers are identical, information leaked without decrypting anything.",
                ],
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
                hints=[
                    "The reset flow never shows you a token when you request one — normal secure flows do exactly this too, so that alone isn't the tell. Look instead at HOW the token is generated: is it derived from anything you already know?",
                    "The token is computed as md5(f'{username}:SOME_SALT')[:10] — a pure function of the username and a fixed, never-rotated secret. If you knew that secret, you could compute anyone's token yourself.",
                    "This example's own source discloses the exact salt used: resetSalt2024. Compute hashlib.md5(f'admin:resetSalt2024'.encode()).hexdigest()[:10] in Python.",
                    "Visit /a02/reset-password/<the token you computed> and submit a new password for the admin account — the app never checks you own that account, only that you know a valid token for it.",
                    "Confirm the takeover by logging in at /a02/legacy-login as admin with your new password.",
                ],
            ),
            ExampleNav(
                id="reset-token-api-leak",
                title="Reset Token Leaked in API Response",
                group="Token Leakage",
                difficulty="Easy",
                endpoint="a02_crypto_failures.forgot_password_api",
                hints=[
                    "This is a JSON API meant to kick off a password reset — trigger it and look closely at the full response body, not just the status code.",
                    "A real password reset should only ever send the token through email or SMS. Check whether this API's JSON response contains the token itself.",
                    "curl -X POST http://127.0.0.1:5000/a02/api/forgot-password -H \"Content-Type: application/json\" -d '{\"username\": \"admin\"}' — the response includes a resetToken field directly. Use it immediately at /a02/reset-password/<token> to take over the account, no email access needed at all.",
                ],
            ),
            ExampleNav(
                id="reset-token-referrer-leak",
                title="Reset Token Leaked via Referrer Header",
                group="Token Leakage",
                difficulty="Medium",
                endpoint="a02_crypto_failures.reset_password_referrer",
                hints=[
                    "This reset-password page is reached via a link containing your token in the URL's query string. Look at what else is on this page — does it link out anywhere?",
                    "There's a 'Security Tips' link at the bottom pointing to another page. Nothing on this page sets a Referrer-Policy header, so when a browser follows that link, it sends the full current URL — token included — as the Referer header to whatever it links to.",
                    "Click the Security Tips link on this page — the destination page reads request.headers['Referer'] and recovers your reset token without you ever giving it up directly. In a real deployment that link could point anywhere, including an attacker-controlled domain.",
                    "Exact reproduction: curl -s http://127.0.0.1:5000/a02/external-referrer-sink -H \"Referer: http://127.0.0.1:5000/a02/reset-password-referrer?token=<any token>\" — the response echoes the captured Referer header back, token and all.",
                ],
            ),
            ExampleNav(
                id="predictable-api-key",
                title="Predictable API Key via Time-Seeded PRNG",
                group="Weak Random Number Generation",
                difficulty="Hard",
                endpoint="a02_crypto_failures.generate_api_key",
                hints=[
                    "This 'generate an API key' feature uses Python's random module. Look at exactly how that module is seeded before it generates the key -- is the seed something an attacker could ever guess or observe?",
                    "The seed is random.seed(int(time.time())) -- the current Unix timestamp, to the second. random is a Mersenne Twister PRNG: given the same seed, it always produces the exact same output sequence, every time.",
                    "Note the approximate second a key was generated (in a real deployment, the HTTP response's own Date header gives an attacker this for free). Locally, re-seed random with that same integer and generate a key the same way -- try a small window of nearby seconds if you're not sure of the exact one.",
                    "One of those nearby-second guesses will reproduce the real key exactly -- no brute-force over the 32-character key space itself is needed, only over a handful of candidate timestamps, the same 'small search window' oracle pattern used elsewhere in this lab's blind-injection examples.",
                ],
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
