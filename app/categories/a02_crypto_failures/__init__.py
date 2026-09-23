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
        ],
        seed_fn=seed_legacy_credentials,
    )
)
