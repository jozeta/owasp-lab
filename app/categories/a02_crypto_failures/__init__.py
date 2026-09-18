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
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
