import hashlib

from app.categories.a02_crypto_failures.models import LegacyCredential
from app.core.seed import SEED_USERS
from app.extensions import db


def seed_legacy_credentials():
    if LegacyCredential.query.count() == 0:
        for entry in SEED_USERS:
            db.session.add(
                LegacyCredential(
                    username=entry["username"],
                    weak_password_hash=hashlib.md5(entry["password"].encode()).hexdigest(),
                )
            )
        db.session.commit()
