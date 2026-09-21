from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db

# "dana" is the single-target account for the brute-force example.
# "morgan"/"priya"/"theo" are the multi-account set for the
# credential-stuffing example (Task 2) -- seeded together here so a
# single seed_fn call sets up every A07 example's account data at once.
SEED_ACCOUNTS = [
    ("dana", "welcome1"),
    ("morgan", "Summer2023!"),
    ("priya", "letmein123"),
    ("theo", "qwerty1!"),
]


def seed_a07_accounts():
    if A07Account.query.count() == 0:
        for username, password in SEED_ACCOUNTS:
            db.session.add(
                A07Account(
                    username=username,
                    password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
                )
            )
        db.session.commit()
