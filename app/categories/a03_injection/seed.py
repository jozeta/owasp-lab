from app.categories.a03_injection.models import Comment, InjectionAccount, Secret
from app.extensions import db


def seed_injection_data():
    if InjectionAccount.query.count() == 0:
        db.session.add(InjectionAccount(username="alice", password="alice123", is_admin=False))
        db.session.add(
            InjectionAccount(username="admin", password="sup3r-s3cret-admin-pw", is_admin=True)
        )
        db.session.commit()
    if Secret.query.count() == 0:
        db.session.add(Secret(label="Internal API Key", value="sk_live_51NxFakeKeyForTraining000"))
        db.session.add(
            Secret(label="Database Backup Location", value="s3://internal-backups/prod-db-2024.sql.gz")
        )
        db.session.commit()
    if Comment.query.count() == 0:
        db.session.add(Comment(author="Guest", body="Nice site, looking forward to more posts!"))
        db.session.commit()
