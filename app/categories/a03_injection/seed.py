from app.categories.a03_injection.models import Comment, Employee, InjectionAccount, Secret
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
    if Employee.query.count() == 0:
        db.session.add_all(
            [
                Employee(
                    name="Alice Chen",
                    email="alice.chen@owasp-lab.internal",
                    department="Engineering",
                    salary=95000,
                ),
                Employee(
                    name="Bob Martinez",
                    email="bob.martinez@owasp-lab.internal",
                    department="Engineering",
                    salary=98000,
                ),
                Employee(
                    name="Carol Nguyen",
                    email="carol.nguyen@owasp-lab.internal",
                    department="Engineering",
                    salary=102000,
                ),
                Employee(
                    name="David Okafor",
                    email="david.okafor@owasp-lab.internal",
                    department="Finance",
                    salary=88000,
                ),
                Employee(
                    name="Elena Petrova",
                    email="elena.petrova@owasp-lab.internal",
                    department="Finance",
                    salary=91000,
                ),
                Employee(
                    name="Frank Lopez",
                    email="frank.lopez@owasp-lab.internal",
                    department="Support",
                    salary=62000,
                ),
                Employee(
                    name="Grace Kim",
                    email="grace.kim@owasp-lab.internal",
                    department="Support",
                    salary=65000,
                ),
                Employee(
                    name="Henry Osei",
                    email="henry.osei@owasp-lab.internal",
                    department="Support",
                    salary=60000,
                ),
                Employee(
                    name="Morgan Reyes",
                    email="morgan.reyes@owasp-lab.internal",
                    department="Executive",
                    salary=285000,
                ),
            ]
        )
        db.session.commit()
