from app import create_app
from app.categories.a03_injection.ldap_seed import seed_ldap_data
from app.core.seed import seed_database

app = create_app()
seed_database(app)
seed_ldap_data()
