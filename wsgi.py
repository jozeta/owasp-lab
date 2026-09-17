from app import create_app
from app.core.seed import seed_database

app = create_app()
seed_database(app)
