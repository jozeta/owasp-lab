import os

from flask import Flask

from app.config import Config, TestConfig
from app.extensions import db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app(config_object=None):
    app = Flask(
        __name__,
        static_folder=os.path.join(BASE_DIR, "static"),
        static_url_path="/static",
    )

    if config_object is None:
        config_object = TestConfig if os.environ.get("FLASK_TESTING") == "1" else Config
    app.config.from_object(config_object)

    db.init_app(app)

    from app.core import register_core

    register_core(app)

    from app.categories.a01_access_control import a01_bp

    app.register_blueprint(a01_bp)

    from app.categories.a02_crypto_failures import a02_bp

    app.register_blueprint(a02_bp)

    from app.categories.a03_injection import a03_bp

    app.register_blueprint(a03_bp)

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
