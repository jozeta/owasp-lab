from flask import request


def register_core(app):
    from app.core.auth import get_current_user
    from app.core.models import Settings
    from app.core.nav import CATEGORIES
    from app.core.views import core_bp

    app.register_blueprint(core_bp)

    @app.context_processor
    def inject_globals():
        active_category = next(
            (
                c
                for c in CATEGORIES
                if request.endpoint and request.endpoint.startswith(c.blueprint_name + ".")
            ),
            None,
        )
        return dict(
            settings=Settings.get(),
            categories=CATEGORIES,
            current_user=get_current_user(),
            active_category=active_category,
        )
