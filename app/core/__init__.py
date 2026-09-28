from flask import current_app, request


def register_core(app):
    from app.core.auth import get_current_user
    from app.core.models import ExampleProgress, Settings, compute_points
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
        current_example = next(
            (e for c in CATEGORIES for e in c.examples if e.endpoint == request.endpoint),
            None,
        )
        viewer = get_current_user()
        if viewer is None:
            progress_rows = {}
        else:
            progress_rows = {
                p.example_id: p for p in ExampleProgress.query.filter_by(user_id=viewer.id).all()
            }
        completed_example_ids = {
            example_id
            for example_id, p in progress_rows.items()
            if p.completed_at is not None
        }
        if current_example is not None and current_example.id in progress_rows:
            current_progress = progress_rows[current_example.id]
        else:
            current_progress = ExampleProgress(hints_used=0, completed_at=None, points_awarded=None)
        current_example_pending_points = (
            compute_points(current_example, current_progress.hints_used)
            if current_example is not None
            else None
        )
        nav_score_earned = sum(
            p.points_awarded or 0 for p in progress_rows.values() if p.completed_at is not None
        )
        nav_score_max = sum(e.base_points() for c in CATEGORIES for e in c.examples)
        return dict(
            settings=Settings.get(),
            categories=sorted(CATEGORIES, key=lambda c: c.short_id),
            current_user=viewer,
            active_category=active_category,
            registered_endpoints=set(current_app.view_functions.keys()),
            current_example=current_example,
            completed_example_ids=completed_example_ids,
            current_progress=current_progress,
            current_example_pending_points=current_example_pending_points,
            nav_score_earned=nav_score_earned,
            nav_score_max=nav_score_max,
        )
