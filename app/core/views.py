from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.auth import get_current_user
from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.core.stats import compute_user_stats
from app.extensions import db

core_bp = Blueprint("core", __name__, template_folder="templates")


def _is_safe_redirect_target(target):
    return bool(target) and target.startswith("/") and not target.startswith("//")


def _find_example(example_id):
    return next(
        (
            e
            for c in CATEGORIES
            for e in c.examples
            if e.id == example_id and e.endpoint in current_app.view_functions
        ),
        None,
    )


@core_bp.route("/")
def home():
    viewer = get_current_user()
    if viewer is None:
        progress_rows = {}
    else:
        progress_rows = {
            p.example_id: p for p in ExampleProgress.query.filter_by(user_id=viewer.id).all()
        }
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
    badges = compute_user_stats(viewer.id)["badges"] if viewer is not None else {}
    category_stats = []
    for category in sorted(CATEGORIES, key=lambda c: c.short_id):
        completed = sum(1 for e in category.examples if e.id in completed_ids)
        category_total = len(category.examples)
        earned_points = sum(
            progress_rows[e.id].points_awarded or 0
            for e in category.examples
            if e.id in completed_ids
        )
        max_points = sum(e.base_points() for e in category.examples)
        category_stats.append(
            {
                "category": category,
                "completed": completed,
                "total": category_total,
                "percent": round(completed / category_total * 100) if category_total else 0,
                "earned_points": earned_points,
                "max_points": max_points,
                "badge_earned": category.id in badges,
            }
        )
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    overall_percent = round(completed_total / total * 100) if total else 0
    earned_points_total = sum(cs["earned_points"] for cs in category_stats)
    max_points_total = sum(cs["max_points"] for cs in category_stats)
    return render_template(
        "core/home.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
        earned_points_total=earned_points_total,
        max_points_total=max_points_total,
        viewer=viewer,
    )


@core_bp.route("/leaderboard")
def leaderboard():
    valid_sorts = {"completed", "score", "streak"}
    sort = request.args.get("sort", "completed")
    if sort not in valid_sorts:
        sort = "completed"

    total_examples = sum(len(c.examples) for c in CATEGORIES)
    rows = []
    for user in User.query.order_by(User.username).all():
        stats = compute_user_stats(user.id)
        rows.append(
            {
                "user": user,
                "completed_total": stats["completed_total"],
                "score_total": stats["score_total"],
                "streak_days": stats["streak_days"],
                "badge_count": len(stats["badges"]),
            }
        )
    sort_key = {
        "completed": lambda r: r["completed_total"],
        "score": lambda r: r["score_total"],
        "streak": lambda r: r["streak_days"],
    }[sort]
    rows.sort(key=sort_key, reverse=True)

    return render_template(
        "core/leaderboard.html",
        rows=rows,
        sort=sort,
        total_examples=total_examples,
        total_badges=len(CATEGORIES),
    )


@core_bp.route("/instructor")
def instructor_view():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=url_for("core.instructor_view")))
    if viewer.role != "admin":
        abort(403)

    total_examples = sum(len(c.examples) for c in CATEGORIES)
    rows = []
    for user in User.query.order_by(User.username).all():
        stats = compute_user_stats(user.id)
        rows.append(
            {
                "user": user,
                "completed_total": stats["completed_total"],
                "score_total": stats["score_total"],
                "streak_days": stats["streak_days"],
                "badge_count": len(stats["badges"]),
                "last_active": stats["last_active"],
            }
        )
    rows.sort(key=lambda r: r["completed_total"], reverse=True)

    return render_template(
        "core/instructor.html",
        rows=rows,
        total_examples=total_examples,
        total_badges=len(CATEGORIES),
    )


@core_bp.route("/switch-user", methods=["GET", "POST"])
def switch_user():
    if request.method == "POST":
        session["user_id"] = int(request.form["user_id"])
        next_url = request.args.get("next")
        if _is_safe_redirect_target(next_url):
            return redirect(next_url)
        return redirect(url_for("core.home"))
    users = User.query.order_by(User.username).all()
    return render_template("core/switch_user.html", users=users)


@core_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return redirect(url_for("core.home"))


@core_bp.route("/settings", methods=["GET", "POST"])
def settings_page():
    settings = Settings.get()
    if request.method == "POST":
        settings.show_explanations = "show_explanations" in request.form
        new_scoring_enabled = "scoring_enabled" in request.form
        # While scoring is (or is about to be) enabled, exploit instructions
        # are always effectively hidden regardless of this checkbox's own
        # stored value (see example_page_base.html's derived-effective-value
        # check) -- so leave the stored value untouched rather than letting
        # a disabled, therefore-unsubmitted checkbox silently flip it to
        # False on save.
        if not new_scoring_enabled:
            settings.show_exploit_instructions = "show_exploit_instructions" in request.form
        settings.scoring_enabled = new_scoring_enabled
        db.session.commit()
        flash("Settings updated.")
        return redirect(url_for("core.settings_page"))
    return render_template("core/settings.html", settings=settings)


@core_bp.route("/settings/reset", methods=["POST"])
def reset_lab():
    reset_database(current_app)
    flash("Lab reset to clean state.")
    return redirect(url_for("core.settings_page"))


@core_bp.route("/force-reset")
def force_reset():
    """Safety-net reset reachable by URL alone.

    Deliberately GET, self-contained (no template inheritance), and requires
    no working nav/context processor -- if the app itself is broken and the
    normal Settings page can't be reached, this route still resets the DB
    and clears the session.
    """
    reset_database(current_app)
    session.clear()
    return Response(
        "<!doctype html><title>Lab reset</title>"
        "<p>The lab has been force-reset: the database was restored to its "
        "clean seeded state and your session was cleared.</p>"
        '<p><a href="/">Return to the lab</a></p>',
        mimetype="text/html",
    )


# No CSRF token: matches every other POST route in this app (settings_page,
# reset_lab, logout, switch_user) -- adding one only here would be
# inconsistent. Impact is low (this only flips a training checkbox) and
# the app is meant to run on 127.0.0.1 only.
@core_bp.route("/progress/toggle", methods=["POST"])
def toggle_progress():
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    viewer = get_current_user()
    if viewer is None:
        dest = url_for(example.endpoint) if example else url_for("core.home")
        return redirect(url_for("core.switch_user", next=dest))
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(user_id=viewer.id, example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(user_id=viewer.id, example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.completed_at is None:
        progress.completed_at = datetime.utcnow()
        progress.points_awarded = compute_points(example, progress.hints_used)
    else:
        progress.completed_at = None
        progress.points_awarded = None
    record_activity(viewer.id)
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/hints/reveal", methods=["POST"])
def reveal_hint():
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    viewer = get_current_user()
    if viewer is None:
        dest = url_for(example.endpoint) if example else url_for("core.home")
        return redirect(url_for("core.switch_user", next=dest))
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(user_id=viewer.id, example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(user_id=viewer.id, example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.hints_used < len(example.hints):
        progress.hints_used += 1
    record_activity(viewer.id)
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/tools")
def tools_page():
    return render_template("core/tools.html")


@core_bp.route("/about")
def about_page():
    return render_template("core/about.html")
