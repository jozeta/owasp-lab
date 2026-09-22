from flask import render_template, request, session

from app.categories.a09_logging_monitoring_failures import a09_bp
from app.categories.a09_logging_monitoring_failures.models import SecurityEvent
from app.extensions import db

DEMO_USERNAME = "demo"
DEMO_PASSWORD = "demo-password"


def log_security_event(event_type, detail):
    # DB-backed so the event is visible regardless of which gunicorn
    # worker handles a later request -- mirrors A08's write_rce_proof().
    db.session.add(SecurityEvent(event_type=event_type, detail=detail))
    db.session.commit()


@a09_bp.route("/")
def overview():
    return render_template("a09_logging_monitoring_failures/overview.html")


@a09_bp.route("/security-events")
def security_events():
    events = SecurityEvent.query.order_by(SecurityEvent.logged_at.desc()).all()
    return render_template(
        "a09_logging_monitoring_failures/security_events.html", events=events
    )


@a09_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USERNAME and password == DEMO_PASSWORD:
            log_security_event("user_login_success", f"user={username}")
        else:
            # VULNERABLE: a failed login attempt is a textbook auditable
            # event -- this branch never logs anything at all, no matter
            # how many times it's hit.
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/login.html", error=error)


ADMIN_ACTIONS_SESSION_KEY = "a09_demo_users"
DEFAULT_DEMO_USERS = ["alice", "bob"]


@a09_bp.route("/admin-actions", methods=["GET", "POST"])
def admin_actions():
    users = session.get(ADMIN_ACTIONS_SESSION_KEY, list(DEFAULT_DEMO_USERS))
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "")
        if action == "create":
            if username and username not in users:
                users.append(username)
            log_security_event("admin_user_created", f"username={username}")
        elif action == "delete":
            if username in users:
                users.remove(username)
            # VULNERABLE: a destructive, high-value admin action -- the
            # exact kind of event OWASP's A09 calls out by name -- and it
            # writes nothing to the audit log at all.
        session[ADMIN_ACTIONS_SESSION_KEY] = users
    return render_template(
        "a09_logging_monitoring_failures/admin_actions.html", users=sorted(users)
    )
