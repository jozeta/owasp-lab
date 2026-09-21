from app import create_app
from app.categories.a03_injection.ldap_seed import seed_ldap_data
from app.categories.a05_security_misconfiguration.internal_tool import wrap_with_debug_console
from app.core.seed import seed_database

app = create_app()
seed_database(app)
seed_ldap_data()

# `app` above stays the bare Flask object -- gunicorn.conf.py's post_fork
# hook does `from wsgi import app` and calls `app.app_context()`, which
# only exists on a real Flask app, not on the DispatcherMiddleware-wrapped
# composite below. `application` is what's actually served (see Dockerfile).
application = wrap_with_debug_console(app)
