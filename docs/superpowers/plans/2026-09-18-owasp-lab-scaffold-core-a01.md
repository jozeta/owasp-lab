# OWASP Lab: Scaffold + Core Framework + A01 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boot a working, containerized, intentionally-vulnerable Flask/Postgres lab with the shared teaching framework (nav, warning banner, Settings toggles, seed/reset) and one fully implemented reference category — A01 Broken Access Control, with all three graduated examples (IDOR, missing function-level authz, mass assignment) exploitable end-to-end.

**Architecture:** Flask app factory (`create_app`) with one Blueprint for framework/core concerns (`app/core`) and one Blueprint per OWASP category (`app/categories/a01_access_control`, more added in later plans). SQLAlchemy models for framework state (`Settings`, `User`). A `CATEGORIES` registry in `app/core/nav.py` drives the top nav + left sidebar and is appended to by each category blueprint on import. Two Jinja "base" templates (`core/overview_base.html`, `core/example_page_base.html`) are extended by every category's pages so Explanation/Exploitation visibility and diagram/code-panel structure are consistent everywhere.

**Tech Stack:** Python 3.12, Flask 3, Flask-SQLAlchemy, PostgreSQL (psycopg 3) in production / SQLite in-memory in tests, Bootstrap 5 + Mermaid + highlight.js (vendored locally), Docker + docker-compose, pytest.

**Spec:** `docs/superpowers/specs/2026-09-18-owasp-lab-design.md`

## Global Constraints

- App must bind only to `127.0.0.1` on the host (docker-compose publishes `127.0.0.1:5000:5000`; postgres publishes no host port).
- Only synthetic/dummy data — never real credentials or PII. Seed users: `alice`, `bob`, `carol`, `admin`.
- A persistent, dismissible-per-session warning banner must appear in the UI stating this is an intentionally vulnerable lab that must never be exposed to an untrusted/public network.
- The app container runs as a non-root user.
- Settings toggles (`show_explanations`, `show_exploit_instructions`) are global, persisted in the database, and apply to every example page. "Reset lab" restores the seeded clean state.
- Static assets (Bootstrap, Mermaid, highlight.js) are vendored under `static/vendor/` — no runtime CDN dependency.
- Each example page has independently toggle-gated Explanation and Exploitation sections; when hidden, the vulnerable functionality underneath still works.
- No shared fictional brand across categories (each category's examples are standalone scenarios) — but a shared core `User` model/seed data is reused by every category that needs identity.
- A02–A10 are out of scope for this plan.

---

### Task 1: Repo scaffold, Docker files, vendored static assets

**Files:**
- Create: `.gitignore`
- Create: `requirements.txt`
- Create: `.env.example`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `static/vendor/bootstrap/bootstrap.min.css`
- Create: `static/vendor/bootstrap/bootstrap.bundle.min.js`
- Create: `static/vendor/highlightjs/highlight.min.js`
- Create: `static/vendor/highlightjs/github.min.css`
- Create: `static/vendor/mermaid/mermaid.min.js`
- Create: `static/css/lab.css`
- Create: `static/js/lab.js`

**Interfaces:**
- Produces: on-disk `static/vendor/...` assets referenced by `url_for('static', filename=...)` in Task 6's `base.html`; `requirements.txt` consumed by `Dockerfile` and by local `pip install` in later tasks; `Dockerfile`/`docker-compose.yml` consumed (executed) by Task 11's end-to-end verification.

- [ ] **Step 1: Write `.gitignore`**

```
__pycache__/
*.pyc
.venv/
venv/
.env
*.egg-info/
.pytest_cache/
instance/
.DS_Store
```

- [ ] **Step 2: Write `requirements.txt`**

```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
psycopg[binary]==3.2.1
gunicorn==22.0.0
python-dotenv==1.0.1
pytest==8.2.2
```

- [ ] **Step 3: Write `.env.example`**

```
SECRET_KEY=change-me-to-a-random-value
FLASK_ENV=production
DATABASE_URL=postgresql+psycopg://lab:lab@postgres:5432/owasp_lab
```

- [ ] **Step 4: Write `Dockerfile`**

```dockerfile
FROM python:3.12-slim

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "wsgi:app"]
```

- [ ] **Step 5: Write `docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: owasp_lab
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lab -d owasp_lab"]
      interval: 5s
      timeout: 5s
      retries: 10

  app:
    build: .
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://lab:lab@postgres:5432/owasp_lab
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "127.0.0.1:5000:5000"

volumes:
  pgdata:
```

- [ ] **Step 6: Verify compose file is syntactically valid**

Run: `cp .env.example .env && docker compose config`
Expected: prints the resolved config with no errors.

- [ ] **Step 7: Download vendored static assets (pinned versions)**

```bash
mkdir -p static/vendor/bootstrap static/vendor/highlightjs static/vendor/mermaid static/css static/js

curl -sL -o static/vendor/bootstrap/bootstrap.min.css \
  https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css
curl -sL -o static/vendor/bootstrap/bootstrap.bundle.min.js \
  https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js
curl -sL -o static/vendor/highlightjs/highlight.min.js \
  https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js
curl -sL -o static/vendor/highlightjs/github.min.css \
  https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css
curl -sL -o static/vendor/mermaid/mermaid.min.js \
  https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js
```

Expected: each file downloaded and non-empty. Verify with:
`for f in static/vendor/bootstrap/*.* static/vendor/highlightjs/*.* static/vendor/mermaid/*.*; do wc -c "$f"; done`
— every file should report a size well over 1000 bytes. These files are vendored into the repo/image; the running app makes no further network calls to fetch them.

- [ ] **Step 8: Write `static/css/lab.css`**

```css
#sidebar .nav-link {
  color: #212529;
}

#sidebar .nav-link.active {
  color: #0d6efd;
}

pre code {
  font-size: 0.85rem;
}
```

- [ ] **Step 9: Write `static/js/lab.js`**

```js
document.addEventListener("DOMContentLoaded", function () {
  var banner = document.getElementById("lab-warning-banner");
  if (banner) {
    try {
      if (sessionStorage.getItem("labBannerDismissed") === "1") {
        banner.style.display = "none";
      }
    } catch (e) {
      /* sessionStorage unavailable (e.g. private mode) -- banner stays visible */
    }
  }

  if (window.hljs) {
    hljs.highlightAll();
  }
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: "default" });
  }
});

function dismissLabBanner() {
  var banner = document.getElementById("lab-warning-banner");
  if (banner) {
    banner.style.display = "none";
  }
  try {
    sessionStorage.setItem("labBannerDismissed", "1");
  } catch (e) {
    /* ignore -- dismissal just won't persist across reloads */
  }
}
```

- [ ] **Step 10: Commit**

```bash
git add .gitignore requirements.txt .env.example Dockerfile docker-compose.yml static
git commit -m "chore: scaffold repo, Docker files, and vendored static assets"
```

---

### Task 2: Flask app factory, config, extensions, health check

**Files:**
- Create: `app/config.py`
- Create: `app/extensions.py`
- Create: `app/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/test_app.py`

**Interfaces:**
- Produces: `create_app(config_object=None) -> Flask` (in `app/__init__.py`), `db = SQLAlchemy()` (in `app/extensions.py`), `Config`/`TestConfig` classes (in `app/config.py`), pytest fixtures `app` and `client` (in `tests/conftest.py`) used by every later test file.

- [ ] **Step 1: Write the failing test**

`tests/test_app.py`:
```python
def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app.py -v`
Expected: FAIL (collection error — `app` package / `create_app` don't exist yet).

- [ ] **Step 3: Write `app/config.py`**

```python
import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg://lab:lab@postgres:5432/owasp_lab"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
```

- [ ] **Step 4: Write `app/extensions.py`**

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
```

- [ ] **Step 5: Write `app/__init__.py`**

```python
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

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
```

- [ ] **Step 6: Write `tests/conftest.py`**

```python
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db


@pytest.fixture
def app():
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
```

- [ ] **Step 7: Install dependencies and run test**

Run: `python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pytest tests/test_app.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add app/config.py app/extensions.py app/__init__.py tests/conftest.py tests/test_app.py
git commit -m "feat: add Flask app factory, config, and health check endpoint"
```

---

### Task 3: Core models — Settings and User

**Files:**
- Create: `app/core/models.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Consumes: `db` from `app.extensions` (Task 2).
- Produces: `Settings` (columns: `id`, `show_explanations: bool`, `show_exploit_instructions: bool`; classmethod `Settings.get() -> Settings`, creates the singleton row if absent) and `User` (columns: `id`, `username`, `email`, `password_hash`, `display_name`, `bio`, `private_notes`, `role`) in `app.core.models`, used by every later task.

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:
```python
from app.core.models import Settings, User
from app.extensions import db


def test_settings_get_creates_and_returns_singleton(app):
    with app.app_context():
        first = Settings.get()
        second = Settings.get()
        assert first.id == second.id
        assert first.show_explanations is True
        assert first.show_exploit_instructions is True


def test_user_model_round_trips_fields(app):
    with app.app_context():
        user = User(
            username="testuser",
            email="testuser@example.test",
            password_hash="hashed-value",
            display_name="Test User",
            bio="",
            private_notes="",
            role="user",
        )
        db.session.add(user)
        db.session.commit()

        fetched = User.query.filter_by(username="testuser").first()
        assert fetched.id == user.id
        assert fetched.email == "testuser@example.test"
        assert fetched.role == "user"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.core'`.

- [ ] **Step 3: Write `app/core/models.py`**

```python
from app.extensions import db


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=True)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(show_explanations=True, show_exploit_instructions=True)
            db.session.add(settings)
            db.session.commit()
        return settings


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=False, default="")
    private_notes = db.Column(db.Text, nullable=False, default="")
    role = db.Column(db.String(20), nullable=False, default="user")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/models.py tests/test_models.py
git commit -m "feat: add core Settings and User models"
```

---

### Task 4: Nav registry

**Files:**
- Create: `app/core/nav.py`
- Create: `tests/test_nav.py`

**Interfaces:**
- Produces: `ExampleNav` dataclass (`id`, `title`, `difficulty`, `endpoint`; method `difficulty_badge_class() -> str`), `CategoryNav` dataclass (`id`, `short_id`, `title`, `blueprint_name`, `overview_endpoint`, `examples: list[ExampleNav]`, `seed_fn: Optional[Callable]`), and the module-level list `CATEGORIES: list[CategoryNav]` (starts empty; category blueprints append their own entry on import in later tasks) in `app.core.nav`.

- [ ] **Step 1: Write the failing test**

`tests/test_nav.py`:
```python
from app.core.nav import CategoryNav, ExampleNav


def test_example_nav_difficulty_badge_classes():
    easy = ExampleNav(id="x", title="X", difficulty="Easy", endpoint="core.home")
    medium = ExampleNav(id="y", title="Y", difficulty="Medium", endpoint="core.home")
    hard = ExampleNav(id="z", title="Z", difficulty="Hard", endpoint="core.home")

    assert easy.difficulty_badge_class() == "text-bg-success"
    assert medium.difficulty_badge_class() == "text-bg-warning"
    assert hard.difficulty_badge_class() == "text-bg-danger"


def test_category_nav_holds_ordered_examples():
    category = CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(id="idor", title="IDOR", difficulty="Easy", endpoint="a01_access_control.idor"),
        ],
    )
    assert category.examples[0].difficulty == "Easy"
    assert category.seed_fn is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_nav.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.core.nav'`.

- [ ] **Step 3: Write `app/core/nav.py`**

```python
from dataclasses import dataclass, field


@dataclass
class ExampleNav:
    id: str
    title: str
    difficulty: str
    endpoint: str

    def difficulty_badge_class(self) -> str:
        return {
            "Easy": "text-bg-success",
            "Medium": "text-bg-warning",
            "Hard": "text-bg-danger",
        }[self.difficulty]


@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None


CATEGORIES: list = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_nav.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/nav.py tests/test_nav.py
git commit -m "feat: add category/example nav registry"
```

---

### Task 5: Seed & reset logic, wsgi entrypoint

**Files:**
- Create: `app/core/seed.py`
- Create: `wsgi.py`
- Create: `tests/test_seed.py`

**Interfaces:**
- Consumes: `db`, `Settings`, `User` (Task 3), `CATEGORIES` (Task 4), `create_app` (Task 2).
- Produces: `SEED_USERS: list[dict]`, `seed_database(app) -> None`, `reset_database(app) -> None` in `app.core.seed`, consumed by `wsgi.py` (production startup) and by Task 6+ tests that need seeded users.

- [ ] **Step 1: Write the failing test**

`tests/test_seed.py`:
```python
from werkzeug.security import check_password_hash

from app.core.models import User
from app.core.seed import SEED_USERS, reset_database, seed_database
from app.extensions import db


def test_seed_database_creates_expected_users(app):
    seed_database(app)
    with app.app_context():
        usernames = {u.username for u in User.query.all()}
        assert usernames == {"alice", "bob", "carol", "admin"}

        admin = User.query.filter_by(username="admin").first()
        assert admin.role == "admin"

        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
        seed_alice = next(u for u in SEED_USERS if u["username"] == "alice")
        assert check_password_hash(alice.password_hash, seed_alice["password"])
        assert alice.password_hash != seed_alice["password"]


def test_seed_database_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert User.query.count() == 4


def test_reset_database_restores_clean_state(app):
    seed_database(app)
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        alice.role = "admin"
        alice.bio = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
        assert alice.bio != "tampered"
        assert User.query.count() == 4
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_seed.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.core.seed'`.

- [ ] **Step 3: Write `app/core/seed.py`**

```python
from werkzeug.security import generate_password_hash

from app.core.models import Settings, User
from app.core.nav import CATEGORIES
from app.extensions import db

SEED_USERS = [
    dict(
        username="alice",
        email="alice@example.test",
        password="alice-training-pw1",
        display_name="Alice Anderson",
        bio="Loves hiking and open source.",
        private_notes="Doctor's appointment 3pm Friday.",
        role="user",
    ),
    dict(
        username="bob",
        email="bob@example.test",
        password="bob-training-pw1",
        display_name="Bob Baker",
        bio="Coffee enthusiast, backend engineer.",
        private_notes="Gym locker PIN: 4471.",
        role="user",
    ),
    dict(
        username="carol",
        email="carol@example.test",
        password="carol-training-pw1",
        display_name="Carol Chen",
        bio="Runs the office book club.",
        private_notes="Planning a surprise party for Dave.",
        role="user",
    ),
    dict(
        username="admin",
        email="admin@example.test",
        password="admin-training-pw1",
        display_name="Site Admin",
        bio="System administrator account.",
        private_notes="Rotate backup encryption keys quarterly.",
        role="admin",
    ),
]


def seed_database(app):
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            for entry in SEED_USERS:
                db.session.add(
                    User(
                        username=entry["username"],
                        email=entry["email"],
                        password_hash=generate_password_hash(entry["password"]),
                        display_name=entry["display_name"],
                        bio=entry["bio"],
                        private_notes=entry["private_notes"],
                        role=entry["role"],
                    )
                )
            db.session.commit()
        Settings.get()
        for category in CATEGORIES:
            if category.seed_fn is not None:
                category.seed_fn()


def reset_database(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
    seed_database(app)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_seed.py -v`
Expected: PASS.

- [ ] **Step 5: Write `wsgi.py`**

```python
from app import create_app
from app.core.seed import seed_database

app = create_app()
seed_database(app)
```

- [ ] **Step 6: Commit**

```bash
git add app/core/seed.py wsgi.py tests/test_seed.py
git commit -m "feat: add seed/reset logic and wsgi entrypoint"
```

---

### Task 6: Core UI shell — base layout, auth, login, settings, reset, home page

**Files:**
- Create: `app/core/auth.py`
- Create: `app/core/views.py`
- Create: `app/core/__init__.py`
- Create: `app/core/templates/core/base.html`
- Create: `app/core/templates/core/home.html`
- Create: `app/core/templates/core/switch_user.html`
- Create: `app/core/templates/core/settings.html`
- Modify: `app/__init__.py`
- Create: `tests/test_core_views.py`
- Create: `tests/test_settings.py`

**Interfaces:**
- Consumes: `User`, `Settings` (Task 3), `CATEGORIES` (Task 4), `seed_database`, `reset_database` (Task 5).
- Produces: `get_current_user() -> User | None` in `app.core.auth`; `core_bp` Blueprint with routes `core.home` (GET `/`), `core.switch_user` (GET/POST `/switch-user`), `core.logout` (POST `/logout`), `core.settings_page` (GET/POST `/settings`), `core.reset_lab` (POST `/settings/reset`) in `app.core.views`; `register_core(app)` in `app.core` (registers `core_bp` and a context processor injecting `settings`, `categories`, `current_user`, `active_category` into every template — consumed by every template written from here on). `base.html` is written once, complete, referencing all five `core.*` endpoints — this task ships them together on purpose so no template ever references a route that doesn't exist yet.

- [ ] **Step 1: Write the failing tests**

`tests/test_core_views.py`:
```python
from app.core.models import User
from app.core.seed import seed_database


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"OWASP Top 10" in response.data


def test_switch_user_lists_seeded_users(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"alice" in response.data


def test_switch_user_sets_session_and_redirects(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id

    response = client.post("/switch-user", data={"user_id": alice_id}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Logged in as alice" in response.data


def test_logout_clears_session(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
    client.post("/switch-user", data={"user_id": alice_id})

    response = client.post("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"Logged in as alice" not in response.data
```

`tests/test_settings.py`:
```python
from app.core.models import Settings, User
from app.core.seed import seed_database


def test_settings_page_loads(client):
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"show_explanations" in response.data


def test_settings_page_updates_toggles(app, client):
    client.post("/settings", data={})
    with app.app_context():
        settings = Settings.get()
        assert settings.show_explanations is False
        assert settings.show_exploit_instructions is False

    client.post(
        "/settings",
        data={"show_explanations": "on", "show_exploit_instructions": "on"},
    )
    with app.app_context():
        settings = Settings.get()
        assert settings.show_explanations is True
        assert settings.show_exploit_instructions is True


def test_reset_lab_restores_seeded_users(app, client):
    seed_database(app)
    with app.app_context():
        from app.extensions import db

        alice = User.query.filter_by(username="alice").first()
        alice.role = "admin"
        db.session.commit()

    client.post("/settings/reset")

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core_views.py tests/test_settings.py -v`
Expected: FAIL (all routes 404 — `core_bp` doesn't exist yet).

- [ ] **Step 3: Write `app/core/auth.py`**

```python
from flask import session

from app.core.models import User


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return User.query.get(user_id)
```

- [ ] **Step 4: Write `app/core/views.py`**

```python
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import Settings, User
from app.core.seed import reset_database
from app.extensions import db

core_bp = Blueprint("core", __name__, template_folder="templates")


@core_bp.route("/")
def home():
    return render_template("core/home.html")


@core_bp.route("/switch-user", methods=["GET", "POST"])
def switch_user():
    if request.method == "POST":
        session["user_id"] = int(request.form["user_id"])
        return redirect(request.args.get("next") or url_for("core.home"))
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
        settings.show_exploit_instructions = "show_exploit_instructions" in request.form
        db.session.commit()
        flash("Settings updated.")
        return redirect(url_for("core.settings_page"))
    return render_template("core/settings.html", settings=settings)


@core_bp.route("/settings/reset", methods=["POST"])
def reset_lab():
    reset_database(current_app)
    flash("Lab reset to clean state.")
    return redirect(url_for("core.settings_page"))
```

- [ ] **Step 5: Write `app/core/__init__.py`**

```python
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
```

- [ ] **Step 6: Write `app/core/templates/core/base.html`**

```html
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}OWASP Top 10 Training Lab{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/bootstrap/bootstrap.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/highlightjs/github.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/lab.css') }}">
</head>
<body>
  <div id="lab-warning-banner" class="alert alert-danger rounded-0 mb-0 text-center py-2" role="alert">
    <strong>Intentionally vulnerable lab.</strong>
    Never expose this application to an untrusted or public network.
    <button type="button" class="btn-close float-end" aria-label="Dismiss" onclick="dismissLabBanner()"></button>
  </div>

  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="{{ url_for('core.home') }}">OWASP Top 10 Lab</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navMain">
        <ul class="navbar-nav me-auto">
          {% for category in categories %}
          <li class="nav-item">
            <a class="nav-link {% if active_category and active_category.id == category.id %}active{% endif %}"
               href="{{ url_for(category.overview_endpoint) }}">{{ category.short_id }}</a>
          </li>
          {% endfor %}
        </ul>
        <ul class="navbar-nav">
          {% if current_user %}
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
          <li class="nav-item">
            <form action="{{ url_for('core.logout') }}" method="post" class="d-inline">
              <button type="submit" class="btn btn-outline-light btn-sm">Log out</button>
            </form>
          </li>
          {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.switch_user') }}">Log in</a></li>
          {% endif %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container-fluid">
    <div class="row">
      {% if active_category %}
      <nav class="col-12 col-md-3 col-lg-2 bg-light border-end py-3" id="sidebar">
        <div class="fw-bold mb-2">{{ active_category.short_id }}: {{ active_category.title }}</div>
        <ul class="nav flex-column">
          <li class="nav-item">
            <a class="nav-link {% if request.endpoint == active_category.overview_endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(active_category.overview_endpoint) }}">Overview</a>
          </li>
          {% for example in active_category.examples %}
          <li class="nav-item d-flex justify-content-between align-items-center">
            <a class="nav-link {% if request.endpoint == example.endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
            <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
          </li>
          {% endfor %}
        </ul>
      </nav>
      {% endif %}

      <main class="{% if active_category %}col-12 col-md-9 col-lg-10{% else %}col-12{% endif %} py-4">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for message in messages %}
              <div class="alert alert-info">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
      </main>
    </div>
  </div>

  <script src="{{ url_for('static', filename='vendor/bootstrap/bootstrap.bundle.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/highlightjs/highlight.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/mermaid/mermaid.min.js') }}"></script>
  <script src="{{ url_for('static', filename='js/lab.js') }}"></script>
  {% block scripts %}{% endblock %}
</body>
</html>
```

- [ ] **Step 7: Write `app/core/templates/core/home.html`**

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category above to see its overview and graduated, exploitable examples.</p>
<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">
  {% for category in categories %}
  <div class="col">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title">{{ category.short_id }}: {{ category.title }}</h5>
        <a href="{{ url_for(category.overview_endpoint) }}" class="btn btn-outline-primary btn-sm">Open overview</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endblock %}
```

- [ ] **Step 8: Write `app/core/templates/core/switch_user.html`**

```html
{% extends "core/base.html" %}
{% block title %}Log in — OWASP Top 10 Lab{% endblock %}
{% block content %}
<h1>Choose Who You're Logged In As</h1>
<p class="text-muted">
  This lab uses a lightweight "act as" login so exploits (session, IDOR, authorization)
  behave like a real logged-in user. It is not itself a security control.
</p>
<form method="post" action="{{ url_for('core.switch_user', next=request.args.get('next')) }}">
  <div class="list-group">
    {% for user in users %}
    <button type="submit" name="user_id" value="{{ user.id }}"
            class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
      {{ user.display_name }} <span class="text-muted">@{{ user.username }}</span>
      {% if user.role == "admin" %}<span class="badge text-bg-dark">admin</span>{% endif %}
    </button>
    {% endfor %}
  </div>
</form>
{% endblock %}
```

- [ ] **Step 9: Write `app/core/templates/core/settings.html`**

```html
{% extends "core/base.html" %}
{% block title %}Settings — OWASP Top 10 Lab{% endblock %}
{% block content %}
<h1>Lab Settings</h1>
<p class="text-muted">These toggles apply globally across every category and example page.</p>

<form method="post" action="{{ url_for('core.settings_page') }}" class="mb-4">
  <div class="form-check form-switch mb-2">
    <input class="form-check-input" type="checkbox" role="switch" id="show_explanations"
           name="show_explanations" {% if settings.show_explanations %}checked{% endif %}>
    <label class="form-check-label" for="show_explanations">Show vulnerability explanations</label>
  </div>
  <div class="form-check form-switch mb-3">
    <input class="form-check-input" type="checkbox" role="switch" id="show_exploit_instructions"
           name="show_exploit_instructions" {% if settings.show_exploit_instructions %}checked{% endif %}>
    <label class="form-check-label" for="show_exploit_instructions">Show exploit instructions / PoC payloads</label>
  </div>
  <button type="submit" class="btn btn-primary">Save settings</button>
</form>

<hr>

<h2>Reset Lab</h2>
<p class="text-muted">Restores the database to its initial synthetic dataset. Use this between training sessions.</p>
<form method="post" action="{{ url_for('core.reset_lab') }}"
      onsubmit="return confirm('Reset the lab to its clean seeded state? This discards any changes made during exploitation.');">
  <button type="submit" class="btn btn-danger">Reset lab to clean state</button>
</form>
{% endblock %}
```

- [ ] **Step 10: Modify `app/__init__.py`** — register core after `db.init_app(app)`, before `return app`

```python
    db.init_app(app)

    from app.core import register_core

    register_core(app)

    @app.route("/healthz")
```

(the `@app.route("/healthz")` block and `return app` below it are unchanged)

- [ ] **Step 11: Run tests to verify they pass**

Run: `pytest tests/ -v`
Expected: all tests pass (`base.html` references `core.home`, `core.switch_user`, `core.logout`, `core.settings_page`, `core.reset_lab` — every one of them is registered by the end of this task, so no `BuildError`).

- [ ] **Step 12: Commit**

```bash
git add app/core/auth.py app/core/views.py app/core/__init__.py app/core/templates app/__init__.py \
  tests/test_core_views.py tests/test_settings.py
git commit -m "feat: add core UI shell -- login, settings, reset, home page"
```

---

### Task 7: A01 blueprint scaffold + Overview page

**Files:**
- Create: `app/categories/__init__.py`
- Create: `app/categories/a01_access_control/__init__.py`
- Create: `app/categories/a01_access_control/routes.py`
- Create: `app/core/templates/core/overview_base.html`
- Create: `app/categories/a01_access_control/templates/a01_access_control/overview.html`
- Modify: `app/__init__.py`
- Create: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: `CATEGORIES`, `CategoryNav`, `ExampleNav` (Task 4).
- Produces: `a01_bp` Blueprint mounted at `/a01` with route `a01_access_control.overview` (GET `/a01/`); appends A01's `CategoryNav` (3 examples, endpoints referencing routes added in Tasks 8–10) to `CATEGORIES` on import — consumed by the nav in `base.html` and by Tasks 8–10.

- [ ] **Step 1: Write the failing test**

`tests/test_a01_overview.py`:
```python
def test_a01_overview_renders(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Broken Access Control" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a01_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert a01.short_id == "A01"
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Hard"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a01_overview.py -v`
Expected: FAIL with 404 on `/a01/`.

- [ ] **Step 3: Write `app/categories/__init__.py`** (empty package marker)

```python
```

- [ ] **Step 4: Write `app/categories/a01_access_control/__init__.py`**

```python
from flask import Blueprint

a01_bp = Blueprint(
    "a01_access_control", __name__, template_folder="templates", url_prefix="/a01"
)

from app.categories.a01_access_control import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
            ),
        ],
    )
)
```

- [ ] **Step 5: Write `app/categories/a01_access_control/routes.py`**

```python
from flask import render_template

from app.categories.a01_access_control import a01_bp


@a01_bp.route("/")
def overview():
    return render_template("a01_access_control/overview.html")
```

(routes for `idor`, `admin_users`, `account_update` are added in Tasks 8–10)

- [ ] **Step 6: Write `app/core/templates/core/overview_base.html`**

```html
{% extends "core/base.html" %}

{% block content %}
<h1>{{ category_short_id }}: {{ category_title }}</h1>

<section class="mb-4">
  <h2>What It Is</h2>
  {% block what_it_is %}{% endblock %}
</section>

<section class="mb-4">
  <h2>Why It Matters</h2>
  {% block why_it_matters %}{% endblock %}
</section>

<section class="mb-4">
  <h2>How It's Exploited</h2>
  {% block how_exploited %}{% endblock %}
  <div class="mermaid">
{% block attack_flow_diagram %}{% endblock %}
  </div>
</section>

<section class="mb-4">
  <h2>Real-World Impact</h2>
  {% block real_world_impact %}{% endblock %}
</section>

<section class="mb-4">
  <h2>Vulnerable vs. Secure</h2>
  <div class="row">
    <div class="col-md-6">
      <h6>Vulnerable</h6>
      <pre><code class="language-python">{% block vulnerable_code %}{% endblock %}</code></pre>
    </div>
    <div class="col-md-6">
      <h6>Secure</h6>
      <pre><code class="language-python">{% block secure_code %}{% endblock %}</code></pre>
    </div>
  </div>
</section>

<section>
  <h2>Examples in This Category</h2>
  <ul class="list-group">
    {% for example in active_category.examples %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <a href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
      <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
    </li>
    {% endfor %}
  </ul>
</section>
{% endblock %}
```

- [ ] **Step 7: Write `app/categories/a01_access_control/templates/a01_access_control/overview.html`**

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A01" %}
{% set category_title = "Broken Access Control" %}
{% block title %}A01: Broken Access Control{% endblock %}

{% block what_it_is %}
<p>
  Broken Access Control means the application fails to correctly enforce who is allowed
  to view or act on which resource. The app knows <em>who you are</em> (authentication)
  but does not correctly check <em>what you're allowed to do</em> (authorization) before
  performing an action or returning data.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  It has been the #1 category in the OWASP Top 10 since 2021 because it is both extremely
  common and extremely damaging: a single missing check can expose every user's data or
  let any user perform admin actions, with no need for clever payloads.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers look for parameters that identify a resource (an ID in a URL, a hidden form
  field) and simply change them, or they browse directly to routes that exist in the code
  but aren't linked from the UI — the UI hiding a link is not the same as the server
  enforcing who may use it.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant DB as Database
    Attacker->>App: GET /profile/2 (logged in as user 7)
    App->>DB: SELECT * FROM users WHERE id = 2
    Note over App: No check that 2 == current_user.id
    DB-->>App: user 2's full record
    App-->>Attacker: user 2's private data
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include mass exposure of customer records via
  sequential ID enumeration, and account takeover via admin endpoints that were
  "hidden" in the UI but never actually protected server-side.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/profile/&lt;int:user_id&gt;")
def profile(user_id):
    user = User.query.get(user_id)
    return render_template("profile.html", user=user)
{% endblock %}

{% block secure_code %}@app.route("/profile/&lt;int:user_id&gt;")
def profile(user_id):
    if user_id != current_user.id and not current_user.is_admin:
        abort(403)
    user = User.query.get(user_id)
    return render_template("profile.html", user=user)
{% endblock %}
```

- [ ] **Step 8: Modify `app/__init__.py`** — register the A01 blueprint after `register_core(app)`

```python
    register_core(app)

    from app.categories.a01_access_control import a01_bp

    app.register_blueprint(a01_bp)

    @app.route("/healthz")
```

- [ ] **Step 9: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, including the two new A01 tests, and the full previous suite (now that `CATEGORIES` has a real entry) stays green.

- [ ] **Step 10: Commit**

```bash
git add app/categories app/core/templates/core/overview_base.html app/__init__.py tests/test_a01_overview.py
git commit -m "feat: add A01 blueprint scaffold and overview page"
```

---

### Task 8: A01 Easy — IDOR example

**Files:**
- Create: `app/core/templates/core/example_page_base.html`
- Modify: `app/categories/a01_access_control/routes.py`
- Create: `app/categories/a01_access_control/templates/a01_access_control/idor.html`
- Modify: `tests/conftest.py`
- Create: `tests/test_a01_idor.py`

**Interfaces:**
- Consumes: `get_current_user` (Task 6), `User` (Task 3).
- Produces: route `a01_access_control.idor` (GET `/a01/profile/<int:user_id>`); `login` pytest fixture in `tests/conftest.py` (factory `login(username) -> int`, seeds the DB, sets `session["user_id"]`, returns that user's id) reused by Tasks 9–10.

- [ ] **Step 1: Write the failing test**

`tests/test_a01_idor.py`:
```python
from app.core.models import Settings, User
from app.extensions import db


def test_idor_requires_login(client):
    response = client.get("/a01/profile/1")
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_idor_exposes_another_users_private_notes(app, client, login):
    login("alice")
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_notes = bob.private_notes

    response = client.get(f"/a01/profile/{bob_id}")
    assert response.status_code == 200
    assert bob_notes.encode() in response.data


def test_idor_still_leaks_data_with_teaching_text_hidden(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_notes = bob.private_notes

    response = client.get(f"/a01/profile/{bob_id}")
    assert response.status_code == 200
    assert bob_notes.encode() in response.data
    assert b"Insecure Direct Object Reference" not in response.data
    assert b"Change the URL to a different id" not in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a01_idor.py -v`
Expected: FAIL — `login` fixture doesn't exist yet, and `/a01/profile/<id>` is a 404.

- [ ] **Step 3: Modify `tests/conftest.py`** — add the `login` fixture

```python
@pytest.fixture
def login(app, client):
    def _login(username):
        from app.core.models import User
        from app.core.seed import seed_database

        seed_database(app)
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            user_id = user.id
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
        return user_id

    return _login
```

- [ ] **Step 4: Write `app/core/templates/core/example_page_base.html`**

```html
{% extends "core/base.html" %}

{% block content %}
{% set badge_classes = {"Easy": "text-bg-success", "Medium": "text-bg-warning", "Hard": "text-bg-danger"} %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
</div>

{% if settings.show_explanations %}
<section class="card mb-4">
  <div class="card-header">Explanation</div>
  <div class="card-body">
    {% block explanation %}{% endblock %}
  </div>
</section>
{% endif %}

{% if settings.show_exploit_instructions %}
<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card">
  <div class="card-header">Try It</div>
  <div class="card-body">
    {% block live_example %}{% endblock %}
  </div>
</section>
{% endblock %}
```

- [ ] **Step 5: Modify `app/categories/a01_access_control/routes.py`** — add imports and the `idor` route

```python
from flask import redirect, render_template, request, url_for

from app.categories.a01_access_control import a01_bp
from app.core.auth import get_current_user
from app.core.models import User


@a01_bp.route("/")
def overview():
    return render_template("a01_access_control/overview.html")


@a01_bp.route("/profile/<int:user_id>")
def idor(user_id):
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    profile = User.query.get_or_404(user_id)
    return render_template("a01_access_control/idor.html", profile=profile, viewer=viewer)
```

- [ ] **Step 6: Write `app/categories/a01_access_control/templates/a01_access_control/idor.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "View Another User's Profile (IDOR)" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This profile page is fetched by <code>user_id</code> alone. The server never checks
  whether the <code>user_id</code> in the URL belongs to the person who is logged in —
  it just loads whatever row matches and renders it. This is a textbook Insecure Direct
  Object Reference (IDOR).
</p>
<p>Impact here: any logged-in user can read every other user's private notes.</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> using the login page.</li>
  <li>Visit <code>/a01/profile/1</code> — this is your own profile.</li>
  <li>Change the URL to a different id, e.g. <code>/a01/profile/2</code> or
      <code>/a01/profile/4</code>, and reload.</li>
  <li>The page renders that user's private notes even though you never authenticated as them.</li>
</ol>
{% endblock %}

{% block live_example %}
<p>Logged in as:
  {% if viewer %}<strong>{{ viewer.username }}</strong> (id {{ viewer.id }})
  {% else %}<a href="{{ url_for('core.switch_user', next=request.path) }}">log in</a>{% endif %}
</p>

{% if profile %}
<div class="card">
  <div class="card-body">
    <h5 class="card-title">{{ profile.display_name }} <span class="text-muted">@{{ profile.username }}</span> (id {{ profile.id }})</h5>
    <p class="card-text">{{ profile.bio }}</p>
    <p class="card-text"><strong>Private notes:</strong> {{ profile.private_notes }}</p>
  </div>
</div>
<p class="mt-3">
  Try another id:
  {% for uid in range(1, 5) %}
  <a href="{{ url_for('a01_access_control.idor', user_id=uid) }}" class="btn btn-sm btn-outline-secondary">{{ uid }}</a>
  {% endfor %}
</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add app/core/templates/core/example_page_base.html app/categories/a01_access_control/routes.py \
  app/categories/a01_access_control/templates/a01_access_control/idor.html tests/conftest.py tests/test_a01_idor.py
git commit -m "feat: add A01 Easy IDOR example"
```

---

### Task 9: A01 Medium — missing function-level authorization

**Files:**
- Modify: `app/categories/a01_access_control/routes.py`
- Create: `app/categories/a01_access_control/templates/a01_access_control/admin_users.html`
- Create: `tests/test_a01_admin_users.py`

**Interfaces:**
- Consumes: `get_current_user`, `User`, `db` (existing).
- Produces: route `a01_access_control.admin_users` (GET/POST `/a01/admin/users`) — no role check, reachable by any logged-in session.

- [ ] **Step 1: Write the failing test**

`tests/test_a01_admin_users.py`:
```python
from app.core.models import User


def test_admin_users_reachable_by_non_admin(client, login):
    login("alice")
    response = client.get("/a01/admin/users")
    assert response.status_code == 200
    assert b"bob" in response.data


def test_admin_users_role_change_has_no_role_check(app, client, login):
    login("alice")
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        assert bob.role == "user"

    response = client.post("/a01/admin/users", data={"user_id": bob_id, "role": "admin"})
    assert response.status_code == 200

    with app.app_context():
        assert User.query.get(bob_id).role == "admin"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a01_admin_users.py -v`
Expected: FAIL with 404 on `/a01/admin/users`.

- [ ] **Step 3: Modify `app/categories/a01_access_control/routes.py`** — add the `admin_users` route

```python
from app.extensions import db


@a01_bp.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if request.method == "POST":
        target = User.query.get_or_404(int(request.form["user_id"]))
        target.role = request.form["role"]
        db.session.commit()
    users = User.query.order_by(User.username).all()
    return render_template("a01_access_control/admin_users.html", users=users, viewer=viewer)
```

- [ ] **Step 4: Write `app/categories/a01_access_control/templates/a01_access_control/admin_users.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Hidden Admin Panel" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This admin user-management page has no link anywhere in the normal navigation — but the
  route itself is reachable by anyone with a session, because the code checks "are you
  logged in?" and stops there. It never checks "are you an <em>admin</em>?" This is a
  missing function-level access control: security by obscurity, not by enforcement.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> (a regular, non-admin user).</li>
  <li>Navigate directly to <code>/a01/admin/users</code> — there is no link to it, but it loads anyway.</li>
  <li>Pick any user in the table and submit "admin" as their new role.</li>
  <li>That user now has admin privileges, granted by a non-admin session.</li>
</ol>
{% endblock %}

{% block live_example %}
<p>Logged in as:
  {% if viewer %}<strong>{{ viewer.username }}</strong> (role: {{ viewer.role }})
  {% else %}<a href="{{ url_for('core.switch_user', next=request.path) }}">log in</a>{% endif %}
</p>
{% if viewer %}
<table class="table">
  <thead><tr><th>User</th><th>Role</th><th>Set role</th></tr></thead>
  <tbody>
    {% for user in users %}
    <tr>
      <td>{{ user.username }}</td>
      <td>{{ user.role }}</td>
      <td>
        <form method="post" class="d-flex gap-2">
          <input type="hidden" name="user_id" value="{{ user.id }}">
          <select name="role" class="form-select form-select-sm" style="width:auto">
            <option value="user" {% if user.role == "user" %}selected{% endif %}>user</option>
            <option value="admin" {% if user.role == "admin" %}selected{% endif %}>admin</option>
          </select>
          <button type="submit" class="btn btn-sm btn-outline-danger">Save</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
  app/categories/a01_access_control/templates/a01_access_control/admin_users.html tests/test_a01_admin_users.py
git commit -m "feat: add A01 Medium missing-function-level-authz example"
```

---

### Task 10: A01 Hard — mass assignment role escalation

**Files:**
- Modify: `app/categories/a01_access_control/routes.py`
- Create: `app/categories/a01_access_control/templates/a01_access_control/account_update.html`
- Create: `tests/test_a01_account_update.py`

**Interfaces:**
- Consumes: `get_current_user`, `db`.
- Produces: route `a01_access_control.account_update` (GET/POST `/a01/account/update`) — blindly applies every submitted form field onto the viewer's `User` row.

- [ ] **Step 1: Write the failing test**

`tests/test_a01_account_update.py`:
```python
from app.core.models import User


def test_account_update_applies_legitimate_field(app, client, login):
    alice_id = login("alice")
    client.post("/a01/account/update", data={"display_name": "Alice Updated", "bio": "new bio"})
    with app.app_context():
        alice = User.query.get(alice_id)
        assert alice.display_name == "Alice Updated"
        assert alice.bio == "new bio"


def test_account_update_mass_assignment_escalates_role(app, client, login):
    alice_id = login("alice")
    with app.app_context():
        assert User.query.get(alice_id).role == "user"

    client.post(
        "/a01/account/update",
        data={"display_name": "Alice", "bio": "hiking", "role": "admin"},
    )

    with app.app_context():
        assert User.query.get(alice_id).role == "admin"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a01_account_update.py -v`
Expected: FAIL with 404 on `/a01/account/update`.

- [ ] **Step 3: Modify `app/categories/a01_access_control/routes.py`** — add imports and the `account_update` route

```python
from flask import flash


@a01_bp.route("/account/update", methods=["GET", "POST"])
def account_update():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if request.method == "POST":
        for key, value in request.form.items():
            if key == "id":
                continue
            setattr(viewer, key, value)
        db.session.commit()
        flash("Account updated.")
        return redirect(url_for("a01_access_control.account_update"))
    return render_template("a01_access_control/account_update.html", viewer=viewer)
```

- [ ] **Step 4: Write `app/categories/a01_access_control/templates/a01_access_control/account_update.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Account Update Role Escalation" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "update my profile" endpoint accepts a form submission and applies every field
  in it directly onto your user record — <code>for key, value in request.form.items():
  setattr(user, key, value)</code>. It was written to save the trouble of listing which
  fields are editable. The cost: any field on the model, including <code>role</code>,
  can be set by the client. This class of bug is called mass assignment.
</p>
{% endblock %}

{% block exploitation %}
<p>Log in as <strong>alice</strong>, then submit the form below with an extra field.
  The browser form only submits the visible fields, so use curl to add
  <code>role=admin</code> to the request (copy your session cookie from the browser's
  dev tools first):</p>
<pre><code class="language-bash">curl -i 'http://localhost:5000/a01/account/update' \
  -b 'session=&lt;your session cookie&gt;' \
  -d 'display_name=Alice' \
  -d 'bio=hiking' \
  -d 'role=admin'</code></pre>
<p>Reload this page afterward — your role now reads <strong>admin</strong>.</p>
{% endblock %}

{% block live_example %}
{% if viewer %}
<p>Logged in as <strong>{{ viewer.username }}</strong> — current role: <strong>{{ viewer.role }}</strong></p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">Display name</label>
    <input type="text" class="form-control" name="display_name" value="{{ viewer.display_name }}">
  </div>
  <div class="mb-2">
    <label class="form-label">Bio</label>
    <textarea class="form-control" name="bio">{{ viewer.bio }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Save profile</button>
</form>
{% else %}
<a href="{{ url_for('core.switch_user', next=request.path) }}">Log in to try this example</a>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass — this is the full test suite for the plan's scope.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
  app/categories/a01_access_control/templates/a01_access_control/account_update.html tests/test_a01_account_update.py
git commit -m "feat: add A01 Hard mass-assignment role escalation example"
```

---

### Task 11: README, docker-compose end-to-end verification

**Files:**
- Create: `README.md`

**Interfaces:**
- Consumes: everything built in Tasks 1–10.
- Produces: a documented `git clone` → `docker compose up --build` flow, and a manually-verified running container stack (no automated test — this is the plan's final integration check).

- [ ] **Step 1: Write `README.md`**

```markdown
# OWASP Top 10 Training Lab

> ⚠️ **This application is intentionally vulnerable.** It exists to teach the OWASP
> Top 10 (2021) by letting you exploit real, working vulnerabilities in a safe,
> disposable environment — modeled after OWASP WebGoat, Juice Shop, and DVWA.
> **Never expose this application to an untrusted network or the public internet.**
> Run it only on `localhost` / an isolated Docker network, on a machine you control,
> with no sensitive data anywhere near it.

## What this is

A self-contained Flask + PostgreSQL web app. The top navigation lists each OWASP
Top 10 category; each category has an Overview page (what the vulnerability class
is, why it matters, how it's exploited, real-world impact) plus multiple graduated
examples (Easy → Medium → Hard) that are genuinely exploitable, not simulated.

Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation). Remaining categories (A02–A10)
are tracked separately and follow the same pattern.

## Quick start

```bash
git clone <YOUR_GITHUB_REMOTE_URL_HERE> owasp-lab
cd owasp-lab
cp .env.example .env      # edit SECRET_KEY if you like; defaults work for local use
docker compose up --build
```

Then open <http://127.0.0.1:5000>. The database auto-seeds on first run with
synthetic accounts (`alice`, `bob`, `carol`, `admin`) — no real data is ever used.

## Settings

Visit **Settings** in the top nav to:

- Toggle whether example pages show their **Explanation** text.
- Toggle whether example pages show step-by-step **Exploitation** instructions.
- **Reset the lab** to its clean seeded state (useful between training sessions or
  between developers sharing the same instance).

Both toggles are global and stored in the database — they affect every example page
immediately for every visitor. Hiding the teaching text never disables the underlying
vulnerability; it only conceals the walkthrough, so you can attempt exploitation blind.

## Category summary

| Category | Status | Examples |
| --- | --- | --- |
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |

## Safety model

- The app container binds only to `127.0.0.1` on the host (`docker-compose.yml`
  publishes `127.0.0.1:5000:5000`); PostgreSQL publishes no host port at all.
- The app container runs as a non-root user (`appuser`).
- All data is synthetic and regenerated by "Reset lab" — there is no real user data.
- A persistent warning banner is shown in the UI at all times (dismissible for the
  current browser session only).

## Development

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest tests/ -v
```

Tests run against an in-memory SQLite database and do not require Docker or Postgres.
```

- [ ] **Step 2: Build and start the stack**

Run: `cp .env.example .env && docker compose up --build -d`
Expected: both `postgres` and `app` services report healthy/running; no errors in `docker compose logs app`.

- [ ] **Step 3: Verify health and seeding**

Run:
```bash
curl -s http://127.0.0.1:5000/healthz
docker compose exec postgres psql -U lab -d owasp_lab -c "select username, role from users order by username;"
```
Expected: `{"status": "ok"}`; the `users` query lists exactly `admin`, `alice`, `bob`, `carol` with `admin` having role `admin` and the rest `user`.

- [ ] **Step 4: Verify UI, banner, and nav**

Run: `curl -s http://127.0.0.1:5000/ | grep -i "intentionally vulnerable"`
Expected: the warning banner text is present in the served HTML.

- [ ] **Step 5: Manually verify all three A01 exploits end-to-end**

```bash
# Log in as alice and capture her session cookie
curl -s -c cookies.txt -X POST http://127.0.0.1:5000/switch-user -d "user_id=1" -o /dev/null

# IDOR: view bob's profile as alice (expect his private notes in the response)
curl -s -b cookies.txt http://127.0.0.1:5000/a01/profile/2 | grep -i "Gym locker PIN"

# Missing function-level authz: alice (non-admin) escalates bob to admin
curl -s -b cookies.txt -X POST http://127.0.0.1:5000/a01/admin/users -d "user_id=2&role=admin"
docker compose exec postgres psql -U lab -d owasp_lab -c "select username, role from users where username='bob';"
# expect role = admin

# Mass assignment: alice escalates her own role via an unexpected form field
curl -s -b cookies.txt -X POST http://127.0.0.1:5000/a01/account/update \
  -d "display_name=Alice&bio=hiking&role=admin"
docker compose exec postgres psql -U lab -d owasp_lab -c "select username, role from users where username='alice';"
# expect role = admin
```
Expected: each exploit succeeds exactly as described (private notes leaked; bob's and then alice's roles both become `admin` with no authorization check blocking it).

- [ ] **Step 6: Verify reset restores clean state**

```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:5000/settings/reset -o /dev/null
docker compose exec postgres psql -U lab -d owasp_lab -c "select username, role from users order by username;"
```
Expected: back to the original seeded roles (`admin`=admin, everyone else=user); `cookies.txt`'s session is now stale since the reset dropped and recreated the users table (a fresh `switch-user` login is required afterward — this is expected lab behavior, not a bug).

- [ ] **Step 7: Tear down and clean up local artifacts**

Run: `docker compose down && rm -f cookies.txt`
Expected: containers stop cleanly.

- [ ] **Step 8: Commit**

```bash
git add README.md
git commit -m "docs: add README with quick start, safety model, and category summary"
```
