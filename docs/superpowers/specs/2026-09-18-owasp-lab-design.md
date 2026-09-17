# OWASP Top 10 Training Lab — Design Spec

Date: 2026-09-18
Status: Approved (scaffold + core + A01 scope)

## Purpose

A self-contained, intentionally vulnerable Flask/Bootstrap/PostgreSQL web app
that teaches the OWASP Top 10 (2021) through an Overview page plus multiple
graduated (Easy → Medium → Hard), independently exploitable examples per
category. Modeled after OWASP WebGoat / Juice Shop / DVWA: the vulnerabilities
are the deliverable. Safety comes from network isolation (localhost-only
binding, non-root container, no real data) and an in-UI warning banner, not
from removing or watering down the vulnerable code paths.

## Decisions from brainstorming

- **No shared fictional brand.** Each category's examples are independent,
  standalone scenarios — no cross-category "ShopCo"-style narrative. Keeps
  each blueprint genuinely self-contained.
- **Shared core `User` model.** One seeded set of synthetic accounts
  (`alice`, `bob`, `carol`, `admin`) lives in `app/core/models.py` and is
  reused by every category that needs authentication/identity (A01 IDOR,
  A02 credential dump, A03 login SQLi, A07 brute-force/session). Categories
  needing extra state (comments, coupons, cart items, config blobs) define
  their own models inside their own blueprint.
- **Process depth:** full spec + plan only for scaffold + core framework +
  A01 (the reference implementation). A02–A10 extend that established
  pattern directly from the seed list in the original request, without a
  separate brainstorm/spec cycle per category.
- **Packaging:** pip + `requirements.txt` (no lockfile tooling to explain in
  a teaching repo).

## Repo layout

```
owasp-lab/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── app/
│   ├── __init__.py          # create_app() factory
│   ├── extensions.py        # db = SQLAlchemy(), etc.
│   ├── core/                # framework: never vulnerable, shared by everyone
│   │   ├── models.py        # Settings, User
│   │   ├── seed.py          # seed_database() / reset_database()
│   │   ├── views.py         # home, settings page, reset action
│   │   ├── nav.py           # CATEGORY registry (id, title, blueprint, examples + difficulty)
│   │   └── templates/core/  # base.html, nav+sidebar partials, warning banner, settings.html
│   └── categories/
│       ├── a01_access_control/
│       │   ├── __init__.py  # Blueprint
│       │   ├── routes.py    # vulnerable routes, raw/concatenated SQL where relevant
│       │   ├── models.py    # category-specific models if needed
│       │   └── templates/a01_access_control/overview.html, idor.html, ...
│       └── a02..a10/         # same shape, one directory per remaining category
└── static/
    ├── vendor/bootstrap/, mermaid/, highlightjs/   (vendored, offline)
    └── css/, js/                                    (banner dismiss-per-session, etc.)
```

Each category is a Flask Blueprint registered in `create_app()`, with its own
`templates/<category>/` namespace. `app/core` holds only framework concerns:
layout, settings, nav registry, seeding — never vulnerable logic.

## Core data model

- `Settings` (singleton row): `show_explanations: bool`,
  `show_exploit_instructions: bool`. Read on every request via a Flask
  context processor so templates use `{% if settings.show_explanations %}`.
- `User`: `id, username, email, password_hash` plus whatever a given
  category's *vulnerable* code path chooses to do with it (e.g. A02's easy
  example reads/writes the column as plaintext or MD5 on purpose — that's
  the vulnerability, not a framework concern).
- `seed.py` seeds the shared users, then calls each registered category's own
  optional `seed()` hook so categories own their own seed data. "Reset lab"
  on the Settings page truncates and re-runs seeding.

## Shared UI framework

- `base.html`: dismissible-per-session warning banner (sessionStorage-backed
  Bootstrap alert stating this is an intentionally vulnerable lab that must
  never be exposed to an untrusted network), top navbar from the
  `CATEGORIES` registry (A01–A10), and — when a category is active — a left
  sidebar with Overview first, then that category's examples with a
  difficulty badge (Easy/Medium/Hard).
- `core/overview.html` base template: sections for What it is / Why it
  matters / How it's exploited / Real-world impact, a Mermaid attack-flow
  diagram block, and vulnerable-vs-secure code panels via highlight.js. Each
  category's `overview.html` extends this and fills in the blocks.
- `core/example_page.html` base template: renders two independently toggled
  sections — Explanation and Exploitation — driven by
  `settings.show_explanations` / `settings.show_exploit_instructions`.
  The vulnerable form/UI itself always renders regardless of toggle state.
  Each example template extends this, supplying its explanation text,
  exploit steps/payloads, and the live vulnerable markup/logic.
- Bootstrap 5, Mermaid, highlight.js vendored under `static/vendor/`,
  referenced via local `<link>`/`<script>` tags — no CDN, fully offline.

## Docker / compose

- `Dockerfile`: `python:3.12-slim`, non-root `appuser`, installs
  `requirements.txt`, runs via `gunicorn`.
- `docker-compose.yml`: `app` service (depends_on postgres healthy, env from
  `.env`) + `postgres` service (official image, named volume, healthcheck).
  Only `app`'s port is published to the host, bound to `127.0.0.1:5000`.
  Postgres publishes no host port.
- `.env.example`: `SECRET_KEY`, `DATABASE_URL`, `FLASK_ENV`; real `.env`
  gitignored.

## A01 Broken Access Control (reference category)

- **Overview**: explains BAC, a Mermaid sequence diagram (attacker swaps an
  ID / hits an unauthenticated admin route), and a vulnerable-vs-secure code
  panel (missing `current_user.id == resource.owner_id` check).
- **Easy — IDOR** (`/a01/profile/<int:user_id>`): renders another seeded
  user's profile (email, private notes) with no ownership check. Exploit:
  change the URL parameter.
- **Medium — Missing function-level authz** (`/a01/admin/users`): lists all
  users and lets any authenticated non-admin session flip a user's `role`
  field — the UI hides the link, but the route itself has no role check.
- **Hard — Mass assignment** (`/a01/account/update`): a profile-edit
  endpoint that blindly applies every submitted form key onto the `User`
  row (`for k, v in request.form.items(): setattr(user, k, v)`), so
  submitting `role=admin` alongside legitimate fields escalates privilege —
  mirrors real-world mass-assignment CVEs.

Each example ships independently toggle-gated Explanation and Exploitation
sections (the mass-assignment one includes a copy-pasteable curl payload).

## Verification (this phase)

`docker compose up --build` boots app + postgres, DB auto-seeds, `/` loads
with warning banner + nav, `/settings` toggles persist in the DB and visibly
hide/show explanation/exploit text on A01 pages while the underlying exploits
still work with toggles off, and all three A01 exploits are manually verified
end-to-end (curl and/or browser).

## Out of scope for this spec

A02–A10 category content (already fully enumerated in the original request's
seed list) is implemented directly against the pattern established here, not
re-specified per category.
