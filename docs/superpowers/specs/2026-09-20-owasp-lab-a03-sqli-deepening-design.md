# OWASP Top 10 Training Lab — A03 SQL Injection Deepening Design Spec

Date: 2026-09-20
Status: Approved
Sub-project 6d of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall): quick fixes → UI/infra polish → sidebar regrouping → content retrofit →
UI polish round 2 → A03 expansion (XXE (done) → SSTI (done) → LDAP (done) →
**SQLi deepening (this spec)** → XSS deepening → CMD-injection deepening) →
progress tracking & stats.

## Purpose

Deepen the existing SQL injection coverage under A03 with two new, purely
additive examples covering a new clause type (ORDER BY), a new injection
context (numeric, not string), and a new blind technique (boolean, not
time-based) — plus a new reusable "multi-task with solutions" content
pattern, piloted here and intended for reuse by the still-to-come XSS and
command-injection deepening sub-projects. This is the fourth of six A03
injection sub-projects (XXE, SSTI, LDAP done; SQLi deepening this one, then
XSS and CMD-injection deepening).

## Decisions from brainstorming

- **Purely additive — the three existing SQLi examples
  (`sqli-login`/Easy, `union-exfiltration`/Medium, `blind-sqli`/Hard) are
  completely untouched.** Confirmed with you before proceeding: this
  matches the low-regression-risk, additive-only pattern every A03
  sub-project has used so far. A new, separate model/table is used for
  the new examples' seed data rather than expanding the existing
  `InjectionAccount` table — `tests/test_a03_data.py` hardcodes
  `InjectionAccount.query.count() == 2`, so growing that table's seed
  data in place would have broken an existing, currently-passing test.
- **The "multiple distinct tasks per example with published solutions"
  content pattern is designed now, as a reusable base-template addition**
  (not deferred to its own separate sub-project, and not designed
  one-off just for SQLi) — confirmed with you, since XSS-deepening and
  CMD-injection-deepening (both still to come) will want to reuse it
  without redesigning. See Components §1.
- **A real technical finding, live-verified before finalizing this
  spec, not assumed:** `sqlmap` was installed and run against this
  project's actual Docker-backed Postgres instance, targeting the
  *existing* `blind-sqli` (`/a03/check-username`) example. It found and
  confirmed the time-based blind injection automatically in under 20
  seconds with zero tuning (`--batch --technique=T --level=1 --risk=1`).
  This means the existing Hard example does NOT, on its own, meaningfully
  justify "requires sqlmap" — a human with a browser could eventually
  replicate the same discovery, just slower. The new flagship example
  (Components §3) is deliberately designed to need real automation: a
  large row/column count to extract via nothing but a boolean
  found/not-found oracle, where manual character-by-character extraction
  is genuinely impractical (hundreds of individual probes), not just
  slow.
- **The new flagship example uses a *numeric* injection context and a
  *boolean* (not time-based) blind technique** — both genuinely new
  relative to every existing SQLi example in this project (the existing
  three are all string-context; the existing blind example is
  time-based). This avoids teaching the same lesson twice under a new
  name.
- **New seed data lives in a new model** (`Employee`, table
  `a03_employees`) — ~9 rows across a few departments, with a
  higher-value "target" row (a CEO-level salary) for the extraction
  tasks to aim at. Reuses the exact same `db.session.execute(text(query))`
  raw-interpolation vulnerable pattern already used identically in three
  existing routes in this same file — not a new mechanism requiring
  fresh live verification (unlike XXE/SSTI/LDAP, which each introduced a
  genuinely new vulnerable mechanism), just a new clause/context applied
  to the same well-proven technique.
- **Exact `sqlmap` invocation flags for the Task 3 solution are deferred
  to live verification during the implementation plan's Docker-verification
  task** — a preliminary `--dump` attempt against the existing table
  during brainstorming needed more tuning than a bare `--dump` (automatic
  column enumeration didn't succeed on the first attempt against a
  time-based-only endpoint), so the plan's own Docker task must
  determine and document the exact working invocation against the real
  new endpoint, not assume one will work out of the box.

## Components

### 1. Reusable multi-task content pattern

`app/core/templates/core/example_page_base.html` gains a new optional
`{% block tasks %}` section, following the same
`{% set X = self.block() %}{% if X|trim %}` conditional-rendering
convention already used for `vulnerable_code`/`secure_code`. Positioned
after the Exploitation section, inside the same
`{% if settings.show_exploit_instructions %}` guard as Detect/Exploitation
(so it participates in the existing teaching-toggle-off behavior and
tests identically):

```html
{% if settings.show_exploit_instructions %}
...
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
```

Each task is hand-authored HTML in the child template — matching this
codebase's established convention of hand-written content blocks, not a
data-driven loop — using Bootstrap's native `collapse` component (already
vendored, already used for the nav's mobile toggler) for a per-task
"Show solution" reveal, collapsed by default:

```html
{% block tasks %}
<ol class="list-unstyled">
  <li class="mb-4">
    <strong>Task 1: ...</strong>
    <p>...</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task1-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task1-solution">
      <div class="card card-body"><code>...</code><p>...</p></div>
    </div>
  </li>
  <!-- Task 2, Task 3, ... -->
</ol>
{% endblock %}
```

No new dependency, no new JS. This block is optional — existing examples
that don't define it render nothing extra (same `|trim` guard pattern
already protects `vulnerable_code`/`secure_code`).

### 2. New model and seed data

`app/categories/a03_injection/models.py` gains:

```python
class Employee(db.Model):
    __tablename__ = "a03_employees"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(80), nullable=False)
    salary = db.Column(db.Integer, nullable=False)
```

`app/categories/a03_injection/seed.py`'s `seed_injection_data()` gains an
idempotent seeding block (same `if Employee.query.count() == 0:` pattern
already used for the other three models in this file) for exactly these
9 rows:

| name | email | department | salary |
|---|---|---|---|
| Alice Chen | alice.chen@owasp-lab.internal | Engineering | 95000 |
| Bob Martinez | bob.martinez@owasp-lab.internal | Engineering | 98000 |
| Carol Nguyen | carol.nguyen@owasp-lab.internal | Engineering | 102000 |
| David Okafor | david.okafor@owasp-lab.internal | Finance | 88000 |
| Elena Petrova | elena.petrova@owasp-lab.internal | Finance | 91000 |
| Frank Lopez | frank.lopez@owasp-lab.internal | Support | 62000 |
| Grace Kim | grace.kim@owasp-lab.internal | Support | 65000 |
| Henry Osei | henry.osei@owasp-lab.internal | Support | 60000 |
| Morgan Reyes | morgan.reyes@owasp-lab.internal | Executive | 285000 |

Morgan Reyes (Executive, salary 285000 — distinctly larger than every
other row) is the target for the extraction tasks in Components §4.

### 3. New Medium example — Employee Roster Sort (ORDER BY injection)

`GET /a03/roster` — a "sort the employee roster" feature. Builds
`SELECT id, name, email, department FROM a03_employees ORDER BY {sort}`
via the same raw f-string interpolation pattern as every existing SQLi
example, with `sort` taken directly from a query parameter. This is the
first example in this project injecting into an ORDER BY clause rather
than a WHERE clause — the relevant techniques (column-count discovery via
`ORDER BY N`, and boolean-signaled row reordering via
`CASE WHEN (condition) THEN col1 ELSE col2 END`) are genuinely distinct
from the WHERE-clause techniques taught elsewhere, since ORDER BY never
returns new data directly — only re-orders what's already visible.

### 4. New Hard flagship example — Employee Lookup (numeric boolean-blind, multi-task, sqlmap)

`GET /a03/roster-lookup` — an "employee ID lookup" feature. Builds
`SELECT COUNT(*) FROM a03_employees WHERE id = {id}` via the same raw
f-string interpolation pattern, with `id` taken directly from a query
parameter and NOT quoted (a numeric injection context — no string
delimiter to break out of, distinct from every existing example, all of
which are string-context). The response reveals only a boolean
"Found"/"Not found" (never the actual row), making this a boolean blind
injection point — distinct from the existing Hard example's time-based
technique.

Uses the new Tasks pattern (Components §1) with three graduated tasks:

- **Task 1 (manual):** confirm the injection point exists using a single
  boolean probe pair (e.g. `id=1 OR 1=1` returns "Found", `id=1 AND 1=2`
  returns "Not found" — a discriminating true/false test, matching this
  project's established Detect-block rigor).
- **Task 2 (manual):** extract one specific value — Morgan Reyes'
  salary (`285000`) — character-by-character via boolean probes, proving
  hands-on understanding of the technique before automating it.
- **Task 3 (sqlmap-required, explicitly framed as such):** extract the
  entire roster — all ~9 rows, all 4 non-id columns. The task's prose
  states plainly that this is impractical to do manually (potentially
  hundreds of individual boolean probes) and this is exactly why
  automated tools like `sqlmap` exist — pointing `sqlmap` at this
  endpoint and letting it enumerate the whole table unattended is the
  intended solution path. The exact working `sqlmap` invocation is
  determined and documented during the implementation plan's Docker
  verification task (see Decisions above).

## Navigation

Both new examples register in the EXISTING "SQL Injection" group in
`app/categories/a03_injection/__init__.py` (not a new group — these are
explicitly a *deepening* of SQL injection, not a new vulnerability
sub-type), appended after the existing `blind-sqli` entry: `roster-sort`
(Medium) and `roster-lookup` (Hard).

## Testing

- Route-level tests for `/a03/roster`: legitimate sort works normally;
  column-count discovery via `ORDER BY N` genuinely distinguishes valid
  from invalid column counts; the `CASE WHEN` boolean-reordering payload
  genuinely changes result order based on a true/false condition.
- Route-level tests for `/a03/roster-lookup`: legitimate numeric lookup
  works; the boolean probe pair from Task 1 genuinely discriminates
  true/false; a full manual character-by-character extraction test (run
  through the real Flask test client in a loop, the same "prove it for
  real" discipline used for the LDAP sub-project's blind extraction)
  recovers Morgan Reyes' exact salary (`285000`) using only the boolean
  oracle.
- A test confirming the Tasks section only renders when
  `show_exploit_instructions` is on, matching Detect/Exploitation's
  existing toggle-off test pattern.
- Both examples' standard nav-registration test.
- Docker verification task: confirms the ORDER BY techniques work against
  the real Postgres backend, confirms the full manual-oracle extraction
  works live, and — the critical new proof this spec defers from
  brainstorming — determines and documents the exact `sqlmap` invocation
  that successfully dumps the entire `a03_employees` table against the
  real running container, genuinely recovering all seeded values
  unattended.

## Out of scope for this spec

- Any change to the three existing SQLi examples
  (`sqli-login`/`union-exfiltration`/`blind-sqli`) or their existing seed
  data/tests.
- XSS deepening and CMD-injection deepening (separate sub-projects,
  sequenced after this one — both expected to reuse the Tasks pattern
  built here without redesigning it).
- Progress tracking / Stats page (a separate, later sub-project — the
  multi-task structure here is content/UI only; tracking which tasks a
  trainee has completed is out of scope for this spec).
- Any change to XXE, SSTI, or LDAP injection examples.
