# OWASP Top 10 Training Lab — Content Retrofit Design Spec

Date: 2026-09-18
Status: Approved
Sub-project 4 of 7 in the extended post-A04 roadmap (quick fixes → UI/infra
polish → sidebar regrouping → **content retrofit** → UI polish round 2 →
A03 expansion → progress tracking & stats).

## Purpose

Deepen every existing example page (15 total across A01–A04) with a
consistent four-part teaching structure: **Explanation** (what/why, mostly
already present), **Detect** (a new, non-harmful probe that confirms the
bug exists), **Exploitation** (the existing walkthrough, expanded with a
real-world-impact narrative and, where it strengthens the lesson, a
bulk/automated escalation example), and **Vulnerable vs. Secure** (a new,
always-visible code panel scoped to this specific example, not just the
category-level comparison the Overview page already shows). This
establishes the standard every future example — A05–A10, and the A03
expansion that follows this sub-project — is built against from day one.

## Decisions from brainstorming

- **Detect is a new block**, inserted between Explanation and
  Exploitation in `core/example_page_base.html`. It answers "how would I
  first notice this without doing anything harmful" — a single safe probe
  (a stray quote, checking a status code, noting a response is
  unexpectedly fast/slow), not a full exploit.
- **Detect gates under the existing `show_exploit_instructions` toggle**,
  the same toggle as Exploitation — both are "how do I act" content, as
  opposed to Explanation's "what is this" content. No new Settings toggle
  is introduced.
- **Vulnerable vs. Secure is new and always visible** (no toggle),
  matching how the category Overview page already shows its
  category-level comparison unconditionally. Revealing the exact
  vulnerable/secure code is treated as a code-reading exercise, not a
  spoiler — consistent with the existing convention that hiding
  Explanation/Exploitation never disables the underlying bug, so showing
  the code doesn't either.
- **Exploitation gets a real-world-impact expansion**, not a replacement.
  The existing step-by-step stays; each example adds 1–2 sentences
  connecting this exact bug class to how it's actually abused at scale
  (bulk enumeration, credential stuffing, automated tooling), and — where
  it genuinely strengthens the lesson rather than padding it — a
  copy-paste-ready example of that escalation (e.g., a shell loop that
  turns a one-record IDOR into a full-table dump).
- **Scope is exactly the 15 nav-registered example pages** (the templates
  whose endpoint is set as an `ExampleNav.endpoint` — `idor.html`,
  `admin_users.html`, `account_update.html`; `credential_dump.html`,
  `encrypted_notes.html`, `forgot_password.html`; `login.html`,
  `search.html`, `greet.html`, `check_username.html`, `host_lookup.html`,
  `comments.html`; `coupon_cart.html`, `quantity_cart.html`,
  `checkout_shipping.html`). Supporting mid-flow pages with no nav entry
  of their own (`reset_password.html`, `legacy_login.html`,
  `checkout_payment.html`, `checkout_confirm.html`) keep their current
  lightweight cross-links unchanged — they're steps inside another
  example's flow, not independent examples needing their own full
  four-part structure.
- **No route or model changes.** This sub-project only touches templates
  (the shared base + the 15 example templates) and their tests. Every
  vulnerable code path stays exactly as-is — the retrofit teaches around
  the existing bugs, it doesn't touch them.

## Template change

`app/core/templates/core/example_page_base.html` gains a Detect section
and a Vulnerable vs. Secure section:

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
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4">
  <div class="card-header">Vulnerable vs. Secure</div>
  <div class="card-body">
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
  </div>
</section>

<section class="card">
  <div class="card-header">Try It</div>
  <div class="card-body">
    {% block live_example %}{% endblock %}
  </div>
</section>
{% endblock %}
```

Every one of the 15 example templates adds two new blocks (`detect`,
already-existing blocks stay) and two new blocks (`vulnerable_code`,
`secure_code`) to its existing `{% extends %}`.

## Two worked examples (calibration for the remaining 13)

### A01 — View Another User's Profile (IDOR), Easy

Route (`app/categories/a01_access_control/routes.py:16-21`, unchanged):

```python
def idor(user_id=1):
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    profile = db.get_or_404(User, user_id)
    return render_template("a01_access_control/idor.html", profile=profile, viewer=viewer)
```

**Detect:**
> Log in, note your own id in the URL (e.g. `/a01/profile/1`), then change
> just that number by one (`/a01/profile/2`) and reload. You don't need to
> read anything on the page to detect the bug — the mere fact that you get
> a `200 OK` with *someone else's* profile at all, instead of a `403` or a
> redirect back to your own, already confirms there's no ownership check.
> That's the whole probe: no data extraction required to prove the bug
> exists.

**Exploitation (expanded):** existing 4 steps kept, plus:
> IDOR is one of the most common findings in real-world bug bounty
> reports precisely because it scales trivially: once you know the check
> is missing, there's no reason to stop at one record. A short loop turns
> a single leaked private note into the entire user table:
> ```bash
> for id in $(seq 1 50); do
>   curl -s -b "session=<your session cookie>" \
>     http://127.0.0.1:5001/a01/profile/$id \
>     | grep -o 'Private notes:[^<]*'
> done
> ```
> Run against a real production app instead of this lab, that same loop
> is a full customer-data breach — the technique behind several
> large-scale IDOR disclosures has been exactly this: iterate a numeric
> ID, harvest whatever comes back.

**Vulnerable vs. Secure:**
```python
# Vulnerable
def idor(user_id=1):
    viewer = get_current_user()
    profile = db.get_or_404(User, user_id)
    return render_template("idor.html", profile=profile, viewer=viewer)

# Secure
def idor(user_id=1):
    viewer = get_current_user()
    if user_id != viewer.id and not viewer.is_admin:
        abort(403)
    profile = db.get_or_404(User, user_id)
    return render_template("idor.html", profile=profile, viewer=viewer)
```

### A03 — Blind Time-Based SQL Injection, Hard

Route (`app/categories/a03_injection/routes.py:61-69`, unchanged):

```python
def check_username():
    username = request.args.get("username", "")
    exists = None
    if username:
        # VULNERABLE: raw string-concatenated SQL, no parameterization
        query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
        count = db.session.execute(text(query)).scalar()
        exists = bool(count)
    return render_template("a03_injection/check_username.html", username=username, exists=exists)
```

**Detect:**
> Enter a single quote on its own, `'`, and submit. A parameterized query
> would just search for a username containing a literal quote and find
> nothing unusual; this one throws a database error (or, depending on how
> the app handles it, silently misbehaves) because the quote breaks out
> of the string literal in the raw SQL. That single character — no
> payload, no timing, no data read — is enough to confirm the input
> reaches the query unescaped.

**Exploitation (expanded):** existing 3 steps + portability note kept, plus:
> Blind and time-based SQL injection is the technique behind fully
> automated database takeovers in the wild — tools exist specifically
> because doing this one bit at a time by hand doesn't scale to a real
> schema. A single confirmed timing injection point like this one is
> often enough to justify pointing `sqlmap` at the endpoint and letting
> it enumerate the entire database, table by table, column by column,
> unattended — turning one manual timing test into a complete data
> exfiltration with no further human input required.

**Vulnerable vs. Secure:**
```python
# Vulnerable
query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
count = db.session.execute(text(query)).scalar()

# Secure
query = text("SELECT COUNT(*) FROM injection_accounts WHERE username = :username")
count = db.session.execute(query, {"username": username}).scalar()
```

## Remaining 13 examples

The implementation plan authors the same four-part structure for the
remaining 13 examples directly (admin_users, account_update;
credential_dump, encrypted_notes, forgot_password; login, search, greet,
host_lookup, comments; coupon_cart, quantity_cart, checkout_shipping),
each grounded in that example's actual route code (read fresh at
plan-writing time, not assumed), matching the depth and style of the two
worked examples above:
- Detect: one safe, minimal probe specific to that bug — not a rehash of
  the existing Exploitation steps' first step.
- Exploitation: existing content kept, expanded with a real-world-impact
  sentence or two, and a copy-paste-ready bulk/automated example only
  where it teaches something the manual steps don't already show (not
  mandatory for every example — e.g. A04's design-flaw examples may not
  have a natural "automate this at scale" angle the way injection
  examples do).
- Vulnerable vs. Secure: the example's actual vulnerable line(s) from its
  route, paired with a fixed version — every one of the 15 examples has a
  clear, single-cause code fix, so this section is not optional for any
  of them (the earlier "if applicable" hedge from the original request
  turns out not to be needed once every route was actually read).

## Testing

- Every example's existing "still works with both toggles off" test
  (established convention since A02) extends to also confirm the new
  Vulnerable vs. Secure section is NOT gated (still renders with both
  toggles off), while Detect content IS hidden when
  `show_exploit_instructions` is off, alongside Exploitation.
- A new test per example confirms Detect content renders when
  `show_exploit_instructions` is on.
- A shared-template test (in `tests/test_core_views.py` or a new
  `tests/test_example_page_base.py`) confirms the base template's four
  sections appear in the right order and the Vulnerable vs. Secure
  section's markup is well-formed, independent of any specific category.

## Out of scope for this spec

- A05–A10 (not built yet — they'll use this structure from their first
  task, no retrofit needed).
- The A03 expansion (new XXE/SSI/LDAP examples, deepened SQLi/XSS/CMD) —
  sub-project 6, sequenced after this one specifically so its new
  examples are built directly in this structure.
- Progress tracking / Stats page — sub-project 7.
- Any route, model, or vulnerable-logic change.
