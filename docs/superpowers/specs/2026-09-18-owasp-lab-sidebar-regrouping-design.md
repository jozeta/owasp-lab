# OWASP Top 10 Training Lab — Sidebar Regrouping Design Spec

Date: 2026-09-18
Status: Approved
Sub-project 3 of 5 in the post-A04 enhancement batch (quick fixes → UI/infra
polish → **sidebar regrouping** → content retrofit → progress tracking &
stats).

## Purpose

Group each category's examples by vulnerability sub-type in the left
sidebar and the Overview page's "Examples in This Category" list, instead
of one flat difficulty-ordered list. Within each group, examples stay
ordered Easy → Hard. Applies retroactively to A01–A04 and becomes the
standing convention for A05–A10.

## Decisions from brainstorming

- **`ExampleNav.group: str` is a required field** (no default), added right
  after `title`. Every example must declare its sub-type explicitly —
  unlike `blurb` (sub-project 2), a missing group isn't a soft
  degradation (an empty tooltip); it would break the sidebar's rendering
  structure, so it's caught at construction time instead of by a
  best-effort test.
- **Group order is first-occurrence order, not alphabetical.** A new
  `CategoryNav.grouped_examples()` method partitions `examples` into
  `(group_name, [ExampleNav, ...])` pairs in the order groups first appear
  in the source list — never Jinja's `|groupby` filter, which sorts by key
  alphabetically and would take control of group ordering away from each
  category's `__init__.py`. This keeps the existing convention where a
  category's `examples=[...]` list is the single source of truth for
  display order (both which group comes first and which example within a
  group comes first).
- **Difficulty-ascending order within a group is still hand-authored**,
  exactly like difficulty order across the whole list is hand-authored
  today — no automatic sorting is introduced. A test per category asserts
  each group's difficulties are non-decreasing (Easy < Medium < Hard),
  catching an ordering mistake without adding runtime sorting logic
  nothing else needs.
- **Three of four existing categories need no reordering**, only the new
  `group=` kwarg — A01, A02, and A04 already have exactly one example per
  intended group, so their current list order is already correct group
  order. Only **A03** needs its `examples=[...]` list order changed (its
  SQLi/XSS/Command-Injection examples are currently interleaved by
  difficulty across the whole category, not clustered by sub-type).
- **Empty groups don't render.** A group header only renders if at least
  one of its examples has a registered endpoint — reusing the existing
  `registered_endpoints` guard, now checked per-group as well as
  per-example, so a category still mid-build-out (like A05–A10 will be
  while their tasks land one at a time) never shows an empty group header.

## Group assignments

| Category | Group | Examples (existing difficulty, existing order preserved within group) |
| --- | --- | --- |
| A01 | Insecure Direct Object References (IDOR) | IDOR (Easy) |
| A01 | Missing Function-Level Access Control | Hidden Admin Panel (Medium) |
| A01 | Mass Assignment | Account Update Role Escalation (Hard) |
| A02 | Weak Hashing | Leaked Credential Dump (Easy) |
| A02 | Weak Encryption | Weak Encryption / ECB Mode (Medium) |
| A02 | Predictable Tokens | Predictable Password Reset Token (Hard) |
| A03 | SQL Injection | Auth Bypass (Easy), UNION Exfiltration (Medium), Blind Time-Based (Hard) — **reordered** so these three are consecutive |
| A03 | Cross-Site Scripting (XSS) | Reflected XSS (Medium), Stored XSS (Hard) — **reordered** so these two are consecutive |
| A03 | OS Command Injection | Command Injection in Host Lookup Tool (Hard) |
| A04 | Business Logic Abuse | Unlimited Coupon Reuse (Easy), Negative Quantity Price Manipulation (Medium) |
| A04 | Workflow Bypass | Multi-Step Checkout Bypass (Hard) |

A03's new list order (by `id`): `sqli-login` (Easy), `union-exfiltration`
(Medium), `blind-sqli` (Hard), `reflected-xss` (Medium), `stored-xss`
(Hard), `command-injection` (Hard) — flat difficulty sequence becomes
`Easy, Medium, Hard, Medium, Hard, Hard` (was `Easy, Medium, Medium, Hard,
Hard, Hard`).

## Components

### 1. Data model

`app/core/nav.py`:
- `ExampleNav` gains `group: str` as a required field, positioned right
  after `title` (before `difficulty`).
- `CategoryNav` gains a method:
  ```python
  def grouped_examples(self):
      groups = {}
      order = []
      for example in self.examples:
          if example.group not in groups:
              groups[example.group] = []
              order.append(example.group)
          groups[example.group].append(example)
      return [(name, groups[name]) for name in order]
  ```
  (Python 3.7+ dicts preserve insertion order, so this needs no extra
  bookkeeping beyond the `order` list for clarity.)

### 2. Templates

- `app/core/templates/core/base.html`'s sidebar: replace the flat
  `{% for example in active_category.examples %}` loop with
  `{% for group_name, group_examples in active_category.grouped_examples() %}`,
  skip the group entirely if none of `group_examples` have a registered
  endpoint, render a small group-heading element, then loop
  `group_examples` exactly as today (same per-example markup, same
  `registered_endpoints` guard).
- `app/core/templates/core/overview_base.html`'s "Examples in This
  Category" list: same restructuring, applied to that list instead of the
  sidebar `<ul>`.

### 3. Retrofit on A01–A04

- Each category's `__init__.py`: add `group=` to every `ExampleNav(...)`
  call per the table above. A03's `examples=[...]` list is additionally
  reordered so the three group assignments listed above are correct.

### 4. Tests

- `tests/test_nav.py`: a unit test for `grouped_examples()` covering (a)
  first-occurrence group ordering with interleaved input, (b) within-group
  order preservation, (c) a single-example category (one group, one
  example).
- Each of `tests/test_a01_overview.py` through `test_a04_overview.py`:
  update (or, for A03, replace) the existing
  `[e.difficulty for e in aNN.examples]` assertion to match the (possibly
  reordered) flat list, and add a new assertion that every group's
  difficulties are non-decreasing (Easy=0 < Medium=1 < Hard=2 via a small
  local rank map — no new production code needed for this, it's test-only
  logic).
- A rendering-level test (extending existing overview-page tests) that a
  category's sidebar/overview-list HTML contains each expected group
  heading text once.

## Out of scope for this spec

- Any change to example page content, routes, or vulnerable logic
  (that's sub-project 4).
- Progress tracking / "mark as done" (sub-project 5).
- A05–A10 content — this sub-project only establishes the pattern; A05–A10
  will use `group=` from the start when they're built.
