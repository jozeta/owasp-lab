# Second-Order SQL Injection & Insecure File Upload Additions — Design

## Goal

Add 3 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab, bringing the app from 100 to 103 examples:

1. **Second-Order SQL Injection via Department Report** — A03 Injection, joins the existing "SQL Injection" group.
2. **Path Traversal via Unsanitized Avatar-Upload Filename** — A01 Broken Access Control, joins the existing "Path Traversal" group.
3. **Stored XSS via Untrusted SVG Upload** — A03 Injection, new "Insecure File Upload" group.

This is the seventh PayloadsAllTheThings-derived round in this project. Prior rounds (all merged to `main`) took the app from 63 → 100 examples across six rounds. This round covers 9 reference sources the user supplied in one batch: 8 PayloadsAllTheThings pages (Race Condition, SQL Injection/PostgreSQL Injection, Server Side Include Injection, Server Side Template Injection, Upload Insecure Files, XSS Injection, XXE Injection, Zip Slip) plus one external article (dev.to, general SQL injection).

## Triage Summary

Each of the 9 sources was researched independently (fetched fresh, cross-checked against the app's ACTUAL current routes/models — not assumed from titles) and triaged against the existing 100-example baseline. Decisions below reflect the user's explicit choices via `AskUserQuestion`, not automatic acceptance.

| Source | Verdict | Reasoning |
|---|---|---|
| PostgreSQL Injection + dev.to SQLi article | **Accepted — Second-Order SQLi only** | A03 already has 7 SQLi examples (auth bypass, UNION, ORDER BY, error-based, blind, numeric blind, stacked-query RCE). Two non-duplicate candidates surfaced: a dollar-quoting/`CHR()` WAF-bypass technique, and second-order SQLi. User picked second-order only. |
| Server Side Include Injection | **Declined — infeasible** | SSI (`<!--#exec-->`, `<!--#include-->`) is interpreted by the web server itself (Apache mod_include / Nginx SSI module), never by the application framework. This app's `Dockerfile`/`docker-compose.yml` run gunicorn+Flask directly with no Apache/Nginx layer — confirmed by reading both files fresh. No ESI-capable proxy either. The closest legitimate analog (file-inclusion → template execution) is already implemented as `file-inclusion-lfi-ssti` (A03, existing). Matches this project's round-3 precedent of declining CRLF Injection as infeasible against Werkzeug's real HTTP handling. |
| Server Side Template Injection | **Declined — user chose to skip** | A03 already has 3 SSTI-adjacent examples (`ssti-email-preview`, `ssti-blacklist-bypass`, `file-inclusion-lfi-ssti`), all using the "Rendered" detection technique. A genuinely novel candidate (blind/time-based SSTI, a different DETECTION technique) exists but requires building a whole new feature (e.g. async email/invoice rendering) just to have a non-reflected injection point. User declined given the cost-to-marginal-value ratio. |
| Upload Insecure Files | **Accepted — both candidates** | The app has zero upload-and-serve-back feature anywhere (confirmed via full-tree grep for `request.files`, `secure_filename`, `.save(`). Two candidates: path traversal via unsanitized upload filename (A01), and stored XSS via untrusted SVG content-type (A03). User approved both. |
| XSS Injection | **Declined — user chose to skip** | A candidate (plain-JS DOM-based XSS via `location.hash`, distinct from A06's existing jQuery-specific DOM XSS) was proposed as cheap and self-contained. User declined. |
| XXE Injection | **Declined — user chose to skip** | A candidate (blind/error-based XXE via parameter-entity DTD repurposing, genuinely different from the 2 existing direct-reflection examples) was proposed. User declined. |
| Zip Slip | **Declined — user chose to skip** | A candidate (zip-based plugin-bundle install extending A08's existing plugin marketplace) was proposed. User declined. |
| Race Condition | **Declined — user chose to skip** | A candidate (TOCTOU gift-card double-redemption) was proposed, but empirical verification during triage found this app's test suite runs against an in-memory SQLite DB, and genuinely concurrent OS threads against it crash with driver-level `sqlite3.OperationalError` rather than cleanly demonstrating the race — the test would have needed a deterministic interleaving simulation rather than true concurrency. User declined given this test-design fragility plus the need for a new model. |

## Example 1: Second-Order SQL Injection via Department Report

**Category/Group/Difficulty:** A03 Injection, existing "SQL Injection" group, **Hard** (8th member, appended after the existing `sqli-to-rce`, preserving the group's Easy→Medium→Medium→Medium→Hard→Hard→Hard→**Hard** order).

**Mechanism:** A classic second-order injection — the malicious payload is stored via a completely SAFE, parameterized write, and only becomes exploitable when a *separate, later* feature reads it back and unsafely re-interpolates it into a new raw SQL query.

- **New feature 1 (the safe store):** `POST /a03/roster/add` — a new "add employee to roster" form. Inserts a new `Employee` row (reusing the EXISTING `Employee` model at `app/categories/a03_injection/models.py` — `name`, `email`, `department`, `salary` — no new model). The insert uses the ORM (`Employee(name=..., email=..., department=..., salary=...)`, `db.session.add()`, `db.session.commit()`) — fully parameterized, genuinely safe at write time. This route is NOT itself vulnerable to first-order injection.
- **New feature 2 (the unsafe consumer):** `GET /a03/roster/department-report` — loops over every DISTINCT `department` value currently in the table (`SELECT DISTINCT department FROM a03_employees` — itself safe, no user input at this step) and, for each one, builds and executes: `f"SELECT name, email, salary FROM a03_employees WHERE department = '{department}'"` via `db.session.execute(text(query))` — raw string interpolation, no parameterization. Because the `department` value was already sitting safely in the database (put there by a completely different, already-completed request), the injection fires the moment ANY admin/report view reads it back — the attacker never has to touch the vulnerable line directly.

**Exploit:** submit a new employee via the add-roster form with `department` set to:
```
NoSuchDept' UNION SELECT username, password, 0 FROM injection_accounts--
```
(name/email/salary filled with any benign values). The write succeeds safely. Visiting `/a03/roster/department-report` afterward triggers the vulnerable per-department query for this stored value, and the UNION fires — leaking every row of `injection_accounts` (username, plaintext password) into the report output, disguised as one department's employee roster.

**Empirical verification performed** (this project's established practice — verify library/runtime behavior before finalizing a design that depends on it): confirmed via a standalone SQLite script (this app's test suite runs against `sqlite:///:memory:`, per `TestConfig`) that the exact write-then-read-back sequence works as designed — the malicious department value is stored verbatim via a parameterized `INSERT ... VALUES (?, ?, ?, ?)`, then the vulnerable `SELECT name, email, salary FROM a03_employees WHERE department = '<value>'` query, when built via raw f-string interpolation over that stored value, returns `('admin', 'sup3rSecretPW', 0)` from the `injection_accounts` table — i.e. the exploit fires exactly as designed. The query shape (`SELECT <3 cols> ... UNION SELECT <3 type-compatible cols>`) uses no dialect-specific syntax, so it is expected to behave identically against the app's real PostgreSQL backend; this is the same 3-column `(string, string, int)` UNION shape the existing `union-exfiltration` example already proves works against real Postgres in production.

**Non-duplication:** distinguishes itself from the app's 7 existing SQLi examples (all first-order — the payload and its execution happen within the same request) by being the first example where the vulnerability lives entirely in a *second*, unrelated consumer of already-stored, already-"successfully written" data. The teaching point is explicitly that safe parameterization at the STORE step provides zero protection if a later feature re-interpolates the stored value unsafely.

**Vulnerable code must never be "fixed":** the add-roster route stays exactly as designed (genuinely safe — this is not the bug); the department-report route's raw `f"...'{department}'"` interpolation must never be parameterized, and the per-department loop must never validate/allowlist department values against the initial write.

## Example 2: Path Traversal via Unsanitized Avatar-Upload Filename

**Category/Group/Difficulty:** A01 Broken Access Control, existing "Path Traversal" group, **Medium** (inserted between the existing `arbitrary-file-read` (Medium) and `path-traversal-filter-bypass` (Hard), preserving Easy→Medium→Medium→Hard order for the group).

**Mechanism:** A new route `POST /a01/avatar-upload` accepts an uploaded file (`request.files["avatar"]`) and saves it via `os.path.join(AVATARS_DIR, file.filename)` with `file.save(path)` — using the client-supplied filename completely unsanitized (no `werkzeug.utils.secure_filename()`, no traversal check of any kind). `AVATARS_DIR` is a new sibling directory to the existing `DOCUMENTS_DIR` (both under `instance/`), created via `os.makedirs(AVATARS_DIR, exist_ok=True)` on first use, mirroring the existing `_ensure_seed_document()` pattern.

**Exploit:** upload a file with the multipart filename field set to `../a01_documents/welcome.txt` and attacker-controlled body content. Because `os.path.join()` and `file.save()` perform no validation, the file lands at `instance/a01_documents/welcome.txt` — overwriting the EXISTING seeded document from A01's document-center feature (`app/categories/a01_access_control/routes.py`'s `_ensure_seed_document()`/`download_document()`).

**Proof of impact:** the EXISTING `GET /a01/download-document?name=welcome.txt` route (already implemented, untouched by this change) then serves back the attacker's overwritten content — a genuine, verifiable cross-feature impact requiring no new "read back" route at all.

**Empirical verification performed:** confirmed via `os.path.normpath()` that `../a01_documents/welcome.txt`, joined against the real `AVATARS_DIR` path (`instance/a01_avatars/`), resolves to exactly `instance/a01_documents/welcome.txt` — a single `../` is correct since both directories are direct siblings under `instance/` (verified against the real `BASE_DIR`-derived paths used elsewhere in this app, not assumed).

**Non-duplication:** the 2 existing Path Traversal examples are both READ-side traversal (arbitrary file disclosure via a download route). This is the WRITE side of the same underlying bug class (unsanitized path construction from user input) — a natural escalation within the same group, demonstrating that path traversal is exploitable in either direction.

**Vulnerable code must never be "fixed":** the avatar-upload route must never call `secure_filename()`, must never validate that the resolved path stays inside `AVATARS_DIR`, and must never reject `../` sequences or absolute paths.

## Example 3: Stored XSS via Untrusted SVG Upload

**Category/Group/Difficulty:** A03 Injection, new **"Insecure File Upload"** group (single member), **Hard**, appended at the very end of A03's example list.

**Mechanism:** Two new routes:
- `POST /a03/upload-attachment` — accepts an uploaded file and saves it to a new `ATTACHMENTS_DIR` using the original filename, with zero extension allowlist and zero content-type/content verification.
- `GET /a03/view-attachment/<filename>` — serves the file back via Flask's `send_from_directory(ATTACHMENTS_DIR, filename)`, with no override of the default MIME-type behavior and no forced `Content-Disposition: attachment`.

**Exploit:** upload a file named `poc.svg` containing:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"></svg>
```
Then navigate directly to `GET /a03/view-attachment/poc.svg` (as a top-level page load, not embedded via `<img>` — browsers do not execute scripts inside `<img>`-context SVGs, but a direct navigation renders the SVG as its own document and DOES execute the `onload` handler). Genuine stored XSS: the payload persists on disk and executes for any user who opens the link.

**Empirical verification performed:** confirmed via a standalone Flask app that `send_from_directory()`'s real default behavior for a `.svg` file is `Content-Type: image/svg+xml; charset=utf-8` and `Content-Disposition: inline; filename=poc.svg` — i.e. Flask's own extension-based MIME guessing, with no attachment-forcing, is sufficient on its own to make this genuinely exploitable with zero additional vulnerable configuration beyond "no extension allowlist, no forced download disposition."

**Non-duplication:** distinct from A03's 4 existing XSS examples (all HTML-context reflection/storage bugs triggered by TEXT input rendered into a template) and from A06's `jquery-dom-xss` (a jQuery-library-specific client-side bug) — this is the first example where the vulnerability is in FILE-serving configuration (trusting an uploaded file's own extension to decide how the browser interprets it), not in template rendering or a JS library.

**Vulnerable code must never be "fixed":** the upload route must never restrict file extensions or verify content against the declared type; the view route must never force `Content-Disposition: attachment` and must never override the guessed MIME type to something inert like `text/plain` or `application/octet-stream`.

## Data Model Approach

**No new SQLAlchemy models anywhere in this round.** Example 1 reuses the existing `Employee` and `InjectionAccount` models (`app/categories/a03_injection/models.py`) unmodified. Examples 2 and 3 are filesystem-only (new directories under `instance/`), following the exact precedent of A01's existing document-center feature (`DOCUMENTS_DIR`) — no persistent metadata table needed for either upload feature; the filesystem itself is the store.

## Self-Review

**Placeholder scan:** no TBD/TODO; every example has a complete, concrete mechanism, exact route shapes, and a verified exploit payload.

**Internal consistency:** all three examples' category/group/difficulty placements were checked against the ACTUAL current `__init__.py` contents for A01 and A03 (via the fresh inventory dump taken at the start of this round, then re-confirmed against the live model/route files during design) — not assumed from memory of prior rounds' state.

**Ambiguity check:** the two most runtime-dependent claims in this design — the second-order UNION exploit actually firing through a genuine store-then-read-back sequence, and Flask's real default SVG-serving headers — were both empirically verified against real code execution in this session, not asserted from documentation alone, matching this project's standing practice (established in rounds 3–5) of verifying any exploit that depends on library/runtime behavior before finalizing.

**Scope check:** this spec covers exactly the 3 user-approved examples; no unapproved candidates (Race Condition, DOM-XSS, blind XXE, Zip Slip, blind SSTI, dollar-quoting SQLi bypass) are included, matching the `AskUserQuestion` decisions recorded in the Triage Summary above.
