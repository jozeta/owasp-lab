# OWASP Top 10 Training Lab — A03 OS Command Injection Deepening Design Spec

Date: 2026-09-20
Status: Approved
Sub-project 6f of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall, and its LAST piece): quick fixes → UI/infra polish → sidebar regrouping →
content retrofit → UI polish round 2 → A03 expansion (XXE (done) → SSTI (done) →
LDAP (done) → SQLi deepening (done) → XSS deepening (done) →
**CMD-injection deepening (this spec)**) → progress tracking & stats (sub-project 7,
next).

## Purpose

Deepen the existing OS Command Injection coverage under A03 with two new,
purely additive examples: a Medium filter-bypass lesson and a Hard blind
(no-output) injection flagship using the existing multi-task pattern. This
is the sixth and final A03 injection sub-project (XXE, SSTI, LDAP, SQLi
deepening, XSS deepening done; CMD-injection deepening this one).

## Decisions from brainstorming

- **Purely additive — the existing `command-injection` example
  (`/a03/host-lookup`, Hard) is completely untouched.** Matches the
  additive-only pattern every A03 sub-project has used.
- **Both a filter-bypass example and a blind-injection flagship were
  requested**, matching SQLi-deepening's two-new-examples shape more
  closely than XSS-deepening's one-new-example shape. The existing
  command-injection example is fully output-visible; neither new example
  duplicates that lesson.
- **The filter-bypass bypass technique was live-verified before
  finalizing this spec, not assumed:** a naive blacklist checking only
  the three obvious shell separators (`;`, `&`, `|`) was reproduced in
  Python and confirmed to let a literal newline character through
  untouched; a `getent hosts` call run with a newline-separated payload
  via `shell=True` genuinely executed a second command (`/bin/sh`
  treats `\n` exactly like `;`), confirmed via actual subprocess output.
- **The blind flagship's core mechanism (timing-only oracle) was
  live-verified, not assumed:** a scratch Flask route matching the
  proposed "fire and forget" shape (`shell=True`, output discarded,
  identical response text regardless of outcome) was built and measured
  directly — an unmodified request completed in ~0.01s, while a request
  carrying `; sleep 3 #` completed in ~3.0s, a clear, unambiguous timing
  signal with zero content-based signal available.
- **The Task 2 manual-extraction technique (ASCII-ordinal binary search
  via a conditional sleep) was live-verified, not assumed:** confirmed
  against a real `/bin/sh` (this project's `shell=True` calls resolve to
  `/bin/sh`, not `bash`) that
  `[ $(printf %d '$(head -c1 <path>)) -gt N ] && sleep 3` correctly
  discriminates true/false for a real file's first character, using only
  POSIX `sh` syntax — no bashisms required.
- **The Task 3 automation tool is `commix`** (the command-injection
  analog to `sqlmap`), confirmed to be a real, actively maintained
  project cloned from `github.com/commixproject/commix` (not
  pip-installable — the `commix` PyPI package that name resolves to is
  an unrelated, empty, unofficial package and must not be used). The
  real tool was cloned and its `--help` output confirmed it runs from
  source with no installation step. Running it live against a scratch
  replica of the proposed vulnerable route was blocked by this
  environment's sandbox (execution of freshly-cloned external code is
  restricted) — the exact working invocation is deferred to live
  verification during the implementation plan's own Docker-verification
  task, the same precedent SQLi-deepening set for tuning its exact
  `sqlmap` invocation.
- **No changes to the shared `{% block tasks %}` base-template
  mechanism** — reused exactly as built in SQLi-deepening and reused
  as-is (unmodified) in XSS-deepening.
- **A new secret file, mirroring the existing XXE-secret convention**
  (`app/categories/a03_injection/xxe_secret.txt`), holds the blind
  flagship's extraction target — a short, single-line fake credential,
  so Task 2's `head -c1 <path>` technique targets the real secret's
  first character directly with no prefix text to skip.

## Components

### 1. New Medium example — Hostname Lookup Filter Bypass

`POST /a03/filtered-host-lookup` — the same `getent hosts` shell-out
pattern as the existing `command-injection` example, guarded by a naive
blacklist:

```python
@a03_bp.route("/filtered-host-lookup", methods=["GET", "POST"])
def filtered_host_lookup():
    host = ""
    output = None
    blocked = False
    if request.method == "POST":
        host = request.form.get("host", "")
        if any(bad in host for bad in (";", "&", "|")):
            blocked = True
        else:
            # VULNERABLE: blacklist checks only ";", "&", "|" -- a literal
            # newline is just as good a command separator to /bin/sh and
            # isn't checked for at all
            result = subprocess.run(
                f"getent hosts {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
    return render_template(
        "a03_injection/filtered_host_lookup.html",
        host=host,
        output=output,
        blocked=blocked,
    )
```

Bypass: `localhost\necho bypassed` — the newline is not in the blacklist,
`/bin/sh` treats it as a command separator, and the second command
executes. No Tasks block needed — a single clean lesson, matching the
plain single-walkthrough shape of SQLi-deepening's Medium example
(`roster-sort`).

### 2. New secret file

`app/categories/a03_injection/cmd_secret.txt` — a single-line fake
credential, mirroring `xxe_secret.txt`'s "plausible internal secret"
convention:

```
K7QXTP-prod-signing-key
```

### 3. New Hard flagship example — Blind Command Injection via Report Generator

`POST /a03/generate-report` — a "generate my report" feature that never
shows command output and always returns the same response text,
regardless of success, failure, or what the injected command did:

```python
CMD_SECRET_PATH = os.path.join(os.path.dirname(__file__), "cmd_secret.txt")


@a03_bp.route("/generate-report", methods=["GET", "POST"])
def generate_report():
    report_name = ""
    submitted = False
    if request.method == "POST":
        report_name = request.form.get("report_name", "")
        # VULNERABLE: raw string-concatenated shell command, output
        # discarded -- the response text below is identical no matter
        # what happens, so the ONLY signal available is how long the
        # request took to complete
        subprocess.run(
            f"touch /tmp/reports/{report_name}.pdf",
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        submitted = True
    return render_template(
        "a03_injection/generate_report.html",
        report_name=report_name,
        submitted=submitted,
        secret_path=CMD_SECRET_PATH,
    )
```

Uses the existing Tasks pattern with three graduated tasks:

- **Task 1 (confirm):** submit `x; sleep 5 #` as the report name and
  observe the multi-second delay before the (content-identical) response
  arrives — proves blind command execution with zero output needed.
- **Task 2 (manual):** binary-search the ASCII value of the secret
  file's first character using a conditional-sleep probe:
  `x; [ $(printf %d '$(head -c1 <secret_path>)) -gt N ] && sleep 3 #`,
  halving the 0–255 range each time (~8 requests) to confirm the first
  character is `K` (ASCII 75) — proving the technique recovers real file
  content one bit of information at a time, matching this project's
  established "prove it for real, through the actual route" discipline.
- **Task 3 (automation-required):** the task's prose states plainly that
  extracting the entire secret this way — one character, one binary
  search, repeated — is impractical by hand, and points to `commix`
  (cloned from `github.com/commixproject/commix`, run from source, not
  pip-installed) as the tool built for exactly this. The exact working
  invocation is determined and documented during the implementation
  plan's Docker-verification task, per the Decisions section above.

## Navigation

Both entries land in the *existing* "OS Command Injection" nav group in
`app/categories/a03_injection/__init__.py` (currently one Hard entry,
`command-injection`). To preserve the group's required Easy→Hard
sortedness in flat-list traversal order: the new `filtered-host-lookup`
(Medium) entry is inserted immediately *before* the existing
`command-injection` entry, and the new `blind-report-injection` (Hard)
entry is inserted immediately *after* it — keeping the group contiguous
and its traversal order Medium → Hard → Hard (non-decreasing), the same
contiguous-insertion approach SQLi-deepening used.

## Testing

- Route-level tests for `/a03/filtered-host-lookup`: legitimate lookups
  work normally; the three blacklisted characters (`;`, `&`, `|`) are
  genuinely blocked; the newline bypass genuinely executes a second
  command, with its output present in the response.
- Route-level tests for `/a03/generate-report`: a legitimate submission
  returns the standard response text with no error; a full multi-request
  binary-search extraction (run through the real Flask test client in a
  loop, matching the LDAP and SQLi-deepening sub-projects' "prove it for
  real" discipline) recovers the exact ASCII value of the secret file's
  first character (`75`, i.e. `K`) using only response timing as the
  oracle — no output is ever read.
- A test confirming the Tasks section only renders on the blind flagship
  when `show_exploit_instructions` is on, matching the existing
  toggle-off test pattern.
- Both new examples' standard nav-registration/grouping tests, updated
  for two entries landing inside the existing OS Command Injection group.
- Docker verification task: confirms both new routes work against the
  real container, confirms the full manual binary-search extraction works
  live, and determines and documents the exact `commix` invocation that
  successfully extracts the entire secret file's contents against the
  real running container — the verification this spec deferred (see
  Decisions above).

## Out of scope for this spec

- Any change to the existing `command-injection` example
  (`/a03/host-lookup`) or its existing route/template/tests.
- Progress tracking / Stats page (sub-project 7, the next and final piece
  of this project's current roadmap after this sub-project ships).
- Any change to XXE, SSTI, LDAP, SQLi-deepening, or XSS-deepening
  examples.
- Any change to the shared `{% block tasks %}` base-template mechanism.
