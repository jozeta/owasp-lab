# Changelog

All notable changes to owasp-lab are listed here, newest first.

The project has no tagged releases yet, so changes are grouped by date. Entries before November 2026 were reconstructed from the commit history.

## Unreleased

- docs: document that local setup needs Python 3.10+ (matching CI) since `requirements.txt`'s
  `python-dotenv` and `pytest` pins require it

- fix: close 16 unintended bypasses of this lab's own checks (open redirect, reset tokens, filter/blocklist logic, and more) found by a full-branch audit against their own hints and tests -- across A01-A04, A06, A07 and A10
- fix: close 6+ caching/stale-state bugs where "Reset lab" left old filesystem-backed proof/log/upload state (A03, A06, A09) or in-memory per-example session state (A07) behind from a previous run
- feat(a07): add `AuthSession.active_mfa_flow` to scope MFA session state to each example instead of sharing it across all 15 A07 examples -- if your Postgres volume predates this column, run `docker compose down -v && docker compose up -d` once before "Reset lab" works again (see README)
- docs: correct hint/explanation/vulnerable_code text in A01, A02, A03 and A10 examples that still described already-fixed vulnerable behavior

## 2026-11-02

- Security: upgrade Flask 3.1.3, python-dotenv 1.2.4 and pytest 9.2.0 (3 Dependabot alerts). None of them is part of an exercise; all exploit tests still pass.
- Add CI workflow, Dependabot config, security policy

## 2026-11-01

- Ignore macOS, Claude Code and secret files
- Add CLAUDE.md with project guidance for Claude Code

## 2026-09-30

- feat: add 24-badge achievement catalog and flip scoring default to on
- feat: show the badge case on the home page, wire up scoring-aware stat strip
- test: explicitly disable scoring in exploit-instructions-visibility tests
- docs: document the achievement system and default-on scoring
- fix: stop red-team-legend badge description from using frozen TOTAL_EXAMPLES constant
- Rework home page badge case layout and add 8 new achievements

## 2026-09-29

- Add design spec for sub-project 3: site-wide Fjord visual redesign
- Refine Fjord spec: theme via Bootstrap's own CSS variables
- Add implementation plan for sub-project 3: site-wide Fjord redesign
- feat: add Fjord design-system foundation (fonts, icons, color tokens)
- feat: restyle nav bar and sidebar with Fjord tokens
- fix: add missing !important to light-mode sidebar background rule
- feat: restyle example and category overview pages with Fjord cards/icons
- feat: add category icons and fill-on-load animation to home page
- feat: wrap leaderboard and instructor tables in Fjord cards
- fix: light-mode contrast and color-consistency issues from final review
- Add design spec for sub-project 4: visual roadmap homepage
- Refine roadmap spec: drop the redundant unearned-badge pill
- Add implementation plan for sub-project 4: visual roadmap homepage
- feat: add roadmap CSS (progress rings, spine, zigzag)
- feat: replace home-page category grid with a visual roadmap
- fix: roadmap desktop zigzag rows and badge emoji overflow
- Revert home-page roadmap trail; restore Fjord card grid
- Rework dashboard to faithfully match the approved Fjord mockup
- Add design spec: revert to global (single-student) progress tracking
- Add implementation plan: revert to global progress tracking
- feat: revert progress/score/badges/streaks to global (single-instance) tracking
- feat: remove anonymous-progress alert and leaderboard/instructor-view pages
- test: rewrite the test suite for global (single-instance) progress tracking
- docs: update README for global (single-instance) progress tracking
- docs: update README screenshots to match the current dashboard design
- Add design spec: expanded 24-badge achievement system
- Add implementation plan: 24-badge achievement system

## 2026-09-28

- feat(a03): add Stored XSS via Untrusted SVG Upload example
- test(nav): update total/max-score assertions and README for 3 new examples
- fix(a03): handle malformed department values in department_report and correct SVG hint xmlns
- docs: add screenshots, MIT license, and tidy .gitignore for public release
- build: vendor ImageMagick 6.9.2-10 source for the upcoming A06 ImageTragick example
- docs: add design spec for A06 ImageMagick ImageTragick RCE addition
- docs: add implementation plan for A06 ImageTragick RCE addition
- build(a06): compile vendored ImageMagick 6.9.2-10 for the ImageTragick RCE example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a06): add ImageMagick ImageTragick RCE examples (base + extension-allowlist bypass)
- fix(a06): entity-encode literal angle brackets in secure_code documentation blocks
- test(nav): update total/max-score assertions and README for 2 new A06 examples
- fix(a06): handle subprocess timeouts and scope proof-file display to the triggering POST
- docs: reformat README's category list as a bulleted list
- docs: add design spec for per-user progress tracking (sub-project 1/4)
- docs: add implementation plan for per-user progress tracking
- feat(core): make example progress, hints, and score per-user
- test(core): log in before progress/hint actions now that they require a user Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- fix(core): redirect anonymous progress actions to the example page, not the POST endpoint
- Add design spec for sub-project 2: gamification + instructor view
- Add implementation plan for sub-project 2: gamification + instructor view
- feat: track daily activity for streaks
- feat: add compute_user_stats() for badges, streaks, and totals
- feat: add leaderboard page
- feat: add admin-gated instructor aggregate view
- feat: show per-category completion badges on the home page
- docs: document the leaderboard and instructor view pages
- fix: use UTC date in activity-tracking test assertions

## 2026-09-27

- feat(a03): add CSV Formula Injection via Comment Export example
- feat(a03): add Argument Injection via Unsanitized tar Archive Export example
- test(a03): skip GNU-tar-specific exploit test when local tar isn't GNU tar
- test(nav): update total/max-score assertions and README for 2 new examples
- fix(a03): address final-review minor findings on tar argument injection example
- docs: add design spec for CSRF/traversal/encoding/file-inclusion additions
- docs: add implementation plan for CSRF/traversal/encoding/file-inclusion additions
- feat(a01): add CSRF via Token Presence-Only Validation example
- feat(a01): add Directory Traversal examples (arbitrary read + filter bypass)
- feat(a03): add Unicode Normalization Filter Bypass (XSS) example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a03): add LFI-to-SSTI via Unsanitized Snippet Include example
- test(nav): update total/max-score assertions and README for 5 new examples
- fix(a01,a03): handle non-OSError crashes in file-path routes gracefully
- docs(a01): clarify ../ segment count depends on install depth
- docs: add design spec for HPP/IDOR/randomness/open-redirect additions
- docs: add implementation plan for HPP/IDOR/randomness/open-redirect additions
- feat(a01): add IDOR via Wildcard Pattern-Matched Lookup example
- feat(a01): add Open Redirect examples (unvalidated + allowlist bypass) Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- fix(a01): render explanation page for Open Redirect examples on bare nav visit
- feat(a01): add HTTP Parameter Pollution role-escalation example
- feat(a02): add Predictable API Key via Time-Seeded PRNG example
- test(nav): update total/max-score assertions and README for 5 new examples Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- docs: add design spec for second-order SQLi & avatar-upload additions
- docs: add implementation plan for second-order SQLi & avatar-upload additions
- feat(a03): add Second-Order SQL Injection via Department Report example
- feat(a01): add Path Traversal via Unsanitized Avatar-Upload Filename example

## 2026-09-24

- fix(review): correct A07 recovery examples and address final whole-branch review findings
- docs: add Business Logic Errors & CORS Misconfiguration additions design spec
- docs: add implementation plan for Business Logic Errors & CORS Misconfiguration additions
- feat(a04): add free-shipping-via-client-trusted-flag example
- Fix: Entity-encode >= operator in A04 shipping_select.html secure_code block
- docs: fix two more unescaped entity-encoding defects in plan (Tasks 3, 5)
- Revert "docs: fix two more unescaped entity-encoding defects in plan (Tasks 3, 5)"
- feat(a04): add overselling-no-stock-limit-check example
- feat(a04): add discount-code-stacking-via-parameter-pollution example
- feat(a04): add premium-access-persists-after-cancellation example
- feat(a04): add store-credit-rounding-exploit example
- feat(a05): add cors-null-origin-whitelisted example
- docs: fix ExampleNav-points-at-raw-JSON-API design defect in Tasks 6/7/8
- Fix CORS null-origin example: add HTML route for explanation page
- feat(a05): add cors-wildcard-origin-internal-network-pivot example
- docs: add missing HTML-route test to Task 8's plan text
- test(a05): add test for cors-wildcard-internal-pivot HTML page render
- feat(a05): add cors-origin-allowlist-regex-bypass example
- test(nav): update grouping/hints-count tests and README for 8 new Business Logic Errors and CORS Misconfiguration examples
- fix(a04): correct shipping button label and add loyalty-convert reset
- test(a05): fix misleading test names and unused fixture param
- fix(a05): use url_for instead of hardcoded port in null-origin demo
- docs: add design spec for CRLF/log-injection and CSS-injection additions
- docs: add implementation plan for CRLF/log-injection and CSS-injection additions
- feat(a09): add Audit Log Forged via Unescaped Display Name example
- feat(a03): add CSS Attribute-Selector Data Exfiltration example
- test(nav): update total/max-score assertions and README for 2 new examples
- fix(a03): retarget CSS exfil rule at rendered sibling so it actually fires
- fix(a03): store CSS exfil leaks in a log file instead of the session
- test(a03): strengthen CSS exfil regression coverage
- docs: add design spec for CSV injection and argument injection additions
- docs: add implementation plan for CSV/argument injection additions

## 2026-09-23

- docs: add A03 SQL/command injection content expansion implementation plan
- docs(a03): expand blind-sqli exploitation text with version/table/credential extraction
- feat(a03): expand union-exfiltration to pull real account credentials
- docs(a03): add reverse-shell delivery instructions to command-injection example
- feat(a03): add error-based-sqli example
- feat(a03): add sqli-to-rce example
- docs(a03): update README for the SQLi content expansion Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- fix(a03): correct reverse-shell teaching text about request-timeout behavior
- docs: add scoring + hints system design spec
- docs: add scoring + hints system implementation plan
- feat(scoring): add compute_points formula, ExampleNav.hints, ExampleProgress score fields
- feat(scoring): wire up hint reveal/mark-done routes, settings, nav+home score display, A10 pilot hints
- feat(scoring): author hints for A01 examples
- fix(scoring): match A01 hints test to brief's exact function signature
- fix(scoring): revert unnecessary conftest.py change from Task 2 fix round
- feat(scoring): author hints for A02 examples
- feat(scoring): author hints for A03 SQL Injection group
- feat(scoring): author hints for A03's XSS/OS-command/XXE/SSTI/LDAP groups
- feat(scoring): author hints for A04 examples
- feat(scoring): author hints for A05 examples
- feat(scoring): author hints for A06 examples
- feat(scoring): author hints for A07 examples
- feat(scoring): author hints for A08 examples
- feat(scoring): author hints for A09 examples
- docs(scoring): update README for the scoring system, fix stale stats-page reference
- docs: correct spec arithmetic (24 Hard / 1310 max, not 25 Hard / 1340)
- docs: add PayloadsAllTheThings-derived additions design spec
- docs: add implementation plan for PayloadsAllTheThings-derived additions
- feat(a01): add CSRF email-change and password-change IDOR examples
- feat(a02): add reset-token referrer-leak and API-response-leak examples
- feat(a04): add password reset poisoning via Host header example
- feat(a05): add clickjacking-on-delete-account example
- feat(a07): add Account Recovery Abuse group (username collision, unicode normalization, reset-disables-2FA)
- Fix test_unicode_lookalike_username_collides_with_real_account to exercise Unicode collision
- feat(a07): add MFA code-leaked-via-API and code-reusability examples
- feat(a07): add MFA brute-force and code-not-bound-to-session examples
- feat(a07): add MFA magic-value bypass and CSRF-on-disable-2FA examples
- test(nav): update grouping/hints-count tests and README for 15 new PayloadsAllTheThings-derived examples

## 2026-09-22

- docs: add A09 Security Logging and Monitoring Failures design spec
- docs: add A09 Security Logging and Monitoring Failures implementation plan
- feat(a09): add category scaffold, SecurityEvent model, and failed-logins-not-logged example
- feat(a09): add admin-action-no-audit example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a09): add sensitive-data-in-logs example and file-log helpers
- feat(a09): add log-file-world-readable example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a09): add no-alert-threshold example
- feat(a09): add attack-signature-not-flagged example
- docs(a09): update README and add overview/nav tests for A09
- docs: add A10 Server-Side Request Forgery design spec
- docs: add A10 Server-Side Request Forgery implementation plan
- feat(a10): add category scaffold, internal-metadata target, and webhook-internal-metadata example
- feat(a10): add fetch-based-port-scan example
- feat(a10): add file-scheme-local-read example
- feat(a10): add blocklist-alternate-ip-bypass example
- fix(a10): match import_avatar's vulnerable_code teaching block to the real route behavior
- fix(a10): make import_avatar's literal-host-blocking tests load-bearing again
- feat(a10): add blocklist-redirect-bypass example
- fix(a10): make mirror_fetcher's non-allowlisted-host rejection test load-bearing
- docs(a10): update README and add overview/nav tests for A10 (final category)
- fix(a10): correct port-scan teaching text and update Dockerfile worker-count comment
- feat: hide exploit instructions by default, merge progress stats into home page
- docs: add A03 SQL/command injection content expansion design spec

## 2026-09-21

- feat: add A03 blind command injection example with multi-task pattern and commix task (Hard)
- docs: add progress tracking & Stats page design spec (sub-project 7)
- docs: add progress tracking & Stats page implementation plan (sub-project 7)
- feat: add example progress tracking with manual mark-as-done control
- feat: add Stats page with overall and per-category progress breakdowns
- fix: address final-review findings (README docs, test assertions, code clarity)
- docs: add A05 Security Misconfiguration design spec
- docs: add A05 Security Misconfiguration implementation plan
- feat: add A05 category scaffold and Exposed Database Backup File example (Easy) Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- fix: HTML-escape angle brackets in backup_exposure.html secure_code block Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add A05 Directory Listing Exposed example (Easy)
- feat: add A05 Verbose Error Message Disclosure example (Medium)
- feat: add A05 Permissive CORS with Credentials example (Medium) Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add A05 Exposed Debug Console example with real Werkzeug RCE (Hard)
- feat: add A05 Forgotten Admin Panel with Default Credentials example (Hard)
- docs: register A05 in README and complete nav/grouping tests
- docs: fix stale A05 reference in README prose (A05 is now implemented)
- docs: add A06 Vulnerable and Outdated Components design spec
- docs: add A06 Vulnerable and Outdated Components implementation plan
- feat(a06): add category scaffold and component-inventory example
- feat(a06): vendor jQuery 1.12.4 and add legacy-widgets detection example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a06): add jQuery DOM XSS example (CVE-2020-11022)
- feat(a06): vendor Lodash 4.17.11 and add prototype-pollution example (CVE-2019-10744)
- feat(a06): add jQuery XSS session-theft example
- feat(a06): add prototype-pollution access-bypass example
- docs(a06): update README and add overview/nav tests for A06
- fix(a06): address final-review findings (version-pinned lodash test, wording/escaping fixes)
- feat(ui): sidebar redesign, code highlighting cleanup, XXE file uploads
- docs: add A07 Identification and Authentication Failures design spec
- docs: add A07 Identification and Authentication Failures implementation plan
- feat(a07): add category scaffold, AuthSession model, and brute-force-login example
- feat(a07): add credential-stuffing example
- feat(a07): add session-identifier-in-url example
- fix: revert vulnerable_code to use share_url and remove flawed test assertion
- feat(a07): implement deliberate logout vulnerability and add session-survives-logout example
- fix(a07): use client.set_cookie() idiom instead of modifying shared conftest fixture
- feat(a07): add session-fixation example
- feat(a07): add bypassable-MFA example
- docs(a07): update README and add overview/nav tests for A07
- docs(a07): fix double-and in README intro paragraph
- docs: add A08 Software and Data Integrity Failures design spec
- docs: add A08 Software and Data Integrity Failures implementation plan
- feat(a08): add category scaffold, RceProof model, and cart-pickle-tampering example
- feat(a08): add unsigned-plugin-content-trust example
- feat(a08): add unchecked-signature-cookie example
- feat(a08): add JWT alg:none signature bypass example
- fix(a08): make Task 4 alg:none test assert on the dynamic success message, not static prose
- feat(a08): add pickle-deserialization-RCE example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat(a08): add unsigned-plugin-installation-RCE example
- docs(a08): update README and add overview/nav tests for A08
- fix(a08): address final-review findings (vacuous tests, unreachable docker-internal plugin URLs, cosmetic fixes)

## 2026-09-20

- docs: add A03 SSTI design spec (sub-project 6b)
- docs: add A03 SSTI implementation plan (sub-project 6b)
- feat: add A03 SSTI RCE example (Easy)
- feat: add A03 SSTI blacklist-bypass example (Hard)
- docs: add A03 LDAP injection design spec (sub-project 6c)
- docs: add A03 LDAP injection implementation plan (sub-project 6c)
- feat: add A03 LDAP injection infrastructure and auth-bypass example (Easy)
- feat: add A03 LDAP blind injection example (Hard)
- docs: add A03 SQLi deepening design spec (sub-project 6d)
- docs: add A03 SQLi deepening implementation plan (sub-project 6d)
- feat: add reusable Tasks pattern and A03 ORDER BY injection example (Medium)
- feat: add A03 numeric boolean-blind injection example with multi-task pattern and sqlmap task (Hard)
- fix: correct sqlmap invocation in Employee Lookup Task 3 solution to the command verified working against the real container
- docs: add A03 XSS deepening design spec (sub-project 6e)
- docs: add A03 XSS deepening implementation plan (sub-project 6e)
- feat: add A03 Filter Bypass Challenge XSS example with three graduated bypass tasks (Hard)
- docs: add A03 CMD-injection deepening design spec (sub-project 6f)
- docs: add A03 CMD-injection deepening implementation plan (sub-project 6f)
- feat: add A03 Hostname Lookup Filter Bypass command injection example (Medium)

## 2026-09-19

- fix: address final review findings (empty cards on supporting pages, unobservable/broken code snippets, missing Detect test coverage)
- docs: add UI polish round 2 design spec (sub-project 5 of 7)
- docs: add UI polish round 2 implementation plan (sub-project 5 of 7)
- feat: collapse Theme/Tools/About/Settings/Log out into a hamburger dropdown
- style: fix code-panel line-number padding and add a visual polish pass
- feat: add zproxy to the Tools page
- docs: add A03 XXE design spec (sub-project 6a)
- docs: add A03 XXE implementation plan (sub-project 6a)
- feat: add A03 XXE file disclosure example (Easy)
- feat: add A03 XXE SSRF example (Hard)
- fix: register custom resolver so XXE-SSRF example actually fetches http:// entities
- fix: bump gunicorn workers from 2 to 4 so self-referential XXE-SSRF requests don't starve the worker pool under normal browser concurrency
- fix: address final review findings (Detect probe accuracy, SSRF resolver test coverage, no_network cleanup, worker-count doc, README/spec accuracy, empty-element handling)

## 2026-09-18

- Add design spec for OWASP Top 10 training lab (scaffold + core + A01)
- Add implementation plan for scaffold + core framework + A01
- chore: ignore local .worktrees/ directory before creating isolated workspace
- chore: scaffold repo, Docker files, and vendored static assets
- feat: add Flask app factory, config, and health check endpoint
- fix: add pytest.ini so bare `pytest` resolves the app package
- feat: add core Settings and User models Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add core package __init__ Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add category/example nav registry Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add seed/reset logic and wsgi entrypoint
- feat: add core UI shell -- login, settings, reset, home page
- fix: use non-deprecated db.session.get() instead of legacy Query.get()
- feat: add A01 blueprint scaffold and overview page
- feat: add A01 Easy IDOR example
- feat: add A01 Medium missing-function-level-authz example
- feat: add A01 Hard mass-assignment role escalation example
- docs: add README with quick start, safety model, and category summary
- fix: preload gunicorn and dispose engine post-fork to eliminate seed-race container crash
- fix: address final review findings (stale port, dockerignore, open redirect, banner test, legacy API warnings)
- Add implementation plan for A02 Cryptographic Failures
- fix: bump psycopg[binary] pin to 3.2.4 for macOS arm64 wheel availability
- feat: add A02 blueprint scaffold and overview page
- feat: add LegacyCredential model and seed wiring for A02
- feat: add A02 Easy credential dump example
- feat: add A02 Medium weak-encryption (ECB) example
- feat: add A02 Hard predictable-reset-token example and legacy login
- docs: mark A02 Cryptographic Failures as implemented
- fix: address final review findings (README accuracy, legacy-login discoverability, toggle-hidden coverage)
- fix: sort nav categories by short_id instead of import order
- Add implementation plan for A03 Injection
- feat: add A03 blueprint scaffold and overview page
- feat: add A03 data models and seed wiring
- feat: add A03 Easy SQL injection auth-bypass example
- feat: add A03 Medium UNION-based SQLi exfiltration example
- feat: add A03 Medium reflected XSS example
- feat: add A03 Hard blind time-based SQLi example
- feat: add A03 Hard OS command injection example
- feat: add A03 Hard stored XSS example
- docs: mark A03 Injection as implemented
- Add implementation plan for A04 Insecure Design
- feat: add A04 blueprint scaffold and overview page
- feat: add A04 Easy unlimited-coupon-reuse example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add A04 Medium negative-quantity example Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- feat: add A04 Hard multi-step checkout bypass example
- docs: mark A04 Insecure Design as implemented
- fix: address final review findings (stale-session crash, reset-scope docs, overflow guard)
- fix: A03 mermaid diagram bug + add force-reset safety-net route
- docs: add UI/infra polish design spec (sub-project 2 of 5)
- docs: add UI/infra polish implementation plan (sub-project 2 of 5)
- docs: pre-flight fix -- Task 1 blurb test needs the app fixture
- feat: add CategoryNav.blurb field and retrofit onto A01-A04
- feat: add hover tooltips to top-nav category links
- feat: add highlight.js line numbers to code panels
- feat: add dark mode toggle
- feat: add Tools page
- feat: add About page Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
- docs: document Tools/About pages and dark mode in README
- fix: dark-mode sidebar nav-link text contrast
- docs: add sidebar regrouping design spec (sub-project 3 of 5)
- docs: add sidebar regrouping implementation plan (sub-project 3 of 5)
- feat: group ExampleNav by vulnerability sub-type, retrofit A01-A04
- feat: render sidebar and overview examples grouped by vulnerability sub-type
- fix: address final review findings (vacuous assertion, thin group-heading tests, missing nonempty-group guard)
- docs: add content retrofit design spec (sub-project 4 of 7)
- docs: add content retrofit implementation plan (sub-project 4 of 7)
- feat: add Detect and Vulnerable vs. Secure sections to example page template
- feat: add Detect and Vulnerable vs. Secure content to A01 examples
- feat: add Detect and Vulnerable vs. Secure content to A02 examples
- feat: add Detect and Vulnerable vs. Secure content to A03 SQL injection examples
- feat: add Detect and Vulnerable vs. Secure content to A03 XSS/command injection examples
- feat: add Detect and Vulnerable vs. Secure content to A04 examples
- fix: HTML-entity-escape literal tags in illustrative code panels
