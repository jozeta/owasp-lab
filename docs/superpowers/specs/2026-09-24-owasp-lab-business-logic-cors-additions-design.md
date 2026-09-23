# Business Logic Errors & CORS Misconfiguration Additions — Design

## Overview

Add 8 new intentionally-vulnerable examples to the OWASP Top 10 Training
Lab, sourced from PayloadsAllTheThings' "Business Logic Errors" and "CORS
Misconfiguration" reference pages: 5 new examples in A04 Insecure Design
(9 total, up from 4), 3 new examples in A05 Security Misconfiguration (10
total, up from 7). App-wide example count: 78 → 86. No new categories, no
new database models — every example reuses Flask `session`/cookies for
ephemeral per-browser state, matching each category's existing
established precedent.

## Source Material Triage

**Business Logic Errors** (`PayloadsAllTheThings/Business Logic Errors`):

- Already covered by existing content (skip, duplicates):
  - "Apply the same discount code multiple times" → A04's existing
    `unlimited-coupon` example already demonstrates this exact mechanism.
  - "Negative values for delivery/quantity fields" → A04's existing
    `negative-quantity` example.
  - "CSRF unprotected on this feature" → already the explicit subject of
    dedicated examples in A01 (`csrf-email-change`) and A07
    (`csrf-disable-2fa`); not worth a third generic restatement.
- Infeasible for this app's architecture (skip, out of scope):
  - Review/Rating Feature Testing, Thread/Comment Testing — this app has
    no product-review or comment-thread feature anywhere; building one
    solely to host a single teaching example would be out of proportion
    to the lesson, matching this project's established "skip when it
    requires inventing unrelated new app surface" precedent (e.g. HTTP
    request smuggling was skipped in the prior round for a parallel
    reason — needing infrastructure this app doesn't have).
  - Currency Arbitrage — this app has no multi-currency system; would
    require inventing an entire currency-conversion subsystem.
  - Race-condition variants (same-discount-code-two-accounts-at-once,
    multiple-simultaneous-refund-requests) — genuinely demonstrable in
    principle, but timing-dependent tests are flaky (the same class of
    concern already flagged and deliberately avoided for the MFA
    brute-force example in the prior round, which tests "no lockout"
    behaviorally rather than a literal timing race). Not pursued this
    round.
- Genuinely novel, implemented this round: see "The 8 New Examples"
  below (items 1-5 for A04).

**CORS Misconfiguration**
(`PayloadsAllTheThings/CORS Misconfiguration`):

- Already covered (skip, duplicate): "Origin Reflection" — A05's
  existing `cors-credentials` example (`/a05/api/loyalty-status`)
  already reflects any `Origin` header verbatim combined with
  `Access-Control-Allow-Credentials: true`, an exact match for this
  reference page's primary technique.
- Deferred as lower-priority/compound (not pursued this round): "XSS on
  Trusted Origin" — this technique requires a *second*, independent XSS
  vulnerability on the same origin as a strict CORS allowlist to chain
  with; this app's existing XSS examples (A03, A06) live in different
  categories/routes with no natural strict-CORS-allowlist counterpart to
  combine with, and building one artificially would be a contrived,
  compound two-bug demo rather than a clean single-lesson example.
- Genuinely novel, implemented this round: see "The 8 New Examples"
  below (items 6-8 for A05).

## Decisions (confirmed with user via AskUserQuestion)

1. **Scope:** all 8 candidates, this round.
2. **Category placement for the premium/refund example:** A04 Insecure
   Design (matches the reference page's own framing under general
   business-logic testing, and sits naturally beside A04's other
   session-based examples).
3. **Cart/Wishlist ownership IDOR** (a 9th candidate: "move another
   user's cart item"): explicitly **excluded** — it would require
   building a brand-new per-user Cart/CartItem database model solely for
   one example, and A01 already has two solid IDOR examples covering the
   same underlying lesson (`idor`, `password-change-idor`).

## Existing Infrastructure This Builds On

- **A04's session-based ephemeral-state precedent**: `coupon_cart`/
  `quantity_cart` already demonstrate the established pattern of
  Flask-`session`-scoped, no-new-model, single-browser demo state
  (`session["a04_coupon_uses"]`, `session["a04_quantity"]`). All 5 new
  A04 examples follow this same precedent — no new SQLAlchemy models are
  needed anywhere in this round.
- **A04's existing constants**: `DEMO_PRODUCT_NAME`,
  `DEMO_PRODUCT_PRICE_CENTS`, `COUPON_CODE`, `COUPON_DISCOUNT_CENTS`,
  and the `_format_cents()` helper in `app/categories/a04_insecure_design/routes.py`
  — new examples reuse these where relevant (e.g. the discount-stacking
  example introduces a second coupon constant, `SAVE20`, alongside the
  existing `WELCOME10`).
- **A05's existing CORS example** (`cors_credentials`/
  `loyalty_status_api` in `app/categories/a05_security_misconfiguration/routes.py`,
  using `LOYALTY_TOKEN_COOKIE`) — the 3 new CORS examples are
  independent routes with their own cookies/constants, following the
  same "one clean flaw per route" convention; none of them modify or
  reuse the existing `cors-credentials` route itself.
- **This app's total absence of any global CORS/security-header
  middleware** — confirmed via the prior round's whole-branch review,
  which grepped the entire `app/` tree for `X-Frame-Options`,
  `Content-Security-Policy`, and `after_request` and found zero hits.
  This means every new CORS route can set (or omit) its own
  `Access-Control-*` headers independently, with no risk of an existing
  global handler interfering.
- **The scoring+hints integration requirement**: every new `ExampleNav`
  gets `hints=[...]` (3-5 entries), and this changes the same
  cross-cutting test files every prior task in this project has had to
  update: `tests/test_a04_hints.py`, `tests/test_a05_hints.py`,
  `tests/test_a04_overview.py`, `tests/test_a05_overview.py`,
  `tests/test_all_examples_have_hints.py` (`total == 78` → `total == 86`),
  and `tests/test_hints.py` (max-score assertion, currently 1610 — new
  additions are Easy×1 (10) + Medium×5 (100) + Hard×2 (60) = +170, so
  1610 → 1780).

## The 8 New Examples

### A04 Insecure Design

#### 1. Free Shipping via Client-Trusted Flag (Easy)

**Group:** Business Logic Abuse (existing group; sorts alongside
`unlimited-coupon` at Easy)

**Route:** `GET/POST /a04/shipping-select`

**Mechanism:** A checkout step lets the customer pick a shipping method.
The page's own copy states "Free shipping is only available on orders
over $50" — but the server accepts a client-submitted
`shipping_cost_cents` value directly and never checks the actual order
total against that $50 threshold before using the submitted value. No
session state is needed; the flaw is visible within a single
request/response.

**Explanation:** Real checkouts often compute shipping cost server-side
from real business rules (order total, weight, destination). Here, the
form itself carries the computed cost as a hidden field, and the server
trusts it completely — a customer can simply submit `shipping_cost_cents=0`
regardless of their real order total, because the "over $50" rule exists
only in the page's displayed copy, never in the code that processes the
submission.

**Exploitation:** View the shipping-select form's HTML source; note the
hidden `shipping_cost_cents` field. Submit the form with that field
edited to `0` (or omit it and supply `free_shipping=true` directly) even
though the cart total is well under $50 — the confirmed total reflects
free shipping anyway.

#### 2. Overselling — No Stock-Limit Check (Medium)

**Group:** Business Logic Abuse (sorts at Medium alongside
`negative-quantity`)

**Route:** `GET/POST /a04/limited-stock-cart`

**Mechanism:** The page displays a fixed "Only 3 left in stock!" banner
(a hardcoded `STOCK_COUNT = 3` constant) but the order-submission handler
never validates the submitted quantity against that count — any positive
integer is accepted and multiplied into the total, exactly like a normal
order.

**Explanation:** A common real-world flaw: the "in stock" number shown to
customers is a display-only decoration, not an enforced business rule.
Nothing stops a customer from ordering far more units than genuinely
exist, which in a real system would mean shipping promises the business
cannot keep (or, worse, a race to buy out limited/flash-sale inventory at
a stale price).

**Exploitation:** Submit `quantity=500` to `/a04/limited-stock-cart` — the
order confirms for 500 units of an item the page itself says only 3 of
exist, with no rejection, warning, or capped total.

#### 3. Discount Code Stacking via Parameter Pollution (Medium)

**Group:** Business Logic Abuse (sorts at Medium)

**Route:** `POST /a04/coupon-stack` (a `GET` form-display companion on
the same route)

**Mechanism:** Two valid, independent coupon codes exist: `WELCOME10`
($5.00 off) and `SAVE20` ($10.00 off). The form has a single `code`
input, implying only one code applies per order. The server-side handler
reads `request.form.getlist("code")` and applies a discount for *every*
value present in the submitted list, rather than taking only the first
(or validating exactly one). Submitting both codes as duplicate `code`
form fields in a single request (HTTP parameter pollution) stacks both
discounts at once.

**Explanation:** This is mechanistically different from the existing
`unlimited-coupon` example: that one is about *repeatedly resubmitting
the same code over time* (no "already used" tracking). This one is about
*submitting multiple distinct codes in a single request* when the
application's own design intends exactly one code per order — a
parameter-pollution-driven business-logic bypass, not a missing
repeat-use check.

**Exploitation:** `curl -X POST http://127.0.0.1:5001/a04/coupon-stack -d "code=WELCOME10&code=SAVE20"`
— both the $5.00 and $10.00 discounts apply in one single order, a
combination the storefront never intends to offer.

#### 4. Premium Access Persists After Cancellation (Medium)

**Group:** Premium Access Design Flaws (**new group**, sole entry)

**Routes:** `POST /a04/premium/subscribe`, `POST /a04/premium/cancel`,
`GET /a04/premium/content`

**Mechanism:** Subscribing sets a raw, client-visible cookie
(`a04_premium_tier=gold`, no signature, no server-side subscription
record at all). Cancelling flips a *session* flag
(`session["a04_premium_cancelled"] = True`) but never clears, expires, or
otherwise invalidates the `a04_premium_tier` cookie. The premium-content
route checks only `request.cookies.get("a04_premium_tier") == "gold"` —
it never consults the cancellation state at all.

**Explanation:** This directly models the reference material's own
framing: "look for true/false values in cookies validating premium
access" and "cancel a premium feature, see if you can still use it." The
root cause is trusting unsigned client-side state as the sole proof of
an active subscription, with the cancellation flow never touching that
same piece of state.

**Exploitation:** POST to `/a04/premium/subscribe` (sets the cookie),
then POST to `/a04/premium/cancel` (the page confirms cancellation), then
GET `/a04/premium/content` — the premium content still renders, because
the cookie that actually gates access was never cleared by cancellation.

#### 5. Store-Credit Rounding Exploit (Hard)

**Group:** Rounding & Arithmetic Errors (**new group**, sole entry)

**Route:** `POST /a04/loyalty-convert` (a `GET` display companion showing
the running `session["a04_store_credit_cents"]` balance)

**Mechanism:** Converting loyalty points to store credit uses a rate of
0.3 cents per point, but the conversion always rounds the credited amount
*up* to a minimum of 1 cent — even converting a single point (worth
0.3¢) credits a full 1¢ — with no minimum-conversion-amount enforced and
no rate limiting on repeated conversions. Repeating a 1-point conversion
N times credits N cents, net creating money that was never actually
present in the true fractional value.

**Explanation:** This directly adapts the reference material's own
headline example (a real HackerOne report: a cryptocurrency platform's
internal transfer system rounded a sub-minimum-precision transfer up on
the receiving side without deducting anything equivalent from the
sender) into this app's cents-based store-credit system. The lesson is
identical: whenever a system rounds in the customer's favor with no
floor on the operation size and no throttling on repetition, an attacker
can automate the operation into real, unbounded value.

**Exploitation:** POST `points=1` to `/a04/loyalty-convert` repeatedly
(e.g. 100 times in a loop) — the store-credit balance grows by 1 cent
per call regardless of the true 0.3¢ value each point should be worth,
netting 100 cents of pure rounding profit for 100 requests that
individually look completely legitimate.

### A05 Security Misconfiguration

All 3 new examples join the existing "Insecure Response Configuration"
group (alongside `verbose-errors` and `cors-credentials`), sorted
Easy→Hard: `verbose-errors`(Medium), `cors-credentials`(Medium),
`cors-null-origin`(Medium), `cors-wildcard-internal-pivot`(Medium),
`cors-origin-regex-bypass`(Hard).

#### 6. CORS: Null Origin Whitelisted (Medium)

**Routes:** `GET /a05/api/partner-directory`, `GET /a05/cors-null-origin-demo`
(a companion page hosting the sandboxed-iframe PoC, matching this
category's existing `delete_account_clickjack_demo.html` precedent of a
dedicated "attacker page" demo route)

**Mechanism:** `/a05/api/partner-directory` checks
`request.headers.get("Origin") == "null"` and, if so, responds with
`Access-Control-Allow-Origin: null` plus
`Access-Control-Allow-Credentials: true` — a common leftover from
testing via sandboxed iframes or local files during development that
was never removed.

**Explanation:** Browsers send a literal `Origin: null` header in
several legitimate contexts (a sandboxed iframe without
`allow-same-origin`, a `data:` URI navigation, some redirect chains) —
an attacker can deliberately trigger one of these to obtain a `null`
Origin on demand, then exploit a server that trusts it as if it were a
real, specific origin.

**Exploitation:** Visit `/a05/cors-null-origin-demo`, which embeds a
`<iframe sandbox="allow-scripts" src="data:text/html,...">` whose script
fetches `/a05/api/partner-directory` with credentials included. Because
the sandboxed data-URI iframe's Origin is `null`, and the server
explicitly whitelists exactly that value, the fetch succeeds
cross-origin with the victim's cookies attached, and the response is
readable by the attacker's script.

#### 7. CORS: Wildcard Origin, Internal Network Pivot (Medium)

**Route:** `GET /a05/api/internal-metrics`

**Mechanism:** This "internal-only" metrics endpoint sets
`Access-Control-Allow-Origin: *` unconditionally and requires **no
authentication of any kind** — no session check, no API key. Because the
origin is a literal wildcard, browsers never attach cookies to the
request (so credential theft isn't the risk here) — but since the
endpoint itself never checks who's asking either, any external page can
still read the sensitive response data through a victim's browser simply
by being on the same network path (or, in a real deployment, by getting
a victim inside the corporate network to load the attacker's page,
pivoting the read through the victim's browser into an
otherwise-unreachable internal service).

**Explanation:** This is the "internal network pivot" variant from the
reference material: a wildcard-CORS response doesn't leak cookies, but
that's irrelevant when the endpoint requires no authentication at all —
the real vulnerability is the missing auth check, and the permissive CORS
header is what lets an external attacker's page make the request in the
first place instead of the browser blocking it outright as cross-origin.

**Exploitation:**
`curl -s http://127.0.0.1:5001/a05/api/internal-metrics -H "Origin: https://evil.com"`
— the response includes `Access-Control-Allow-Origin: *` and the full
metrics payload, with zero authentication required; any external page's
JavaScript can `fetch()` this endpoint directly and read the response.

#### 8. CORS: Origin Allowlist Regex Bypass (Hard)

**Route:** `GET /a05/api/partner-portal`

**Mechanism:** This endpoint is meant to allow only genuine
`https://partner.example.com`-style origins, checked via
`re.match(r"https://.*example\.com", origin)` — an unanchored regex with
no `$` end-anchor and no escaping discipline enforced elsewhere in the
same check. Any origin containing `example.com` anywhere after
`https://` — including `https://evilexample.com` or
`https://partner.example.com.evil.com` — matches and is reflected back
with credentials enabled.

**Explanation:** Directly adapts the reference material's "Expanding the
Origin" technique: a badly-implemented regular expression intended to
validate an origin allowlist accepts substrings or prefixes it shouldn't,
because the pattern was never anchored to the full string or escaped
correctly.

**Exploitation:**
`curl -s http://127.0.0.1:5001/a05/api/partner-portal -H "Origin: https://evilexample.com"`
— the response reflects `Access-Control-Allow-Origin: https://evilexample.com`
with `Access-Control-Allow-Credentials: true`, even though
`evilexample.com` is not a real partner domain — a regex meant to match
only `example.com` matches anything ending in that substring.

## Data Model Approach

No new SQLAlchemy models anywhere in this round. All 8 examples use
either Flask's `session` (server-side, per-browser, matching A04's
existing `coupon_cart`/`quantity_cart` precedent) or plain response
cookies (matching A05's existing `LOYALTY_TOKEN_COOKIE` precedent for
the premium-tier cookie and the CORS-credential examples). This keeps
the round's scope comparable to the smaller tasks from the prior round
(A01/A02/A04/A05 additions), not the larger A07 model-touching tasks.

## Testing Approach

Real Flask-test-client requests, no mocking, one test file per new
example matching this app's established convention (e.g.
`tests/test_a04_free_shipping.py`, `tests/test_a05_cors_null_origin.py`).
Each category's `__init__.py` ExampleNav list, `test_aNN_hints.py`,
`test_aNN_overview.py` (difficulty list + grouped-by-subtype assertions),
`test_all_examples_have_hints.py` (`total == 78` → `86`), and
`test_hints.py` (max-score assertion, `1610` → `1780`) are updated
exactly as every prior task in this project has done, using the same
"verify the real current file state before editing, don't blindly
pattern-match a stale snippet" discipline the prior round's final
whole-branch review confirmed worked correctly for sequential
same-file edits.

## Scope Note

8 new examples across 2 categories, no new categories, no new database
models. Comparable in scale to the smaller half of the prior round (which
handled 15 examples across 5 categories including 4 model-touching A07
tasks) — expect roughly 5-7 implementation-plan tasks: one per A04
example (5, since each is architecturally independent enough to warrant
its own task-scoped review) or possibly batched pairs, plus the 3 A05
CORS examples (likely one task per example given the CORS mechanism
subtleties reviewers will need to verify independently), plus one final
integration task. Exact task breakdown left to writing-plans.
