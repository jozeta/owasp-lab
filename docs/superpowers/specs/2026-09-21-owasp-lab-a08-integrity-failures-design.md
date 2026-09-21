# OWASP Top 10 Training Lab — A08 Software and Data Integrity Failures Design Spec

Date: 2026-09-21
Status: Approved

New category sub-project, following the same from-scratch pattern used to build
A01–A07. This is A08's own full brainstorming cycle.

## Purpose

Build A08 (OWASP Top 10 2021: Software and Data Integrity Failures) as a new
category with six examples — two per difficulty tier, per the user's explicit
request — covering distinct, genuinely exploitable real-world integrity
failures not already covered elsewhere in the app.

## Decisions from brainstorming

- **Overlap with A02 Cryptographic Failures was explicitly mapped and
  avoided.** A02 owns weak/unsalted hashing, ECB-mode encryption, and
  predictable password-reset *token randomness*. A08 never touches any of
  that — its three groups are about integrity *verification being skipped
  or bypassed entirely* (no signature check ever runs, or an attacker
  controls which check runs), a genuinely different failure mode from "the
  crypto itself is weak." No other category touches deserialization or
  software-update integrity at all — this is fresh territory.
- **A hard design constraint carried over from this session's direct prior
  experience**: A06's brainstorming hit a safety-classifier block when a
  candidate PyYAML-unsafe-deserialization example tried to prove code
  execution via `os.system`/`subprocess`. A08's subject matter (insecure
  deserialization, unsigned code execution) is exactly the kind of topic
  that risks the same block. Every "prove arbitrary code executed" claim in
  this spec is proven with a **safe, contained, pure-Python side effect**
  instead — writing a row to a dedicated database table — never a shell
  command or OS-level process.
- **Four technical claims were live-verified before finalizing this spec,
  not assumed**, using a scratch Python venv with no Flask app involved yet
  (pure-Python mechanics, each with the safe-proof discipline above):
  - **Pickle data tampering, no code execution.** A `pickle.dumps()`/
    `pickle.loads()` round-trip of a plain dict (`{"item": "Widget",
    "price": 49.99}`) through base64 has zero built-in integrity checking —
    an attacker can independently construct their own pickle of
    `{"item": "Widget", "price": 0.01}` (no access to the server's own
    token needed at all) and it deserializes cleanly. Verified live.
  - **Pickle remote code execution via `__reduce__`.** A crafted class
    whose `__reduce__` method returns `(some_function, (args,))` causes
    `pickle.loads()` to call that function *during deserialization* — not
    during pickling, not in the attacker's own process. Verified live with
    a safe proof: the function writes a marker file, and the marker
    genuinely appeared only after `pickle.loads()` ran, never before.
  - **JWT `alg: none` bypass.** A hand-rolled JWT-style signer/verifier
    (HS256, stdlib `hmac`/`hashlib`/`base64`/`json` only) was built and
    tested with a real positive and negative control: a verifier that reads
    the algorithm from the token's *own* header (rather than pinning to a
    fixed expected algorithm) accepts a forged token with `alg: none` and
    an empty signature, claiming an arbitrary role — verified live,
    `{'user': 'attacker', 'role': 'admin'}` was returned by the vulnerable
    verifier with zero valid signature. A second verifier that pins the
    expected algorithm was verified to correctly reject the identical
    forged token (`ValueError: unsupported alg`). This is a real,
    well-documented historical vulnerability class (circa 2015, multiple
    real JWT libraries), reproduced faithfully here.
  - **Unsigned "plugin" content execution.** Simulated fetching arbitrary
    text content from a URL and "installing" it via `exec()` with no
    checksum/signature check against any known-good hash — verified live
    with the same safe marker-file-style proof (a DB row, in the real
    implementation) appearing only after the `exec()` call.
- **Implementation choice: hand-roll the JWT-style token with stdlib,
  don't add PyJWT as a new dependency.** Two real options were considered:
  adding `PyJWT` (a real, widely-used library — but the specific `alg:
  none` bug class in question was fixed in that library over a decade ago,
  so demonstrating it faithfully would require either pinning a very old,
  unmaintained PyJWT release or working against the library's grain) versus
  hand-rolling a minimal HS256 signer/verifier with `hmac`/`hashlib`/
  `base64`/`json` (already in the standard library, already live-verified
  above, and more pedagogically transparent since the learner can read the
  *exact* signing/verification logic in the vulnerable route rather than
  trusting an opaque library call). The hand-rolled approach is chosen:
  it avoids adding a new dependency for one example, matches this app's
  established minimal-dependency posture (A06 vendored old JS rather than
  adding new Python packages; A07 hand-rolled its own session mechanism
  rather than adding Flask-Session), and makes the vulnerable *and* secure
  code samples fully self-contained and readable.
- **A shared `RceProof` database table is used by both Hard-tier examples**
  (cart-pickle-rce and plugin-marketplace-rce) to record the safe
  side-effect proof, rather than an in-memory flag — this avoids the
  known multi-worker gunicorn pitfall already documented in this session
  (A05's Werkzeug-debugger note): an in-memory Python global set by one
  request is invisible to a different request if gunicorn routes it to a
  different worker process. A DB row is visible regardless of which worker
  handles which request.
- **Six examples, two per tier, in three groups, mirroring A06/A07's
  "same underlying mechanism, deepened consequence" pattern**: each group's
  Easy/Medium example and its Hard-tier sibling share the identical
  vulnerable mechanism, with the Hard tier proving a strictly worse
  consequence (data tampering → code execution) rather than being an
  unrelated bug.

## Components

### Group 1: Insecure Deserialization

**1. Pickle Cart Tampering (Easy)** — `id: cart-pickle-tampering`. `GET/POST
/a08/cart`. A shopping-cart feature serializes the cart contents with
`pickle`, base64-encodes it, and stores it in a cookie:

```python
import base64
import pickle

def serialize_cart(cart):
    return base64.b64encode(pickle.dumps(cart)).decode()

def deserialize_cart(token):
    # VULNERABLE: no HMAC/signature check at all -- the app trusts
    # whatever pickle bytes the client sends back.
    return pickle.loads(base64.b64decode(token))
```

The Exploitation section shows the learner how to independently construct
their own pickle payload with `price: 0.01` (they never need to see or
modify the server's real token — pickle has no integrity protection to
defeat, so knowing the expected shape is enough) and swap the cookie value.

**2. Pickle Deserialization RCE (Hard)** — `id: cart-pickle-rce`. `GET
/a08/cart-rce-demo` (teaching page) reusing the exact same vulnerable
`/a08/cart` endpoint from example 1. The Exploitation section shows the
`__reduce__` gadget:

```python
class _EvilPayload:
    def __reduce__(self):
        return (write_rce_proof, ("PWNED-VIA-PICKLE-RCE",))
```

pickled, base64-encoded, and swapped in as the `a08_cart` cookie value —
visiting `/a08/cart` with that cookie triggers `write_rce_proof(...)`
*during deserialization*, which inserts a row into the shared `RceProof`
table. The teaching page displays the live `RceProof` table contents
(via `/a08/rce-proof`, a shared non-nav utility endpoint) so the learner
sees the proof appear in real time after visiting `/a08/cart`.

### Group 2: Unsigned Software Updates / Supply Chain

**3. Unsigned Plugin Content Trust (Medium)** — `id:
plugin-marketplace-tampering`. `GET/POST /a08/plugin-marketplace`. A
"Plugin Marketplace" feature fetches Python source text from a
user-supplied URL and installs it — `urllib.request.urlopen(url,
timeout=5).read().decode()` — with no checksum or signature check against
any known-good/trusted-source registry. The Exploitation section has the
learner host two different files locally via `python3 -m http.server`
(matching this session's established multi-actor-artifact convention, e.g.
A05's CORS collector): a bundled "official-looking" plugin file this app
ships, and a substituted, differently-branded file — both install
identically, with the marketplace never distinguishing a legitimate source
from a substituted one. This tier's proof is content substitution (the
installed plugin's displayed content doesn't match the official file),
not code execution — that's example 4's deepening.

**4. Unsigned Plugin Installation Leads to RCE (Hard)** — `id:
plugin-marketplace-rce`. `GET /a08/plugin-marketplace-rce-demo` (teaching
page) reusing the exact same `/a08/plugin-marketplace` endpoint from
example 3 — because "installing" a plugin in this feature means running
its source via `exec()` as part of activation, which was already happening
in example 3, this tier simply proves the consequence explicitly: a
substituted plugin file containing:

```python
write_rce_proof("PWNED-VIA-UNSIGNED-PLUGIN-INSTALL")
```

genuinely executes with full application privileges the moment it's
"installed" — proven via the same shared `RceProof` table and
`/a08/rce-proof` utility endpoint as example 2.

### Group 3: Broken Signature Verification

**5. Unchecked Signature on Preferences Cookie (Easy)** — `id:
unchecked-signature-cookie`. `GET/POST /a08/preferences`. A "remember my
preferences" feature stores `{"theme": ..., "premium_unlocked": ...,
"sig": ...}` as a cookie. A real signature-verification function exists in
the codebase and is shown in the vulnerable-code teaching block — but the
route that *reads* the cookie on `GET` never actually calls it; it parses
the JSON and trusts `premium_unlocked` directly. This is a realistic,
common real-world bug shape: the check was written, just never wired up at
the one call site that mattered. The Exploitation section has the learner
craft a cookie with `"premium_unlocked": true` and an obviously bogus
`"sig": "not-a-real-signature"` value and confirms the server honors it
anyway.

**6. JWT `alg: none` Signature Bypass (Medium)** — `id:
jwt-alg-none-bypass`. `GET /a08/api-token` (non-nav utility page) issues a
legitimate HS256-signed token for a `role: "guest"` identity, displayed as
text for the learner to copy. `GET/POST /a08/admin-api` (the example's
real endpoint) accepts a pasted token in a form field and verifies it with
the vulnerable pattern live-verified above — reading `alg` from the
token's own header instead of pinning to `HS256`. The Exploitation section
shows constructing a forged token with `alg: none`, an empty signature,
and `role: "admin"`, submitting it, and reaching admin-only content with
no valid signature ever produced.

## Data Model

```python
class RceProof(db.Model):
    __tablename__ = "a08_rce_proofs"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    triggered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

No other persisted models are needed — the cart, plugin-marketplace, and
preferences examples all carry their exploitable state in a cookie, and
the JWT example's tokens are self-contained and stateless by design (that's
the whole point of a JWT).

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a08_integrity_failures/__init__.py`, following the exact
A05/A06/A07 pattern): `id="a08_integrity_failures"`, `short_id="A08"`,
`title="Software and Data Integrity Failures"`, a blurb describing
unverified deserialization, unsigned updates, and broken signature checks,
`overview_endpoint="a08_integrity_failures.overview"`, no `seed_fn` (no
persisted seed data needed — `RceProof` starts empty and is written to by
the exploits themselves). The six `ExampleNav` entries land in the three
groups described above, in Easy→Hard flat-list order per group (Group 1 is
Easy→Hard, Group 2 is Medium→Hard, Group 3 is Easy→Medium — satisfying
`grouped_examples()`'s per-group sortedness requirement).

## Testing

- Route-level tests for all six examples via the normal `client`/`app`
  fixtures: legitimate use works for each example; the vulnerable behavior
  is genuinely provable through the real Flask test client — specifically:
  - Examples 1–2: a legitimately-issued cart cookie round-trips correctly;
    a client-crafted tampered pickle cookie (price manipulation) is
    honored; a client-crafted malicious `__reduce__`-gadget cookie causes a
    new `RceProof` row to appear after the request, which did not exist
    before it.
  - Examples 3–4: spin up a real local `http.server.HTTPServer` (matching
    the established pattern from A03's `test_xxe_ssrf_resolver_genuinely_
    fetches_http_entities`) serving two different plugin source texts;
    installing from each URL produces genuinely different installed
    content; installing a payload containing the `write_rce_proof(...)`
    call produces a new `RceProof` row.
  - Example 5: submitting a cookie with a tampered `premium_unlocked` flag
    and an invalid `sig` value is still honored by the `GET` route.
  - Example 6: a legitimate HS256 token verifies and is rejected once
    tampered; a forged `alg: none` token with `role: admin` is accepted by
    the vulnerable verifier and reaches admin-only content.
- `tests/test_a08_overview.py` mirrors `test_a07_overview.py` exactly:
  overview renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness, group headings render on the overview page.
- README.md's category summary table gets A08's row (Implemented status,
  full example list), matching every other row's format exactly, and the
  trailing "Planned" row becomes "A09–A10".

## Out of scope for this spec

- A09–A10 (separate, future sub-projects).
- Adding `PyJWT` or any other new Python dependency — the hand-rolled
  stdlib approach covers this category's needs fully (see Decisions).
- Any RCE proof mechanism that shells out via `os.system`/`subprocess`/any
  OS-level process — every code-execution proof in this spec uses a
  database write instead, per the hard constraint established above.
- Any change to A02's existing crypto-failure examples, or to any other
  existing category's routes, templates, or tests.
- Progress tracking changes — the existing `{% block tasks %}` and
  "Mark as done" mechanisms are reused as-is (no multi-task examples in
  this spec; every A08 example is single-shot, matching every prior
  category's style).
