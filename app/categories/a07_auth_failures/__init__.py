from flask import Blueprint

a07_bp = Blueprint(
    "a07_auth_failures", __name__, template_folder="templates", url_prefix="/a07"
)

from app.categories.a07_auth_failures import routes  # noqa: E402,F401
from app.categories.a07_auth_failures.seed import seed_a07_accounts  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a07_auth_failures",
        short_id="A07",
        title="Identification and Authentication Failures",
        blurb="Broken login protections and session-lifecycle handling that let attackers impersonate real users.",
        blueprint_name="a07_auth_failures",
        overview_endpoint="a07_auth_failures.overview",
        examples=[
            ExampleNav(
                id="brute-force-login",
                title="No Rate Limiting Enables Brute Force",
                group="Brute Force & Credential Stuffing",
                difficulty="Easy",
                endpoint="a07_auth_failures.brute_force_login",
                hints=[
                    "This login form checks a username and password with no protection against repeated attempts. What happens if you submit the wrong password many times in a row?",
                    "There is no lockout, no delay, no CAPTCHA, and no rate limiting on this endpoint — every failed attempt returns instantly and lets you try again immediately.",
                    "Pick a real seeded username (e.g. dana) and try common weak passwords against /a07/customer-login in quick succession — nothing stops you from guessing until one works. (The seeded password for dana is a very common one.)",
                ],
            ),
            ExampleNav(
                id="credential-stuffing",
                title="Credential Stuffing Across Multiple Accounts",
                group="Brute Force & Credential Stuffing",
                difficulty="Medium",
                endpoint="a07_auth_failures.credential_stuffing",
                hints=[
                    "This is a different login form (the loyalty portal) with no special protection of its own. Where might real attackers get lists of already-known username/password pairs?",
                    "Real credential stuffing reuses username/password pairs leaked from OTHER breaches, tried here on the assumption people reuse passwords. This endpoint has the exact same missing rate-limiting as the customer login.",
                    "Try the seeded accounts morgan, priya, and theo against /a07/loyalty-portal-login with a few common/weak password guesses each — the same unprotected check that let you brute-force one account earlier reuses that pattern across multiple identities, exactly like real credential-stuffing attacks.",
                ],
            ),
            ExampleNav(
                id="session-in-url",
                title="Session Identifier Exposed in URL",
                group="Session Identity & Lifecycle",
                difficulty="Easy",
                endpoint="a07_auth_failures.share_session_link",
                hints=[
                    "This page offers a 'share session link' feature. What sensitive value might end up embedded directly in that shareable URL?",
                    "The share link puts your session id in the URL itself (?sid=...) rather than relying only on your cookie — URLs get logged, cached, shared in chat, and stored in browser history far more readily than cookies do.",
                    "Copy the 'share session link' URL shown on this page (it contains ?sid=<your session id>), open it in a different browser or incognito window — you're instantly logged in as that same session, no cookie needed, proving anyone who obtains that URL can hijack the session.",
                ],
            ),
            ExampleNav(
                id="session-survives-logout",
                title="Session Not Invalidated on Logout",
                group="Session Identity & Lifecycle",
                difficulty="Medium",
                endpoint="a07_auth_failures.session_survives_logout",
                hints=[
                    "This example is about what logging out actually invalidates. Does clicking 'log out' destroy your session on the SERVER, or only clear something on your own browser?",
                    "The logout route clears the client's cookie, but never deletes the corresponding session record stored server-side — the old session id, if you still have a copy of it, remains just as valid as before.",
                    "Before logging out, note your current session id (visible via your browser's cookie inspector, or the ?sid= value from the session-in-url example). Log out normally, then manually set your session cookie back to that same saved id.",
                    "After restoring the old session id post-logout, visit /a07/session-survives-logout again — you're still recognized as logged in, proving the server-side session was never actually invalidated.",
                ],
            ),
            ExampleNav(
                id="session-fixation",
                title="Session Fixation",
                group="Session Identity & Lifecycle",
                difficulty="Hard",
                endpoint="a07_auth_failures.session_fixation_demo",
                hints=[
                    "This vulnerability is about WHO chooses the session id, and WHEN. Does this app ever generate a fresh session id at the moment a user logs in?",
                    "Look at how a session id gets assigned: /a07/account?sid=<anything> will adopt whatever id you supply as a brand-new, real session if it doesn't already exist yet — the server trusts client-supplied ids, not just ones it minted itself.",
                    "An attacker picks their own session id ahead of time (e.g. planted-by-attacker-1234), visits /a07/account?sid=planted-by-attacker-1234 to register it as a live session, then tricks a victim into visiting the SAME URL before logging in.",
                    "When the victim logs in while using that planted sid, the app never rotates it to a fresh one on authentication — so the attacker, who already knows that exact sid value, can present it themselves afterward and be authenticated as the victim with no credentials of their own.",
                ],
            ),
            ExampleNav(
                id="mfa-bypass-magic-value",
                title="MFA Bypass via Magic/Null Value",
                group="Multi-Factor Authentication Bypass",
                difficulty="Easy",
                endpoint="a07_auth_failures.mfa_login_magic_value",
                hints=[
                    "This login's code-entry page hides the real code from you, same as this category's brute-force example. Before trying to intercept or guess the real code, consider: leftover developer/testing shortcuts sometimes get left in by accident. What suspiciously simple values might one of those look like?",
                    "Try a handful of common 'test bypass' values without ever learning the real code — 000000 is a classic one.",
                    "The verify endpoint accepts EITHER your real per-login code OR one of a small set of hardcoded magic values — 000000 and the literal string null both work — regardless of what the real code is.",
                    "Exact reproduction: log in at /a07/mfa-login-magic-value with dana/welcome1, then on the code-entry page submit code=000000 — you're granted full access with no knowledge of the real code at all.",
                ],
            ),
            ExampleNav(
                id="mfa-leaked-code",
                title="MFA Code Leaked to Client",
                group="Multi-Factor Authentication Bypass",
                difficulty="Easy",
                endpoint="a07_auth_failures.mfa_leaked_login",
                hints=[
                    "This login flow doesn't show the verification code anywhere on the page itself — so how would you ever learn it? Look at what other requests get made after you log in (your browser's dev tools network tab, or the app's own JSON API endpoints).",
                    "There's a JSON API at /mfa-leaked-code/api/send-code that a real app's JavaScript would call to trigger sending the code via SMS/email. Check its full response body, not just whether it says success.",
                    "POST to /a07/mfa-leaked-code/api/send-code (just your session cookie from having logged in, no body needed) and look at the JSON response — it includes a debug_code field containing the real, currently-valid verification code in plaintext.",
                    "Exact reproduction: log in at /a07/mfa-leaked-code/login with dana/welcome1, then curl -X POST http://127.0.0.1:5000/a07/mfa-leaked-code/api/send-code with your session cookie attached — copy the debug_code value from the response and submit it at /a07/mfa-leaked-code/verify to complete MFA, with no access to dana's real phone or inbox ever required.",
                ],
            ),
            ExampleNav(
                id="mfa-reusable-code",
                title="MFA Code Reusability",
                group="Multi-Factor Authentication Bypass",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_reusable_login",
                hints=[
                    "Complete this login's MFA step once, successfully. Now try submitting that exact same code again — does the server remember it was already used?",
                    "The verify endpoint checks your submitted code against the session's stored pending code, but never clears or invalidates that stored code after a successful check — the same code keeps working indefinitely.",
                    "Log in at /a07/mfa-reusable-code/login with morgan/Summer2023!, note the code shown on the verify page, submit it once to complete MFA, then POST to /a07/mfa-reusable-code/verify again with that exact same code — it's accepted again, with no 'already used' error.",
                    "In a real deployment this means anyone who captures a single valid code once — shoulder-surfing, a compromised SMS gateway log, or a leaked API response like this category's 'MFA Code Leaked to Client' example — can keep using it to re-authenticate indefinitely, not just for the one login it was meant to protect.",
                ],
            ),
            ExampleNav(
                id="mfa-brute-force",
                title="MFA Brute-Force (No Rate Limiting)",
                group="Multi-Factor Authentication Bypass",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_login_bruteforce",
                hints=[
                    "This login also has a code-entry step — but this time, the page never tells you the code. Try guessing it: submit any 6-digit number and see what happens on a wrong guess.",
                    "There's no lockout, no delay, no CAPTCHA, and no attempt counter anywhere on this verify endpoint — every wrong guess returns instantly, ready for another try, exactly like this category's brute-force-login example but for the second factor instead of the password.",
                    "A 6-digit numeric code has only 1,000,000 possible values. With zero rate limiting, scripting a few hundred or thousand requests per second against /a07/mfa-verify-bruteforce (after logging in at /a07/mfa-login-bruteforce as dana/welcome1) would find the real code in well under a minute in a real deployment.",
                    "Reproduction without a full brute-force script: log in at /a07/mfa-login-bruteforce, then POST as many wrong codes as you like to /a07/mfa-verify-bruteforce — notice every attempt behaves identically, with nothing ever blocking, slowing, or flagging repeated failures.",
                ],
            ),
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
            ExampleNav(
                id="mfa-not-bound-to-session",
                title="MFA Code Not Bound to Session",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login_unbound",
                hints=[
                    "This verify page asks for both a username and a code. Why would a verify step need you to tell it your username again — doesn't it already know who you are from your session?",
                    "The verify endpoint looks up the pending code by the USERNAME FIELD YOU SUBMIT in the form, not by anything tied to your own session — the code was never actually bound to the session that requested it in the first place.",
                    "Log in as dana at /a07/mfa-login-unbound in one browser/session to generate a real pending code for dana. In a COMPLETELY SEPARATE session (a different browser, an incognito window, or simply clearing your cookies) that never entered dana's password anywhere, submit dana's username together with that same code to /a07/mfa-verify-unbound.",
                    "The second, unrelated session is authenticated as dana anyway — proving the code was only ever bound to a username string, never to the specific session/browser that actually proved it knew dana's password.",
                ],
            ),
            ExampleNav(
                id="password-reset-disables-mfa",
                title="Password Reset Silently Disables 2FA",
                group="Account Recovery Abuse",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_forgot_password",
                hints=[
                    "This password-reset form is meant to do exactly one thing: set a new password. Check what else changes on your session afterward, specifically anything related to MFA.",
                    "Completing this reset sets your session's MFA-verified flag to true directly — no verification code was ever submitted anywhere in this flow.",
                    "curl -X POST http://127.0.0.1:5000/a07/mfa-forgot-password -d 'username=dana&new_password=attacker-chosen-password' -c cookies.txt — the response confirms the password reset, and the session tied to those cookies is now marked as having passed MFA too, purely as a side effect.",
                ],
            ),
            ExampleNav(
                id="username-collision-reset",
                title="Password Reset via Username Collision",
                group="Account Recovery Abuse",
                difficulty="Hard",
                endpoint="a07_auth_failures.register",
                hints=[
                    "This registration form stores your username exactly as you typed it. What happens if you add invisible whitespace to a username that already belongs to someone else?",
                    "Register an account with a username that already exists PLUS a trailing space (e.g. dana with a space appended) — since it's technically a different string, registration succeeds as a brand-new, separate account.",
                    "The password-reset flow that follows registration strips whitespace before looking up which account to update. If a REAL account already exists whose username exactly equals your padded username after stripping, the reset targets that real account instead of the one you just registered.",
                    "Exact reproduction: register username 'dana ' (with a trailing space) at /a07/register with any password, then submit a new password at the forgot-password page you're redirected to — the real, seeded dana account's password changes, not the 'dana ' account you registered. This mirrors a real CVE (CTFd, CVE-2020-7245).",
                ],
            ),
            ExampleNav(
                id="unicode-normalization-takeover",
                title="Account Takeover via Unicode Normalization",
                group="Account Recovery Abuse",
                difficulty="Hard",
                endpoint="a07_auth_failures.account_lookup",
                hints=[
                    "This 'find my account' feature normalizes usernames before comparing them, to be forgiving about accents and capitalization. Some Unicode characters LOOK like ordinary letters but aren't — what happens if normalization turns two visually-similar-but-different usernames into the exact same string?",
                    "First register an account at /a07/register using an unusual Unicode character in place of an ordinary letter (e.g. U+24D0, CIRCLED LATIN SMALL LETTER A, in place of a real 'a') — it looks almost identical but is a completely different character.",
                    "Unicode NFKC normalization strips the circle decoration from a character like U+24D0, turning it into a plain 'a'. Submit that SAME lookalike username (not the plain-ASCII version) into this lookup form — since the lookup normalizes every stored username before comparing, your freshly-registered lookalike account and the already-seeded, real 'dana' account both normalize to the identical string, and the app logs you in as whichever one it finds first.",
                    "Exact reproduction: register username 'd' + chr(0x24D0) + 'na' (renders as 'dⓐna') at /a07/register, then submit that SAME 'dⓐna' string into this page's lookup form — you're logged in as the real, seeded dana account, no password required at all.",
                ],
            ),
            ExampleNav(
                id="csrf-disable-2fa",
                title="CSRF on Disabling 2FA",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_settings",
                hints=[
                    "This settings page shows a 'Disable 2FA' button once you've completed the real login+verify flow. Look at the disable form's HTML source — is there anything that would stop a completely different website from submitting that same request on your behalf?",
                    "There's no CSRF token anywhere in that form, and the server never checks where the POST came from — only that a valid session cookie was attached, which browsers send automatically on cross-origin form submissions too.",
                    "Complete the real MFA flow first (dana / welcome1 at /a07/mfa-login, then the code shown at /a07/mfa-verify) so your session is genuinely mfa_verified. Then, from a separate auto-submitting HTML form hosted anywhere else, POST to /a07/mfa/disable with no body required at all — your session's mfa_verified flag flips back to false with zero confirmation.",
                    "This matches a real, well-documented MFA-bypass technique: 2FA-disable endpoints are exactly the kind of sensitive, state-changing action that most needs CSRF protection and a re-authentication step (re-enter your password, or the code itself) before executing — this one has neither.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
