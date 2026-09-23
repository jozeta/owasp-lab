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
        ],
        seed_fn=seed_a07_accounts,
    )
)
