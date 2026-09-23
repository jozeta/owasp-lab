from flask import Blueprint

a03_bp = Blueprint(
    "a03_injection", __name__, template_folder="templates", url_prefix="/a03"
)

from app.categories.a03_injection import routes  # noqa: E402,F401
from app.categories.a03_injection.seed import seed_injection_data  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a03_injection",
        short_id="A03",
        title="Injection",
        blurb="Untrusted input executed by an interpreter, such as SQL, a shell, or the browser, instead of being treated as data.",
        blueprint_name="a03_injection",
        overview_endpoint="a03_injection.overview",
        examples=[
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                group="SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
                hints=[
                    "This login form builds its database query by directly inserting your username and password into a SQL string. What happens if one of those fields contains a character that has special meaning in SQL, like a quote?",
                    "The query looks roughly like: SELECT * FROM injection_accounts WHERE username = '<your username>' AND password = '<your password>'. A single quote in your input breaks out of that string literal early.",
                    "Log in with username admin'-- and any password (or leave the password field blank) — the -- comments out the rest of the query, including the password check, logging you in as admin without ever knowing the real password.",
                ],
            ),
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
                hints=[
                    "This search box also builds SQL by directly inserting your search term. Once you've broken out of the surrounding string literal, is there a SQL keyword that lets you attach results from a completely different query?",
                    "The underlying query always returns exactly two columns (id, username). UNION SELECT lets you attach a second SELECT with the same column count and shape, pulling rows from any table the database can see.",
                    "First confirm the injection point: search for a lone single quote and check for a database error.",
                    "Then search for: ' UNION SELECT id, value FROM a03_secrets -- — the results table now shows rows from a03_secrets, a table this search box was never meant to expose. The same technique reaches injection_accounts itself for real usernames and passwords.",
                ],
            ),
            ExampleNav(
                id="roster-sort",
                title="Employee Roster Sort (ORDER BY Injection)",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.roster",
                hints=[
                    "The employee roster can be sorted by column, and the column name comes straight from a URL parameter. ORDER BY targets are trickier to inject than a normal WHERE-clause value — think about why the usual quote-breakout trick doesn't directly apply here.",
                    "Since the sort value is inserted as a raw SQL expression rather than a quoted string, you don't need to break out of anything — any valid SQL expression can go there directly, as long as it's legal in an ORDER BY position.",
                    "Try ?sort=(CASE WHEN (1=1) THEN name ELSE email END) — a full conditional expression works fine as a sort target, proving arbitrary SQL executes there, not just a bare column name.",
                    "For real information disclosure, make the CASE condition depend on hidden data, e.g. (CASE WHEN (some condition about a secret) THEN name ELSE id END) — the resulting row order changes depending on whether the condition is true, letting you extract data one true/false answer at a time through the sort order instead of a WHERE clause.",
                ],
            ),
            ExampleNav(
                id="error-based-sqli",
                title="Error-Based SQL Injection via Product Lookup",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.product_lookup",
                hints=[
                    "This product lookup takes a raw ID and, unusually, shows you the actual database error message when something goes wrong. What could that error text accidentally reveal?",
                    "Submit a lone single quote as the product ID and look closely at the error that comes back — the database is telling you something about the query it tried to run.",
                    "PostgreSQL raises a type-conversion error if you ask it to CAST a value that isn't a valid integer — and that error message includes the exact value it failed to convert.",
                    "Submit: 1 AND CAST((SELECT password FROM injection_accounts WHERE username='admin') AS int) > 0 — the CAST fails because a real password isn't numeric, and the resulting error message leaks that password's actual text.",
                ],
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
                hints=[
                    "This username-availability check never shows you any data — just 'available' or 'taken'. When there's nothing to read directly, what OTHER observable signal could a malicious query still produce?",
                    "PostgreSQL has a function that pauses query execution for a given number of seconds. If that delay is made conditional on something you want to know, the response TIME itself becomes the leaked signal.",
                    "Try: nobody' OR (SELECT 1 FROM pg_sleep(5))=1-- — if the page takes about 5 seconds to respond, you've confirmed both the injection point and the timing side-channel work.",
                    "Wrap the sleep in a conditional instead of an unconditional one: pg_sleep((SELECT CASE WHEN <condition> THEN 5 ELSE 0 END)) — a true condition delays the response, a false one returns immediately.",
                    "Extract data one character at a time by testing conditions like (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' inside that CASE — repeat for each position and each candidate character to reconstruct the admin password purely from response timing, with no data ever displayed on the page.",
                ],
            ),
            ExampleNav(
                id="roster-lookup",
                title="Employee Lookup (Numeric Blind Injection)",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.roster_lookup",
                hints=[
                    "This lookup takes a numeric employee ID and only ever tells you found or not found. The ID isn't wrapped in quotes anywhere in the query — what does that change about how you'd break out of it?",
                    "Because the value is substituted as a raw number rather than inside a string literal, you don't need a quote to inject at all — any valid SQL expression that evaluates to a number (or a boolean, which SQL treats as 0/1) works directly in its place.",
                    "Try id=0 OR 1=1 — if 'found' flips to true even though employee 0 shouldn't exist, you've confirmed the whole WHERE clause is under your control, not just a literal ID value.",
                    "Turn this into a working oracle: id=0 OR (SELECT CASE WHEN <condition> THEN 1 ELSE 0 END)=1 — 'found' becomes true exactly when <condition> is true, a boolean-blind read with no timing required.",
                    "Substitute a real condition, e.g. id=0 OR (SELECT CASE WHEN (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' THEN 1 ELSE 0 END)=1 — repeat per character and position to extract the admin password one true/false answer at a time, purely from the found/not-found flag.",
                ],
            ),
            ExampleNav(
                id="sqli-to-rce",
                title="Advanced SQL Injection: From Detection to Remote Code Execution",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.inventory_lookup",
                hints=[
                    "This inventory check takes a numeric SKU with no quotes involved, the same shape as the roster lookup. But this endpoint's database driver allows something most of the other examples don't — what happens if you put more than one SQL statement in the same input, separated by a semicolon?",
                    "Try id=0 OR 1=1 first to confirm the field reaches raw SQL, exactly like the roster lookup example. Then try appending a second, harmless statement after a semicolon, like 1; SELECT 1-- — if that doesn't error out, stacked multi-statement queries are genuinely accepted here.",
                    "PostgreSQL's COPY ... FROM PROGRAM command lets a sufficiently privileged database role run an arbitrary OS command and write its output into a table — and stacked queries mean you can inject that as a second statement right after your first one.",
                    "A safe way to prove code execution without opening any network connection: 1; DROP TABLE IF EXISTS a03_rce_check; CREATE TABLE a03_rce_check (output text); COPY a03_rce_check FROM PROGRAM 'id'; -- — then look up any SKU again and the database now holds this server's real id command output.",
                    "From there, the same COPY ... TO PROGRAM mechanism can pipe a reverse-shell command instead of a harmless one, turning the injection into a fully interactive shell on the database server — this final escalation step is manual, hands-on-keyboard exploitation only, matching this example's own Exploitation walkthrough (this lab's automated tests never attempt it).",
                ],
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
            ExampleNav(
                id="filter-challenge",
                title="Filter Bypass Challenge",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.filter_challenge",
            ),
            ExampleNav(
                id="filtered-host-lookup",
                title="Hostname Lookup Filter Bypass",
                group="OS Command Injection",
                difficulty="Medium",
                endpoint="a03_injection.filtered_host_lookup",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
            ExampleNav(
                id="blind-report-injection",
                title="Blind Command Injection via Report Generator",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.generate_report",
            ),
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
            ),
            ExampleNav(
                id="xxe-ssrf",
                title="XXE SSRF via Status Feed Importer",
                group="XML External Entity Injection (XXE)",
                difficulty="Hard",
                endpoint="a03_injection.xxe_ssrf",
            ),
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
            ),
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
            ),
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
            ),
            ExampleNav(
                id="ldap-directory-search",
                title="Blind LDAP Injection via Employee Directory Search",
                group="LDAP Injection",
                difficulty="Hard",
                endpoint="a03_injection.directory_search",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
