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
            ),
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
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
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
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
        ],
        seed_fn=seed_injection_data,
    )
)
