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
                id="roster-sort",
                title="Employee Roster Sort (ORDER BY Injection)",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.roster",
            ),
            ExampleNav(
                id="error-based-sqli",
                title="Error-Based SQL Injection via Product Lookup",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.product_lookup",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="roster-lookup",
                title="Employee Lookup (Numeric Blind Injection)",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.roster_lookup",
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
