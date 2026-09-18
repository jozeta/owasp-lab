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
        ],
        seed_fn=seed_injection_data,
    )
)
