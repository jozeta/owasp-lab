from importlib.metadata import version
import platform

from flask import render_template

from app.categories.a06_vulnerable_components import a06_bp


@a06_bp.route("/")
def overview():
    return render_template("a06_vulnerable_components/overview.html")


@a06_bp.route("/component-inventory")
def component_inventory():
    # VULNERABLE: a leftover internal "component inventory" page, meant for
    # an ops dashboard, reachable by anyone with no authentication at all --
    # it hands an attacker exactly what they need before searching a CVE
    # database for each exact version.
    component_versions = {
        "Flask": version("flask"),
        "jQuery (Legacy Widgets bundle)": "1.12.4",
        "Lodash (Legacy Widgets bundle)": "4.17.11",
        "Python": platform.python_version(),
    }
    return render_template(
        "a06_vulnerable_components/component_inventory.html",
        component_versions=component_versions,
    )
