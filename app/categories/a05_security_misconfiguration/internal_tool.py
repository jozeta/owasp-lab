from flask import Flask
from werkzeug.debug import DebuggedApplication
from werkzeug.middleware.dispatcher import DispatcherMiddleware

DEBUG_MOUNT_PREFIX = "/internal-tools"

internal_tool_app = Flask("a05_internal_diagnostics_tool")
internal_tool_app.config["DEBUG"] = True
internal_tool_app.config["PROPAGATE_EXCEPTIONS"] = True


@internal_tool_app.route("/diagnostics")
def diagnostics():
    # VULNERABLE: this legacy internal diagnostics tool was mounted with
    # Flask's debug mode left on. Any unhandled exception here reaches
    # Werkzeug's real interactive debugger -- with pin_security=False
    # (see wrap_with_debug_console() below), the console requires no PIN
    # at all, giving anyone who can reach this URL arbitrary Python (and
    # therefore arbitrary shell) code execution.
    raise RuntimeError("Diagnostics probe failed: unable to reach legacy metrics collector")


def wrap_with_debug_console(main_app):
    """Mounts the internal diagnostics tool, with its debugger enabled,
    at DEBUG_MOUNT_PREFIX alongside the main app -- scoped to that one
    prefix only. main_app's own error handling (a plain Flask 500 page
    on any of its own uncaught exceptions) is completely untouched."""
    debugged_internal_tool = DebuggedApplication(internal_tool_app, evalex=True, pin_security=False)
    return DispatcherMiddleware(main_app, {DEBUG_MOUNT_PREFIX: debugged_internal_tool})
