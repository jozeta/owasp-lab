from dataclasses import dataclass
from typing import Callable

from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES
from app.core.stats import compute_streak


@dataclass
class Badge:
    id: str
    name: str
    icon: str
    description: str
    condition: Callable[[dict], bool]
    scoring_only: bool = False


def _category_mastery(category_id):
    def check(ctx):
        category = next(c for c in CATEGORIES if c.id == category_id)
        ids = {e.id for e in category.examples}
        return bool(ids) and ids.issubset(ctx["completed_ids"])

    return check


def _difficulty_sweep(difficulty):
    def check(ctx):
        ids = {e.id for c in CATEGORIES for e in c.examples if e.difficulty == difficulty}
        return bool(ids) and ids.issubset(ctx["completed_ids"])

    return check


def _grand_completion(ctx):
    # Recomputed at call time rather than read from the module-level
    # TOTAL_EXAMPLES: CATEGORIES (app.core.nav) is populated lazily, by each
    # category blueprint's __init__ module, only once create_app() imports
    # it -- so a value captured when this module is first imported (which
    # can happen before any blueprint is registered, e.g. under pytest
    # collection) would be frozen at 0 for the rest of the process.
    total_examples = sum(len(c.examples) for c in CATEGORIES)
    return ctx["completed_total"] >= total_examples


def _purist(ctx):
    for category in CATEGORIES:
        ids = {e.id for e in category.examples}
        if not ids or not ids.issubset(ctx["completed_ids"]):
            continue
        if all(ctx["hints_used_by_id"].get(example_id, 0) == 0 for example_id in ids):
            return True
    return False


def _tell_me_everything(ctx):
    example_by_id = {e.id: e for c in CATEGORIES for e in c.examples}
    for example_id, hints_used in ctx["hints_used_by_id"].items():
        example = example_by_id.get(example_id)
        if example is not None and len(example.hints) > 0 and hints_used >= len(example.hints):
            return True
    return False


def _google_is_my_copilot(ctx):
    return sum(ctx["hints_used_by_id"].values()) >= 25


def _natural_talent(ctx):
    hint_free_completions = sum(
        1
        for example_id in ctx["completed_ids"]
        if ctx["hints_used_by_id"].get(example_id, 0) == 0
    )
    return hint_free_completions >= 10


def _streak_at_least(days):
    def check(ctx):
        return ctx["streak_days"] >= days

    return check


def _participation_trophy(ctx):
    return True


def _leet(ctx):
    return ctx["score_total"] >= 1337


def _the_answer(ctx):
    return ctx["completed_total"] >= 42


def _completed_at_least(count):
    def check(ctx):
        return ctx["completed_total"] >= count

    return check


# SQL-injection-specific examples in A03 -- a genuinely distinct subset of
# that category's Injection examples (command injection, XSS, XXE, SSTI,
# LDAP injection, and others in A03 are NOT SQL injection). Hardcoded by id
# rather than derived from CATEGORIES/ExampleNav metadata (there is no
# "technique" field to filter on), so this set carries no risk of the
# CATEGORIES-lazy-population timing issue that affected TOTAL_EXAMPLES --
# it's checked only against completed_ids (plain strings from
# ExampleProgress), never against CATEGORIES itself.
SQLI_EXAMPLE_IDS = frozenset({
    "sqli-login",
    "union-exfiltration",
    "roster-sort",
    "error-based-sqli",
    "blind-sqli",
    "roster-lookup",
    "sqli-to-rce",
    "second-order-sqli-department-report",
})

# Examples across the lab whose exploitation genuinely results in the
# server running attacker-controlled code or OS commands (not merely a
# data-disclosure or logic bug) -- spans A03 (command/argument injection,
# SQLi-to-RCE, SSTI, LFI-to-SSTI), A05 (exposed Werkzeug debug console),
# A06 (ImageTragick), and A08 (pickle and plugin-install RCE).
CODE_EXECUTION_EXAMPLE_IDS = frozenset({
    "command-injection",
    "blind-report-injection",
    "argument-injection-tar-export",
    "sqli-to-rce",
    "ssti-email-preview",
    "ssti-blacklist-bypass",
    "file-inclusion-lfi-ssti",
    "debug-console-rce",
    "imagetragick-rce",
    "imagetragick-extension-bypass",
    "cart-pickle-rce",
    "plugin-marketplace-rce",
})

# The two examples whose own walkthroughs explicitly go past basic code
# execution and describe escalating into a full interactive reverse shell
# (both call this final step manual, hands-on-keyboard exploitation that
# this lab's automated tests never attempt) -- a subset of
# CODE_EXECUTION_EXAMPLE_IDS, since getting a reverse shell is itself a form
# of code execution.
REVERSE_SHELL_EXAMPLE_IDS = frozenset({
    "command-injection",
    "sqli-to-rce",
})


def _all_example_ids_completed(example_ids):
    def check(ctx):
        return bool(example_ids) and example_ids.issubset(ctx["completed_ids"])

    return check


def _any_example_id_completed(example_ids):
    def check(ctx):
        return bool(example_ids & ctx["completed_ids"])

    return check


BADGE_CATALOG = [
    Badge("backdoor-baron", "Backdoor Baron", "badge-a01-mastery", "Complete every Broken Access Control example. From missing checks to full privilege escalation — nothing in A01 gets past you.", _category_mastery("a01_access_control")),
    Badge("cipher-breaker", "Cipher Breaker", "badge-a02-mastery", "Complete every Cryptographic Failures example. Weak hashes, broken crypto, exposed secrets — you cracked them all.", _category_mastery("a02_crypto_failures")),
    Badge("sql-ninja", "SQL Ninja", "badge-a03-mastery", "Complete every Injection example. SQL, command, LDAP, template — if it takes user input, you've exploited it.", _category_mastery("a03_injection")),
    Badge("architect-of-chaos", "Architect of Chaos", "badge-a04-mastery", "Complete every Insecure Design example. You found the flaws baked into the blueprint, not just the code.", _category_mastery("a04_insecure_design")),
    Badge("config-crusher", "Config Crusher", "badge-a05-mastery", "Complete every Security Misconfiguration example. Default creds, exposed debug endpoints, open panels — all fair game.", _category_mastery("a05_security_misconfiguration")),
    Badge("dependency-hell-survivor", "Dependency Hell Survivor", "badge-a06-mastery", "Complete every Vulnerable Components example. You proved that someone else's bug is still your bug.", _category_mastery("a06_vulnerable_components")),
    Badge("session-hijacker", "Session Hijacker", "badge-a07-mastery", "Complete every Auth Failures example. Sessions, tokens, MFA bypasses — none of it held.", _category_mastery("a07_auth_failures")),
    Badge("supply-chain-saboteur", "Supply Chain Saboteur", "badge-a08-mastery", "Complete every Integrity Failures example. You tampered with the pipeline and nobody noticed.", _category_mastery("a08_integrity_failures")),
    Badge("ghost-in-the-logs", "Ghost in the Logs", "badge-a09-mastery", "Complete every Logging Failures example. You came and went, and none of it was ever logged.", _category_mastery("a09_logging_monitoring_failures")),
    Badge("request-forger", "Request Forger", "badge-a10-mastery", "Complete every SSRF example. You made the server fetch exactly what it should never have reached.", _category_mastery("a10_ssrf")),
    Badge("script-kiddie", "Script Kiddie", "badge-script-kiddie", "Complete every Easy example, in any category. Everyone starts somewhere — you cleared the low-hanging fruit lab-wide.", _difficulty_sweep("Easy")),
    Badge("grey-hat", "Grey Hat", "badge-grey-hat", "Complete every Medium example, in any category. Past the basics, not yet a legend — comfortably in between.", _difficulty_sweep("Medium")),
    Badge("1337-haxor", "1337 Haxor", "badge-1337-haxor", "Complete every Hard example, in any category. The examples that actually make you think.", _difficulty_sweep("Hard")),
    Badge("red-team-legend", "Red Team Legend", "badge-red-team-legend", "Complete every example in every category. Easy, Medium, Hard, all 10 categories — fully cleared.", _grand_completion),
    Badge("purist", "Purist", "badge-purist", "Complete a whole category without revealing a single hint. No walkthroughs, no shortcuts — just you and the vulnerability.", _purist),
    Badge("tell-me-everything", "Tell Me Everything", "badge-tell-me-everything", "Reveal every hint on one example. Sometimes the fastest path to understanding is just asking for all the help.", _tell_me_everything),
    Badge("google-is-my-copilot", "Google Is My Copilot", "badge-google-is-my-copilot", "Reveal 25 hints, lab-wide. There's no shame in it — even real attackers Google their payloads.", _google_is_my_copilot),
    Badge("natural-talent", "Natural Talent", "badge-natural-talent", "Complete 10 examples without using a hint. You either know this stuff cold, or you're very good at guessing.", _natural_talent),
    Badge("consistent-threat", "Consistent Threat", "badge-consistent-threat", "Practice 3 days in a row. Log in and make progress on any day to keep the streak alive.", _streak_at_least(3)),
    Badge("advanced-persistent-threat", "Advanced Persistent Threat", "badge-advanced-persistent-threat", "Practice 7 days in a row. A full week of showing up — the badge name is not subtle.", _streak_at_least(7)),
    Badge("nation-state-actor", "Nation-State Actor", "badge-nation-state-actor", "Practice 30 days in a row. Most attackers give up long before this. You didn't.", _streak_at_least(30)),
    Badge("participation-trophy", "Participation Trophy", "badge-participation-trophy", "Show up. That's it. Everyone gets one — no conditions, no catch.", _participation_trophy),
    Badge("leet", "Leet", "badge-leet", "Cross 1337 points. The most iconic number in hacker culture, and now it's your score.", _leet, scoring_only=True),
    Badge("the-answer", "The Answer", "badge-the-answer", "Complete 42 examples. The Answer to the Ultimate Question of Life, the Universe, and Everything.", _the_answer),
    Badge("foothold-established", "Foothold Established", "badge-foothold-established", "Complete 10 examples, lab-wide. Every real engagement starts with a single foothold.", _completed_at_least(10)),
    Badge("privilege-escalation", "Privilege Escalation", "badge-privilege-escalation", "Complete 25 examples, lab-wide. From a foothold to real access — you're climbing.", _completed_at_least(25)),
    Badge("lateral-movement", "Lateral Movement", "badge-lateral-movement", "Complete 50 examples, lab-wide. Halfway across the network, and still moving.", _completed_at_least(50)),
    Badge("domain-admin", "Domain Admin", "badge-domain-admin", "Complete 75 examples, lab-wide. Nearly the whole environment answers to you now.", _completed_at_least(75)),
    Badge("total-pwnage", "Total Pwnage", "badge-total-pwnage", "Complete 100 examples, lab-wide. Only a handful of stragglers stand between you and Red Team Legend.", _completed_at_least(100)),
    Badge("bobby-tables", "Bobby Tables", "badge-bobby-tables", "Complete every SQL Injection example. Little Bobby Tables would be proud.", _all_example_ids_completed(SQLI_EXAMPLE_IDS)),
    Badge("code-red", "Code Red", "badge-code-red", "Get your first genuine code execution on the target server. Command injection, SSTI, deserialization, ImageMagick — however you got there, the server ran your code.", _any_example_id_completed(CODE_EXECUTION_EXAMPLE_IDS)),
    Badge("popped-a-shell", "Popped a Shell", "badge-popped-a-shell", "Escalate a code-execution bug into a full interactive reverse shell. This lab won't check your netcat listener for you — that part's on you.", _any_example_id_completed(REVERSE_SHELL_EXAMPLE_IDS)),
]


def compute_badges():
    """Returns {badge.id: bool} for every badge in BADGE_CATALOG."""
    progress_rows = ExampleProgress.query.all()
    completed_ids = {p.example_id for p in progress_rows if p.completed_at is not None}
    completed_total = len(completed_ids)
    hints_used_by_id = {p.example_id: p.hints_used for p in progress_rows}
    score_total = sum(
        p.points_awarded or 0 for p in progress_rows if p.completed_at is not None
    )
    activity_dates = {row.date for row in ActivityDay.query.all()}
    streak_days = compute_streak(activity_dates)

    ctx = {
        "completed_ids": completed_ids,
        "completed_total": completed_total,
        "hints_used_by_id": hints_used_by_id,
        "score_total": score_total,
        "streak_days": streak_days,
    }

    return {badge.id: badge.condition(ctx) for badge in BADGE_CATALOG}
