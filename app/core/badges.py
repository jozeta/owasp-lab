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


BADGE_CATALOG = [
    Badge("backdoor-baron", "Backdoor Baron", "badge-a01-mastery", "Complete every Broken Access Control example.", _category_mastery("a01_access_control")),
    Badge("cipher-breaker", "Cipher Breaker", "badge-a02-mastery", "Complete every Cryptographic Failures example.", _category_mastery("a02_crypto_failures")),
    Badge("sql-ninja", "SQL Ninja", "badge-a03-mastery", "Complete every Injection example.", _category_mastery("a03_injection")),
    Badge("architect-of-chaos", "Architect of Chaos", "badge-a04-mastery", "Complete every Insecure Design example.", _category_mastery("a04_insecure_design")),
    Badge("config-crusher", "Config Crusher", "badge-a05-mastery", "Complete every Security Misconfiguration example.", _category_mastery("a05_security_misconfiguration")),
    Badge("dependency-hell-survivor", "Dependency Hell Survivor", "badge-a06-mastery", "Complete every Vulnerable Components example.", _category_mastery("a06_vulnerable_components")),
    Badge("session-hijacker", "Session Hijacker", "badge-a07-mastery", "Complete every Auth Failures example.", _category_mastery("a07_auth_failures")),
    Badge("supply-chain-saboteur", "Supply Chain Saboteur", "badge-a08-mastery", "Complete every Integrity Failures example.", _category_mastery("a08_integrity_failures")),
    Badge("ghost-in-the-logs", "Ghost in the Logs", "badge-a09-mastery", "Complete every Logging Failures example.", _category_mastery("a09_logging_monitoring_failures")),
    Badge("request-forger", "Request Forger", "badge-a10-mastery", "Complete every SSRF example.", _category_mastery("a10_ssrf")),
    Badge("script-kiddie", "Script Kiddie", "badge-script-kiddie", "Complete every Easy example, in any category.", _difficulty_sweep("Easy")),
    Badge("grey-hat", "Grey Hat", "badge-grey-hat", "Complete every Medium example, in any category.", _difficulty_sweep("Medium")),
    Badge("1337-haxor", "1337 Haxor", "badge-1337-haxor", "Complete every Hard example, in any category.", _difficulty_sweep("Hard")),
    Badge("red-team-legend", "Red Team Legend", "badge-red-team-legend", "Complete every example in every category.", _grand_completion),
    Badge("purist", "Purist", "badge-purist", "Complete a whole category without revealing a single hint.", _purist),
    Badge("tell-me-everything", "Tell Me Everything", "badge-tell-me-everything", "Reveal every hint on one example.", _tell_me_everything),
    Badge("google-is-my-copilot", "Google Is My Copilot", "badge-google-is-my-copilot", "Reveal 25 hints, lab-wide.", _google_is_my_copilot),
    Badge("natural-talent", "Natural Talent", "badge-natural-talent", "Complete 10 examples without using a hint.", _natural_talent),
    Badge("consistent-threat", "Consistent Threat", "badge-consistent-threat", "Practice 3 days in a row.", _streak_at_least(3)),
    Badge("advanced-persistent-threat", "Advanced Persistent Threat", "badge-advanced-persistent-threat", "Practice 7 days in a row.", _streak_at_least(7)),
    Badge("nation-state-actor", "Nation-State Actor", "badge-nation-state-actor", "Practice 30 days in a row.", _streak_at_least(30)),
    Badge("participation-trophy", "Participation Trophy", "badge-participation-trophy", "Show up. That's it.", _participation_trophy),
    Badge("leet", "Leet", "badge-leet", "Cross 1337 points.", _leet, scoring_only=True),
    Badge("the-answer", "The Answer", "badge-the-answer", "Complete 42 examples.", _the_answer),
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
