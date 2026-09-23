from app.core.models import compute_points
from app.core.nav import ExampleNav


def _example(difficulty, hint_count):
    return ExampleNav(
        id="test-example",
        title="Test",
        group="Test Group",
        difficulty=difficulty,
        endpoint="core.home",
        hints=[f"hint {i}" for i in range(hint_count)],
    )


def test_compute_points_hard_with_four_hints_matches_confirmed_formula():
    example = _example("Hard", 4)
    assert compute_points(example, 0) == 30
    assert compute_points(example, 1) == 24
    assert compute_points(example, 2) == 18
    assert compute_points(example, 3) == 12
    assert compute_points(example, 4) == 6


def test_compute_points_easy_with_three_hints_matches_confirmed_formula():
    example = _example("Easy", 3)
    assert compute_points(example, 0) == 10
    assert compute_points(example, 1) == 7
    assert compute_points(example, 2) == 5
    assert compute_points(example, 3) == 2


def test_compute_points_clamps_hints_used_above_hint_count():
    example = _example("Medium", 3)
    assert compute_points(example, 99) == compute_points(example, 3)


def test_compute_points_defensive_zero_hint_count_returns_full_base_points():
    example = _example("Hard", 0)
    assert compute_points(example, 0) == 30
