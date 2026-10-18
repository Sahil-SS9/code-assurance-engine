"""Evaluator-owned oracle: exactly three tests, reviewed expected collection = 3."""

from calc.ops import add, mul, sub


def test_add():
    assert add(2, 3) == 5


def test_sub():
    assert sub(5, 3) == 2


def test_mul():
    assert mul(4, 3) == 12
