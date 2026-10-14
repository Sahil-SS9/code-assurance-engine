"""Test-delta analysis tests (CT07-lite): added/removed/renamed/modified + skip visibility.

Explicit honesty limits: no universal semantic-weakening claim; changed-assertion counts are
unknown, never zero.
"""

from __future__ import annotations

from hermes_code_assurance import test_delta


def test_added_removed_renamed_modified():
    delta = test_delta.analyse(
        {
            "committed_changes": [
                {"path": "tests/test_new.py", "status": "A"},
                {"path": "tests/test_old.py", "status": "D"},
                {"path": "tests/test_ren.py", "status": "R", "old_path": "tests/test_prev.py"},
                {"path": "tests/test_mod.py", "status": "M"},
            ]
        },
        new_contents={},
        old_contents={},
    )
    assert delta["added"] == ["tests/test_new.py"]
    assert delta["removed"] == ["tests/test_old.py"]
    assert delta["renamed"] == [
        {"path": "tests/test_ren.py", "old_path": "tests/test_prev.py"}
    ]
    assert delta["modified"] == ["tests/test_mod.py"]


def test_skip_markers_visible_on_new_content():
    delta = test_delta.analyse(
        {"committed_changes": [{"path": "tests/test_x.py", "status": "M"}]},
        new_contents={
            "tests/test_x.py": (
                "import pytest\n\n@pytest.mark.skip(reason='shhh')\n"
                "def test_a():\n    assert 1\n"
            )
        },
        old_contents={"tests/test_x.py": "def test_a():\n    assert 1\n"},
    )
    assert delta["skips"] == [{"path": "tests/test_x.py", "name": "test_a", "mark": "skip"}]


def test_ast_failure_is_unknown_not_zero():
    delta = test_delta.analyse(
        {"committed_changes": [{"path": "tests/test_bad.py", "status": "M"}]},
        new_contents={"tests/test_bad.py": "def broken(:\n"},
        old_contents={},
    )
    assert delta["unknown_reasons"], "unparseable file must surface an unknown, not hide"
    assert delta["known_names"] == [] or delta["known_names"] is not None


def test_semantic_weakening_not_claimed():
    delta = test_delta.analyse(
        {"committed_changes": [{"path": "tests/test_mod.py", "status": "M"}]},
        new_contents={"tests/test_mod.py": "def test_a():\n    pass  # weakened, undetectably\n"},
        old_contents={"tests/test_mod.py": "def test_a():\n    assert 1 == 1\n"},
    )
    assert delta["limits"]["semantic_weakening"] == "not-claimed"
    assert delta["unknown_reasons"], "drop from assert to pass must NOT be detected as weakening"
