"""CLI wiring: `hermes assure` must reach the shared argparse tree (PR 143753 review).

Witnessed RED at effffefd: `_cli_setup` ignored the GIVEN subparser and returned a fresh one,
and no handler was registered, so `hermes assure inspect --repo .` had no arguments and no
handler — every invocation exited with SystemExit(2).
"""

from __future__ import annotations

import argparse
import json
import subprocess

import pytest

from hermes_code_assurance.adapters.hermes import register_cli_assure


def _host_parser():
    """Mimic the host wiring (hermes_cli/main.py:3242-3252 + 3551-3556): setup_fn populates
    the subparser; the host dispatches through args.func, which is set from handler_fn."""
    parser = argparse.ArgumentParser(prog="hermes")
    subs = parser.add_subparsers(dest="command")
    sub = subs.add_parser("assure")
    return parser, sub


def _populated():
    parser, sub = _host_parser()
    register_cli_assure(sub)
    return parser


def test_setup_populates_host_subparser():
    parser, sub = _host_parser()
    assert register_cli_assure(sub) is sub, "setup must populate the GIVEN subparser"
    parsed = parser.parse_args(["assure", "inspect", "--repo", "/tmp/x"])
    assert parsed.repo == "/tmp/x", "the host namespace must carry the assure arguments"
    assert callable(parsed.assure_handler), "subcommand must carry a handler"


def test_handler_runs_shared_cli(tmp_path, capsys):
    parser = _populated()
    parsed = parser.parse_args(["assure", "status", "--assessment", "missing-1",
                                "--state-dir", str(tmp_path)])
    rc = parsed.assure_handler(parsed)
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["state"] == "missing"


def test_real_handler_reaches_service(tmp_path, capsys):
    """Round-trip through parse_args on the same tree the host builds."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    (repo / "calc.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "c1"],
        cwd=repo, check=True, capture_output=True,
    )
    parser = _populated()
    parsed = parser.parse_args(["assure", "inspect", "--repo", str(repo),
                                "--state-dir", str(tmp_path)])
    rc = parsed.assure_handler(parsed)
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0 and payload["assessment_id"]
    assert payload["inventory_state"] in {"complete", "partial"}


def test_dash_leading_base_rejected_at_parse(tmp_path, capsys):
    """argparse cannot even accept `--base --out` (missing argument) — SystemExit(2), never a
    git call. The service-level refusal for `-o`-style VALUES is proven in
    tests/adversarial/test_ref_injection.py."""
    import pytest

    parser = _populated()
    with pytest.raises(SystemExit):
        parser.parse_args(["assure", "inspect", "--repo", str(tmp_path), "--base", "--out"])
    capsys.readouterr()

    # And a value shaped like an option value, e.g. `--base -oanything`, parses to base value
    # only when it looks like a VALUE (starts with '-o' counts as value-like? no — argparse
    # treats '-o' as an option). Use a legitimate dash-leading VALUE via `--base=-oanything`:
    parsed = parser.parse_args(["assure", "inspect", "--repo", str(tmp_path),
                                "--base=-oanything"])
    rc = parsed.assure_handler(parsed)
    assert rc == 1
    assert json.loads(capsys.readouterr().out)["error"].startswith("git ref '-oanything'")


def test_missing_assessment_surfaces_in_cli(tmp_path, capsys):
    parser = _populated()
    parsed = parser.parse_args(["assure", "status", "--assessment", "missing-1",
                                "--state-dir", str(tmp_path)])
    rc = parsed.assure_handler(parsed)
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["state"] == "missing"


def test_missing_required_arguments_exit_two():
    parser = _populated()
    with pytest.raises(SystemExit):
        parser.parse_args(["assure", "inspect"])