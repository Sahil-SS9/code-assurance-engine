"""Skeptic round: nested subcommand surfaces (hermes-plugin-authoring review, minor 2).

Witnessed RED at 0a23249: `hermes assure run` without --assessment raises SystemExit(2) from
a NESTED subparser at parse time. The host owns that exit (argparse convention) — the plugin's
contract is that ITS handler never leaks a traceback, and that a SystemEscape raised inside
cli.run's own nested parse converts to the honest line + rc 2.
"""

from __future__ import annotations

import argparse

import pytest

from hermes_code_assurance.adapters.hermes import register_cli_assure


def _parser():
    parser = argparse.ArgumentParser(prog="hermes")
    subs = parser.add_subparsers(dest="command")
    sub = subs.add_parser("assure")
    register_cli_assure(sub)
    return parser


def test_nested_usage_error_is_host_owned_exit_two(capsys):
    """Missing --assessment on a nested subcommand: argparse exits 2 with the usage message.
    The host owns that exit; the plugin adds no handling to it."""
    with pytest.raises(SystemExit) as excinfo:
        _parser().parse_args(["assure", "run"])
    assert excinfo.value.code == 2
    assert "--assessment" in capsys.readouterr().err


def test_handler_catches_nested_system_exit(capsys, tmp_path):
    """A SystemExit raised INSIDE the handler's own parsing (assure_subcommand missing) is
    caught and converted to the honest usage line + rc 2 — no traceback into the host."""
    parsed = _parser().parse_args(["assure", "status", "--assessment", "x",
                                   "--state-dir", str(tmp_path)])
    parsed.assure_subcommand = None  # strip the subcommand INSIDE the handler's try body
    rc = parsed.assure_handler(parsed)
    assert rc == 2
    out = capsys.readouterr().out
    assert "usage error" in out
    assert "refused" in out


def test_dash_ref_cli_refusal_is_honest_line(capsys, tmp_path):
    """Option-like base values reaching the CLI produce the honest refusal line before any
    git or store call."""
    parsed = _parser().parse_args(["assure", "inspect", "--repo", str(tmp_path),
                                   "--base=-oFile"])
    rc = parsed.assure_handler(parsed)
    assert rc == 1
    assert "must not start with '-'" in capsys.readouterr().out