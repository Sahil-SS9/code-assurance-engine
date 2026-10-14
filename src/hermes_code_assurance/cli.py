"""Domain CLI: `assure` subcommand surface (argparse). Shared function by Hermes CLI adapter."""

from __future__ import annotations

import argparse
import json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assure", description="Code Assurance Engine (read-only default; execution gated)"
    )
    subs = parser.add_subparsers(dest="subcommand", required=True)

    sub = subs.add_parser("inspect", help="read-only candidate inventory + proposed contract draft")
    sub.add_argument("--repo", required=True)
    sub.add_argument("--state-dir", default=None)
    sub.add_argument("--base", default=None)
    sub.add_argument("--head", default=None)

    sub = subs.add_parser("plan", help="freeze a reviewed check contract onto an assessment")
    sub.add_argument("--state-dir", default=None)
    sub.add_argument("--assessment", default=None)
    sub.add_argument("--contract-json", required=True)

    sub = subs.add_parser("run", help="attempt gated check execution (denied by default)")
    sub.add_argument("--assessment", required=True)
    sub.add_argument("--state-dir", default=None)

    sub = subs.add_parser("status", help="assessment state + check statuses")
    sub.add_argument("--assessment", required=True)
    sub.add_argument("--state-dir", default=None)

    sub = subs.add_parser("verify", help="reverify persisted receipts (identity layers)")
    sub.add_argument("--assessment", required=True)
    sub.add_argument("--state-dir", default=None)

    sub = subs.add_parser("report", help="render private markdown/json assessment report")
    sub.add_argument("--assessment", required=True)
    sub.add_argument("--state-dir", default=None)
    sub.add_argument("--fmt", choices=["markdown", "json"], default="markdown")
    return parser


def run(argv: list[str] | None, *, state_dir=None) -> str:
    """Shared service call path. `state_dir` is supplied by the host adapter (plugin data dir)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    from hermes_code_assurance import service

    resolved = state_dir if args.state_dir is None else args.state_dir
    subcommand = args.subcommand
    if subcommand == "inspect":
        return json.dumps(
            service.inspect_candidate(resolved, args.repo, base=args.base, head=args.head),
            sort_keys=True,
        )
    if subcommand == "plan":
        if args.contract_json != "-":
            with open(args.contract_json) as fh:
                contract = json.load(fh)
        else:
            contract = None
        return json.dumps(
            service.plan_checks(resolved, contract, args.assessment), sort_keys=True
        )
    if subcommand == "run":
        return json.dumps(service.run_checks(resolved, args.assessment, caller="cli"), sort_keys=True)
    if subcommand == "status":
        return json.dumps(service.status(resolved, args.assessment), sort_keys=True)
    if subcommand == "verify":
        return json.dumps(service.verify(resolved, args.assessment, caller="cli"), sort_keys=True)
    if subcommand == "report":
        return json.dumps(service.report(resolved, args.assessment, fmt=args.fmt), sort_keys=True)
    raise ValueError(f"unknown subcommand {subcommand}")
