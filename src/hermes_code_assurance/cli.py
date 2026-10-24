"""Domain CLI: `assure` subcommand surface (argparse). Shared function by Hermes CLI adapter."""

from __future__ import annotations

import argparse
import json

_SUBCOMMAND_SPECS: dict[str, list[tuple]] = {
    "inspect": [
        ("--repo", {"required": True}), ("--state-dir", {"default": None}),
        ("--base", {"default": None}), ("--head", {"default": None}),
    ],
    "plan": [
        ("--state-dir", {"default": None}), ("--assessment", {"default": None}),
        ("--contract-json", {"required": True}),
    ],
    "approve": [
        ("--assessment", {"required": True}), ("--owner-keys", {"required": True}),
        ("--owner-request", {"required": True}), ("--owner-signature", {"required": True}),
        ("--state-dir", {"default": None}),
    ],
    "run": [
        ("--assessment", {"required": True}), ("--state-dir", {"default": None}),
        ("--owner-keys", {"default": None, "help": "owner trust root (owner-signed run)"}),
        ("--owner-request", {"default": None}), ("--owner-signature", {"default": None}),
    ],
    "status": [("--assessment", {"required": True}), ("--state-dir", {"default": None})],
    "verify": [("--assessment", {"required": True}), ("--state-dir", {"default": None})],
    "report": [
        ("--assessment", {"required": True}), ("--state-dir", {"default": None}),
        ("--fmt", {"choices": ["markdown", "json"], "default": "markdown"}),
    ],
}

_SUBCOMMAND_HELP = {
    "inspect": "read-only candidate inventory + proposed contract draft",
    "plan": "freeze a reviewed check contract onto an assessment",
    "approve": "owner gate: a signed bundle completes contract review",
    "run": "attempt gated check execution (denied by default)",
    "status": "assessment state + check statuses",
    "verify": "reverify persisted receipts (identity layers)",
    "report": "render private markdown/json assessment report",
}


def attach_to_subparser(subparser, handler_name: str = "assure_handler", handler=None,
                        dest: str = "assure_subcommand"):
    """Attach the shared domain subcommand tree to a HOST-supplied ``hermes assure`` subparser.

    (upstream PR 143753 review, blocking item 3): the adapter previously received the host's
    subparser and threw it away; the subcommand had no arguments and no handler, so every
    `hermes assure ...` exited with SystemExit(2). Each argument now lands on the host
    namespace and the handler is recorded under ``handler_name``. Returns the same subparser.
    """
    subs = subparser.add_subparsers(dest=dest, required=True)
    for name, options in _SUBCOMMAND_SPECS.items():
        sub = subs.add_parser(name, help=_SUBCOMMAND_HELP[name])
        for flag, kwargs in options:
            sub.add_argument(flag, **kwargs)
    if handler is not None:
        subparser.set_defaults(**{handler_name: handler})
    return subparser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assure", description="Code Assurance Engine (read-only default; execution gated)"
    )
    return attach_to_subparser(parser, dest="subcommand")


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
        bundle = (args.owner_keys, args.owner_request, args.owner_signature)
        if all(bundle):
            from .owner_authority import AuthorityDenied

            try:
                return json.dumps(service.run_owner_journey(
                    resolved, args.assessment,
                    owner_keys=args.owner_keys, owner_request=args.owner_request,
                    owner_signature=args.owner_signature, caller="cli",
                ), sort_keys=True)
            except AuthorityDenied as exc:
                return json.dumps({
                    "assessment_id": args.assessment, "status": "AUTHORITY_REFUSED",
                    "reason": "; ".join(exc.reasons), "receipts_unchanged": True,
                }, sort_keys=True)
        return json.dumps(service.run_checks(resolved, args.assessment, caller="cli"), sort_keys=True)
    if subcommand == "approve":
        from hermes_code_assurance.owner_authority import AuthorityDenied

        try:
            return json.dumps(service.approve_contract(
                resolved, args.assessment, owner_keys=args.owner_keys,
                owner_request=args.owner_request, owner_signature=args.owner_signature,
            ), sort_keys=True)
        except AuthorityDenied as exc:
            return json.dumps({
                "assessment_id": args.assessment, "status": "AUTHORITY_REFUSED",
                "reason": "; ".join(exc.reasons), "receipts_unchanged": True,
            }, sort_keys=True)
    if subcommand == "status":
        return json.dumps(service.status(resolved, args.assessment), sort_keys=True)
    if subcommand == "verify":
        return json.dumps(service.verify(resolved, args.assessment, caller="cli"), sort_keys=True)
    if subcommand == "report":
        return json.dumps(service.report(resolved, args.assessment, fmt=args.fmt), sort_keys=True)
    raise ValueError(f"unknown subcommand {subcommand}")
