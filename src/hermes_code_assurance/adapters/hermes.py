"""Hermes host adapter: register tools / slash command / CLI subcommand / shipped skill.

Rules: no Hermes imports at module import time; every host surface is capability-probed via
hasattr and skipped loudly when missing; no load-time scans, no unsolicited model calls, no
parallel approval service; no registration-time writes. All surfaces call the shared service
facade; the state directory is RESOLVED PER CALL through the trusted ladder below and refuses
loudly (never a bare-home fallback, never a model-chosen path outside the permitted roots).
"""

from __future__ import annotations

from pathlib import Path

from hermes_code_assurance.adapters_scope import SecurityRefusal, StateRootUnavailable

_TOOLSET = "code-assurance"
_PLUGIN_DIR_NAME = "code-assurance-engine"
_REGISTERED_OVERRIDE: Path | None = None  # trusted integration hook, set once at registration


def set_state_override(path: Path | str | None) -> None:
    """Trusted integration override — ONLY the code that registers the plugin may set this.
    It is never reachable from model-supplied arguments."""
    global _REGISTERED_OVERRIDE
    _REGISTERED_OVERRIDE = Path(path).resolve() if path is not None else None


def _host_plugin_data_root():
    """Public host-side root: plugins.plugin_storage first, then hermes_constants home.
    Both import failures are EXPECTED capability probes (outside any Hermes process); they are
    deliberately silent so the ladder continues, and the exhausted ladder refuses (C4)."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore[import-untyped]

        return Path(plugin_data_dir(_PLUGIN_DIR_NAME))
    except ImportError:  # expected probe miss outside a Hermes host process
        pass
    try:
        from hermes_constants import get_hermes_home  # type: ignore[import-untyped]

        return Path(get_hermes_home()) / "plugin-data" / _PLUGIN_DIR_NAME
    except ImportError:
        return None


def _resolve_state_dir(args_state_dir=None) -> Path:
    """Per-call resolution ladder (C4): trusted registered override > explicit args (if inside a
    permitted root) > host-active plugin-data. No bare-home fallback: unresolvable or foreign
    paths REFUSE without a write."""
    permitted: list[Path] = []
    if _REGISTERED_OVERRIDE is not None:
        permitted.append(_REGISTERED_OVERRIDE)
    host_root = _host_plugin_data_root()
    if host_root is not None:
        permitted.append(host_root.resolve())
    if args_state_dir is not None:
        supplied = Path(args_state_dir).resolve()
        for root in permitted:
            try:
                supplied.relative_to(root)
            except ValueError:
                continue
            return supplied
        raise SecurityRefusal(
            f"state_dir {args_state_dir!r} is outside every permitted root "
            f"({[str(p) for p in permitted] or ['<unresolvable>']}); refusing without write"
        )
    if _REGISTERED_OVERRIDE is not None:
        return _REGISTERED_OVERRIDE
    if host_root is not None:
        return host_root
    raise StateRootUnavailable(
        "no trusted plugin data root available (host SDK absent and no registered override): "
        "refusing to select a store — no write performed"
    )


def _data_dir() -> Path:  # kept name for backwards-compat within the adapter
    return _resolve_state_dir()


def _tool_schemas():
    """Every handler resolves its state dir PER CALL through the C4 ladder (trusted override,
    args override guarded to permitted roots, or the host-active plugin-data root). Refusals
    propagate as SecurityRefusal/StateRootUnavailable — never a silent fallback, never a write.

    Schemas are COMPLETE OpenAI function definitions ({"name", "description", "parameters"}):
    the host registry passes these through to the model, so arguments AND the description must
    live inside the schema itself (upstream PR 143753 review, blocking item 2).
    """
    from hermes_code_assurance import service

    def state_root(args):
        return str(_resolve_state_dir(args.get("state_dir")))

    def handler_for(fn):
        def call(args):
            try:
                root = state_root(args)  # ladder refusals surface as data, never an exception
                return _json(fn(root, args))
            except (SecurityRefusal, StateRootUnavailable) as exc:
                return _json({"refused": True, "error": f"{type(exc).__name__}: {exc}"})
        return call

    def schema_of(name: str, description: str, properties: dict, required: list[str]) -> dict:
        return {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    return {
        "assure_inspect": {
            "schema": schema_of(
                "assure_inspect",
                "Read-only candidate inventory + non-executable contract proposal. Identifies "
                "the repo contents at the given git refs without running anything.",
                {
                    "repo": {"type": "string",
                             "description": "Path to the git repository to inspect."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                    "base": {"type": "string",
                             "description": "Optional git ref (SHA or branch name) to diff "
                                            "against; must not start with '-'. Defaults to "
                                            "working-tree inventory."},
                    "head": {"type": "string",
                             "description": "Optional git ref to compare against base; must "
                                            "not start with '-'."},
                },
                ["repo"],
            ),
            "handler": handler_for(
                lambda root, args: service.inspect_candidate(
                    root, args["repo"], base=args.get("base"), head=args.get("head")
                )
            ),
            "description": "Read-only candidate inventory + non-executable contract proposal.",
        },
        "assure_plan_checks": {
            "schema": schema_of(
                "assure_plan_checks",
                "Freeze a reviewed CheckContract v1 onto an assessment so execution can later "
                "be gated against exactly that contract.",
                {
                    "contract": {"type": "object",
                                 "description": "Complete check contract body (check-contract "
                                                "v1 schema) agreed by the reviewer."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                    "assessment_id": {"type": "string",
                                      "description": "Target assessment id from "
                                                     "assure_inspect; defaults to the "
                                                     "contract's own id."},
                },
                ["contract"],
            ),
            "handler": handler_for(
                lambda root, args: service.plan_checks(
                    root, args["contract"], args.get("assessment_id")
                )
            ),
            "description": "Freeze a reviewed CheckContract v1 onto an assessment.",
        },
        "assure_status": {
            "schema": schema_of(
                "assure_status",
                "Report the assessment state plus per-check receipt statuses.",
                {
                    "assessment_id": {"type": "string",
                                      "description": "Assessment id from assure_inspect."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                },
                ["assessment_id"],
            ),
            "handler": handler_for(
                lambda root, args: service.status(root, args["assessment_id"])
            ),
            "description": "Assessment state + per-check statuses.",
        },
        "assure_verify": {
            "schema": schema_of(
                "assure_verify",
                "Reverify persisted receipts (identity layers) and compute the overall status. "
                "Idempotent; refuses new-receipt drift without a write.",
                {
                    "assessment_id": {"type": "string",
                                      "description": "Assessment id from assure_inspect."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                },
                ["assessment_id"],
            ),
            "handler": handler_for(
                lambda root, args: service.verify(root, args["assessment_id"])
            ),
            "description": "Reverify persisted receipts (identity layers) and compute overall.",
        },
        "assure_report": {
            "schema": schema_of(
                "assure_report",
                "Render the scoped private assessment report (markdown or json).",
                {
                    "assessment_id": {"type": "string",
                                      "description": "Assessment id from assure_inspect."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                    "fmt": {"enum": ["markdown", "json"],
                            "description": "Report format; defaults to markdown."},
                },
                ["assessment_id"],
            ),
            "handler": handler_for(
                lambda root, args: service.report(root, args["assessment_id"],
                                                  fmt=args.get("fmt", "markdown"))
            ),
            "description": "Render the scoped private assessment report (markdown/json).",
        },
        "assure_run": {
            "schema": schema_of(
                "assure_run",
                "Attempt the gated check run. Refuses unless the assessment state is APPROVED "
                "and the venue gates pass; records a NOT_APPROVED receipt otherwise.",
                {
                    "assessment_id": {"type": "string",
                                      "description": "Assessment id from assure_inspect."},
                    "repo": {"type": "string",
                             "description": "Candidate repository path (recorded, read-only "
                                            "for this tool)."},
                    "state_dir": {"type": "string",
                                  "description": "Optional state directory inside the "
                                                 "plugin's permitted data root."},
                },
                ["assessment_id"],
            ),
            "handler": handler_for(
                lambda root, args: service.run_checks(root, args["assessment_id"],
                                                      caller="plugin-tool")
            ),
            "description": "SOLE repository-code-executing tool; refuses unless state is "
                           "APPROVED and the venue gates pass; records NOT_APPROVED otherwise.",
        },
    }


def _slash_handler():
    """Slash handler re-resolves the data dir per invocation, same as tools."""
    def handle(raw_args: str) -> str:
        try:
            subcommand = (raw_args or "").split()
            if not subcommand:
                return "hermes assure — read-only by default; execution stays gated by design."
            from hermes_code_assurance import cli

            return cli.run(subcommand, state_dir=str(_data_dir()))
        except SystemExit:
            # Nested argparse usage errors (missing --assessment etc.) must not escape the
            # slash surface either (skeptic round finding 3).
            return "assure usage error: see `/assure help` or `hermes assure --help`."
        except Exception as exc:  # noqa: BLE001 — surfaces never raise into the host turn
            return f"assure command error: {exc}"
    return handle


def _cli_handler(args) -> int:
    """`hermes assure` entrypoint: one canonical-JSON line to stdout, exit-code contract per
    host convention (0 = completed, 1 = refused/error, 2 = usage error).

    State-dir contract (C4 ladder, CLI surface): the operator CLI is a trusted surface, so an
    explicit --state-dir is honoured for it (documented in docs/compatibility.md); without one
    the CLI resolves the host-active plugin data dir per call and refuses loudly when no
    trusted root exists. Model-controlled tool args keep the stricter guarded path."""
    import json

    from hermes_code_assurance import cli as cli_mod

    rc = 0
    try:
        argv = _cli_argv_from(args)
        argv = argv or []
        # argv must be a full domain argv; missing subcommand is a HOST parse concern, but a
        # NESTED parse error inside cli.run raises SystemExit here, INSIDE this try: catch
        # below applies to both layers (skeptic round finding 2).
        # Refusals FIRST (before any state resolution or git call): option-like refs.
        for ref in (getattr(args, "base", None), getattr(args, "head", None)):
            if ref is not None and str(ref).startswith("-"):
                payload = {"refused": True,
                           "error": f"git ref {str(ref)!r} must not start with '-': "
                                    "refusing to pass option-like refs to git"}
                print(json.dumps(payload, sort_keys=True))
                return 1
        supplied = getattr(args, "state_dir", None)
        if supplied:
            state_dir = str(Path(supplied))
        else:
            state_dir = str(_data_dir())
        payload = json.loads(cli_mod.run(argv, state_dir=state_dir))
    except SystemExit as exc:  # argparse usage errors
        payload = {"refused": True, "error": "usage error: see `hermes assure --help`"}
        rc = 2 if exc.code else 0
    except (SecurityRefusal, StateRootUnavailable) as exc:
        payload = {"refused": True, "error": f"{type(exc).__name__}: {exc}"}
        rc = 1
    except Exception as exc:  # noqa: BLE001 — one honest line, never a traceback into the CLI
        payload = {"refused": True, "error": f"{type(exc).__name__}: {exc}"}
        rc = 1
    print(json.dumps(payload, sort_keys=True))
    return rc


def _cli_argv_from(args) -> list[str] | None:
    """Rebuild the domain argv from the host namespace (assure subcommand + its options)."""
    subcommand = getattr(args, "assure_subcommand", None)
    if not subcommand:
        return None
    argv = [subcommand]
    mapping = {
        "repo": "--repo", "state_dir": "--state-dir", "base": "--base", "head": "--head",
        "assessment": "--assessment", "contract_json": "--contract-json",
        "owner_keys": "--owner-keys", "owner_request": "--owner-request",
        "owner_signature": "--owner-signature", "fmt": "--fmt",
    }
    for field, flag in mapping.items():
        value = getattr(args, field, None)
        if value is not None:
            argv.extend([flag, str(value)])
    return argv


def _cli_setup(subparser):
    """Compatibility alias kept for the host's register path and older tests."""
    return register_cli_assure(subparser)


def register_cli_assure(subparser):
    """Populate the host-supplied `hermes assure` subparser with the SHARED domain tree
    (upstream PR 143753 review, blocking item 3) and attach the real handler."""
    from hermes_code_assurance.cli import attach_to_subparser

    return attach_to_subparser(subparser, handler_name="assure_handler", handler=_cli_handler)


def register_plugin(ctx, state_dir=None) -> dict:
    """Register every supported host surface. Fail-closed: missing surfaces skipped + recorded.
    No writes at registration (C4): the trusted override is recorded for later per-call use."""
    set_state_override(state_dir)
    report: dict = {"registered_tools": 0, "skipped_surfaces": [], "commands": []}
    for name, item in _tool_schemas().items():
        if callable(getattr(ctx, "register_tool", None)):
            ctx.register_tool(name, _TOOLSET, item["schema"], item["handler"],
                              description=item["description"])
            report["registered_tools"] += 1
        else:
            report["skipped_surfaces"].append(f"tool:{name}")

    if callable(getattr(ctx, "register_command", None)):
        try:
            ctx.register_command(
                "assure", _slash_handler(),
                description="Code Assurance Engine (read-only default; gated execution).",
                args_hint="inspect|plan|run|status|verify|report [args]",
                argument_mode="mixed",
            )
            report["commands"].append("assure")
        except Exception as exc:  # noqa: BLE001 — capability probed, skip surfaced
            report["skipped_surfaces"].append(f"slash: {exc}")

    if callable(getattr(ctx, "register_cli_command", None)):
        try:
            ctx.register_cli_command(
                "assure", help="Code Assurance Engine (read-only default; gated execution)",
                setup_fn=register_cli_assure,
                handler_fn=_cli_handler,  # host wires handler_fn -> set_defaults(func=...) (main.py:3251-3252)
                description="Change-assurance engine CLI subcommand tree.",
            )
            report["commands"].append("hermes assure")
        except Exception as exc:  # noqa: BLE001 — capability probed, skip surfaced
            report["skipped_surfaces"].append(f"cli: {exc}")

    if callable(getattr(ctx, "register_skill", None)):
        try:
            skill_path = Path(__file__).resolve().parents[3] / "skills" / "assure" / "SKILL.md"
            if skill_path.exists():
                ctx.register_skill("assure", skill_path,
                                   description="Code Assurance Engine usage skill")
                report["commands"].append("skill:assure")
        except Exception as exc:  # noqa: BLE001 — capability probed, skip surfaced
            report["skipped_surfaces"].append(f"skill: {exc}")

    return report


def _json(value) -> str:
    import json

    return json.dumps(value, sort_keys=True)
