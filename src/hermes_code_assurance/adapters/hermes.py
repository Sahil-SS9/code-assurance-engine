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
    propagate as SecurityRefusal/StateRootUnavailable — never a silent fallback, never a write."""
    from hermes_code_assurance import service

    def state_root(args):
        return str(_resolve_state_dir(args.get("state_dir")))

    def handler_for(fn):
        def call(args):
            root = state_root(args)
            try:
                return _json(fn(root, args))
            except (SecurityRefusal, StateRootUnavailable) as exc:
                return _json({"refused": True, "error": f"{type(exc).__name__}: {exc}"})
        return call

    return {
        "assure_inspect": {
            "schema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"}, "state_dir": {"type": "string"},
                    "base": {"type": "string"}, "head": {"type": "string"},
                },
                "required": ["repo"],
            },
            "handler": handler_for(
                lambda root, args: service.inspect_candidate(
                    root, args["repo"], base=args.get("base"), head=args.get("head")
                )
            ),
            "description": "Read-only candidate inventory + non-executable contract proposal.",
        },
        "assure_plan_checks": {
            "schema": {
                "type": "object",
                "properties": {
                    "state_dir": {"type": "string"},
                    "contract": {"type": "object"},
                    "assessment_id": {"type": "string"},
                },
                "required": ["contract"],
            },
            "handler": handler_for(
                lambda root, args: service.plan_checks(
                    root, args["contract"], args.get("assessment_id")
                )
            ),
            "description": "Freeze a reviewed CheckContract v1 onto an assessment.",
        },
        "assure_status": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
            "handler": handler_for(
                lambda root, args: service.status(root, args["assessment_id"])
            ),
            "description": "Assessment state + per-check statuses.",
        },
        "assure_verify": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
            "handler": handler_for(
                lambda root, args: service.verify(root, args["assessment_id"])
            ),
            "description": "Reverify persisted receipts (identity layers) and compute overall.",
        },
        "assure_report": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"},
                                                       "fmt": {"enum": ["markdown", "json"]}},
                       "required": ["assessment_id"]},
            "handler": handler_for(
                lambda root, args: service.report(root, args["assessment_id"],
                                                  fmt=args.get("fmt", "markdown"))
            ),
            "description": "Render the scoped private assessment report (markdown/json).",
        },
        "assure_run": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "repo": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
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
        except Exception as exc:  # noqa: BLE001 — surfaces never raise into the host turn
            return f"assure command error: {exc}"
    return handle


def _cli_setup(subparser):
    from hermes_code_assurance import cli as cli_mod

    return cli_mod.build_parser()


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
                setup_fn=_cli_setup,
                handler_fn=None,
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
