"""Hermes host adapter: register tools / slash command / CLI subcommand / shipped skill.

Rules: no Hermes imports at module import time; every host surface is capability-probed via
hasattr and skipped loudly when missing; no load-time scans, no unsolicited model calls, no
parallel approval service. All surfaces call the shared service facade; the plugin data
directory is RE-RESOLVED on every call so the plugin never caches a global path across profiles
(plugin_data_dir contract).
"""

from __future__ import annotations

from pathlib import Path

_TOOLSET = "code-assurance"
_PLUGIN_DIR_NAME = "code-assurance-engine"


def _data_dir() -> Path:
    """Resolve the plugin's state directory per call (follows any active Hermes home)."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore[import-untyped]

        return Path(plugin_data_dir(_PLUGIN_DIR_NAME))
    except Exception:  # noqa: BLE001 — deliberate: any import failure falls back to a local dir
        return Path.home() / ".hermes" / "plugin-data" / _PLUGIN_DIR_NAME


def _tool_schemas():
    """Every handler resolves its state dir per call: explicit ``state_dir`` override or the
    fresh ``_data_dir()`` result — never a cached path captured at registration time."""
    from hermes_code_assurance import service

    def resolved(args):
        return args.get("state_dir") or str(_data_dir())

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
            "handler": lambda args: _json(
                service.inspect_candidate(resolved(args), args["repo"],
                                          base=args.get("base"), head=args.get("head"))
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
            "handler": lambda args: _json(
                service.plan_checks(resolved(args), args["contract"], args.get("assessment_id"))
            ),
            "description": "Freeze a reviewed CheckContract v1 onto an assessment.",
        },
        "assure_status": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
            "handler": lambda args: _json(
                service.status(resolved(args), args["assessment_id"])
            ),
            "description": "Assessment state + per-check statuses.",
        },
        "assure_verify": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
            "handler": lambda args: _json(
                service.verify(resolved(args), args["assessment_id"])
            ),
            "description": "Reverify persisted receipts (identity layers) and compute overall.",
        },
        "assure_report": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "state_dir": {"type": "string"},
                                                       "fmt": {"enum": ["markdown", "json"]}},
                       "required": ["assessment_id"]},
            "handler": lambda args: _json(
                service.report(resolved(args), args["assessment_id"],
                               fmt=args.get("fmt", "markdown"))
            ),
            "description": "Render the scoped private assessment report (markdown/json).",
        },
        "assure_run": {
            "schema": {"type": "object", "properties": {"assessment_id": {"type": "string"},
                                                       "repo": {"type": "string"},
                                                       "state_dir": {"type": "string"}},
                       "required": ["assessment_id"]},
            "handler": lambda args: _json(
                service.run_checks(resolved(args), args["assessment_id"], caller="plugin-tool")
            ),
            "description": "SOLE repository-code-executing tool; unavailable until authority + "
                           "isolation gates pass (records EXECUTION_UNAVAILABLE).",
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
    """Register every supported host surface. Fail-closed: missing surfaces skipped + recorded."""
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
