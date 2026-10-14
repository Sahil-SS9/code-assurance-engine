# Compatibility

Validated environment (this build, observed):
- Python 3.14.7 (within Hermes's declared `>=3.11,<3.15` window — the release floor was NOT
  established by installable-host testing this build; constructor recorded as unknown).
- Linux (the only host actually exercised). Windows/macOS surfaces: untested (recorded).
- Hermes host pin consulted: NousResearch/hermes-agent @ 0e427d78 (vanilla objects verified
  locally; API facts: register_tool / register_command / register_cli_command / dispatch /
  plugin storage / LLM facade / plugins-validate). Docs drift risk: consult the pin, not docs.

Not yet established (honest unknowns, not zero):
- Python 3.11/3.12/3.13 installability (no installable-host matrix run in this build).
- Hermes Desktop compatibility (pkg pyproject version is deliberately not treated as proof).

Known fallback behaviour:
- Data-dir resolution per call tries `plugins.plugin_storage`; on import failure (e.g. plugin
  imported outside a Hermes process) falls back to `~/.hermes/plugin-data/<plugin-id>` — that
  fallback is NOT a sandbox and NOT cross-profile atomic; it exists only so tools can run.
