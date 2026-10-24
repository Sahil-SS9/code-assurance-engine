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
- Data-dir resolution per call follows the refusal ladder (trusted registered override →
  args `state_dir` only when inside a permitted root → host-active plugin-data root). There is
  NO bare-home fallback: when no trusted root resolves (e.g. the plugin runs outside a Hermes
  process with no SDK seam), the call REFUSES with `StateRootUnavailable` and writes nothing
  (regression-tested in `tests/unit/test_c4_data_dir.py`).
- CLI surface (`assure` / `hermes assure`): an explicit `--state-dir` is honoured for the
  OPERATOR surface (documented trust boundary above); model-controlled tool args keep the
  guarded path.
- Git refs from model-supplied `base`/`head` are resolved to SHAs and option-like values are
  refused before any git call (see threat-model "Model-supplied git refs").
