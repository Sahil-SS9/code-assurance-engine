"""Parser registry and shared ParseOutcome vocabulary."""

from __future__ import annotations

from dataclasses import dataclass, field

PARSERS = ("junit-xml", "pytest-terminal")


@dataclass
class ParseOutcome:
    """What a parser claims it OBSERVED. Unknown stays unknown — never silently zero."""

    parser_id: str
    counts: dict  # collected/passed/failed/errors/skipped (None where not knowable)
    status_hint: str  # "clean" | "unknown"
    reasons: list = field(default_factory=list)
    discrepancies: list = field(default_factory=list)


from . import junit_xml, pytest_terminal


def registry() -> dict:
    return {"junit-xml": junit_xml, "pytest-terminal": pytest_terminal}
