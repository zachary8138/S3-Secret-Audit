from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, TextIO


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    resource: str
    summary: str
    details: dict[str, Any]


def _finding_to_json(f: Finding) -> str:
    return json.dumps(
        {
            "check": f.check,
            "severity": f.severity.value,
            "resource": f.resource,
            "summary": f.summary,
            "details": f.details,
        },
        sort_keys=True,
    )


def write_finding(f: Finding, out_fh: Optional[TextIO] = None) -> None:
    line = _finding_to_json(f)
    print(f"[{f.severity.value.upper()}] {f.check} {f.resource} - {f.summary}", file=sys.stdout)
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
