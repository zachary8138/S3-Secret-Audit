from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, Optional

from s3_audit.audit import S3AuditConfig, run_s3_audit
from s3_audit.findings import Finding, Severity, write_finding


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="s3-secret-audit",
        description="Audit AWS S3 for public exposure and leaked secrets.",
    )
    p.add_argument(
        "--regions",
        nargs="*",
        default=[],
        help="Optional AWS regions (not required for S3; reserved for future use).",
    )
    p.add_argument("--scan-objects", action="store_true", help="Sample objects and scan contents.")
    p.add_argument("--max-objects-per-bucket", type=int, default=25)
    p.add_argument(
        "--max-bytes-per-object",
        type=int,
        default=256_000,
        help="Maximum bytes to fetch per object when scanning.",
    )
    p.add_argument(
        "--key-prefixes",
        nargs="*",
        default=[],
        help="Optional key prefixes to prioritize (e.g. '', 'backup/', 'config/').",
    )
    p.add_argument(
        "--buckets",
        nargs="*",
        default=[],
        help="Optional bucket name(s) to audit. Default: all buckets visible to this identity.",
    )
    p.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Optional path to write findings as JSON Lines.",
    )
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit non-zero if any finding at/above severity appears.",
    )
    return p.parse_args(argv)


def _severity_rank(sev: Severity) -> int:
    order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    return order[sev]


def _should_fail(findings: Iterable[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = Severity(fail_on)
    t = _severity_rank(threshold)
    return any(_severity_rank(f.severity) >= t for f in findings)


def main(argv: Optional[list[str]] = None) -> int:
    ns = _parse_args(sys.argv[1:] if argv is None else argv)

    out_fh = None
    if ns.jsonl is not None:
        ns.jsonl.parent.mkdir(parents=True, exist_ok=True)
        out_fh = ns.jsonl.open("a", encoding="utf-8")

    findings: list[Finding] = []
    cfg = S3AuditConfig(
        scan_objects=bool(ns.scan_objects),
        max_objects_per_bucket=int(ns.max_objects_per_bucket),
        max_bytes_per_object=int(ns.max_bytes_per_object),
        key_prefixes=list(ns.key_prefixes),
        regions=list(ns.regions),
        buckets=list(ns.buckets),
    )

    try:
        for f in run_s3_audit(cfg):
            findings.append(f)
            write_finding(f, out_fh=out_fh)
    finally:
        if out_fh is not None:
            out_fh.close()

    if _should_fail(findings, ns.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
