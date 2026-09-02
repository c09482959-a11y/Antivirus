"""Canonical scan-runtime process entrypoint for UMIGE.

This module is scan-entrypoint-only. Runtime snapshots/config/path state stay in
``Virus_Scan.runtime`` and cross-domain scanner, detection, scheduler, YARA,
model, and reporting activation is owned by ``Virus_Scan.orchestration``. The
static import manifest is surfaced as names so packagers can audit visibility
without making this entrypoint own domain internals.
"""
from __future__ import annotations

import sys
from typing import Optional, Sequence

from Virus_Scan.cli.args import parse_args
import Virus_Scan.orchestration.bootstrap_initialization as _orchestration_bootstrap
from Virus_Scan.orchestration.lifecycle import run_scan_lifecycle

_STATIC_RUNTIME_IMPORT_OWNER_NAMES = tuple(
    sorted(
        {
            "Virus_Scan.orchestration",
            _orchestration_bootstrap.__name__,
            "Virus_Scan.orchestration.lifecycle",
            "Virus_Scan.scheduler.api.runner",
        }
        | set(_orchestration_bootstrap.BOOTSTRAP_REQUIRED_MODULE_NAMES)
    )
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(tokens)
    return run_scan_lifecycle(args=args, argv=tokens)


if __name__ == "__main__":
    raise SystemExit(main())
