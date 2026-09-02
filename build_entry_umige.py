"""Nuitka/source build entrypoint for UMIGE.

Delegates normal startup to the canonical source process entrypoint. When the
packaged executable is re-executed with the internal runtime-child token, this
entrypoint transfers ownership to the scan-only runtime entry module.
"""
# nuitka-project: --user-package-configuration-file={MAIN_DIRECTORY}/umige.nuitka-package.config.yml
# nuitka-project: --user-plugin={MAIN_DIRECTORY}/tools/nuitka_packaging/exact_runtime_plugin.py
from __future__ import annotations

import multiprocessing
import sys
_RUNTIME_CHILD_ARG = "--umige-runtime-child"


def _is_runtime_child(argv: tuple[str, ...]) -> bool:
    return bool(argv) and argv[0] == _RUNTIME_CHILD_ARG


_ARGV = tuple(sys.argv[1:])

if _is_runtime_child(_ARGV):
    from Virus_Scan import runtime_main as _runtime_child_entrypoint

    def _run() -> int:
        return int(_runtime_child_entrypoint.main(_ARGV[1:]))
else:
    from Virus_Scan.main import main as _startup_entrypoint

    def _run() -> int:
        return int(_startup_entrypoint(_ARGV))


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(_run())
