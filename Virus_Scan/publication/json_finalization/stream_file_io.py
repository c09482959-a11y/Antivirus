"""Atomic final-result filesystem ownership."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.publication.json_finalization.base_projection_boundaries import projection_path_result
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name


def resolved_output_path(path: object) -> str:
    path_text, reason = projection_path_result(path)
    if reason:
        raise TypeError("unsupported_final_json_output_path:" + no_hook_type_name(path))
    return str(Path(path_text).resolve())


def finalizer_tmp_path(path: object) -> str:
    resolved = Path(resolved_output_path(path))
    descriptor, temporary = tempfile.mkstemp(
        prefix=(resolved.name or "scan_results.json") + ".",
        suffix=".tmp",
        dir=str(resolved.parent),
        text=True,
    )
    os.close(descriptor)
    return temporary


def safe_unlink(path: str | None) -> bool:
    if not path:
        return False
    try:
        Path(path).unlink()
        return True
    except FileNotFoundError:
        return False
    except TELEMETRY_FAILURE_ERRORS:
        return False


def stream_write_failure(path: str, exc: BaseException) -> RuntimeError:
    return RuntimeError(
        "final scan_results.json write failed: final_json_stream_write_failed:path="
        + path
        + ":reason="
        + no_hook_type_name(exc)
    )


__all__ = (
    "finalizer_tmp_path",
    "resolved_output_path",
    "safe_unlink",
    "stream_write_failure",
)
