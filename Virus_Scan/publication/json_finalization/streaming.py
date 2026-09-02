"""Canonical final and partial scan-result publication orchestration."""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.worker_record import make_json_safe as contract_make_json_safe
from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta
from Virus_Scan.publication.json_finalization.checkpoint_journal import append_checkpoint_delta
from Virus_Scan.publication.json_finalization.stream_commit import (
    commit_streamed_file,
    finalize_partial_evidence,
    write_mapping_temporary,
    write_scalar_temporary,
)
from Virus_Scan.publication.json_finalization.stream_file_io import (
    finalizer_tmp_path,
    resolved_output_path,
    safe_unlink,
    stream_write_failure,
)
from Virus_Scan.publication.json_finalization.stream_record import (
    json_safe_record,
    stream_result_items,
)
from Virus_Scan.runtime.api import deterministic_mode_enabled
from Virus_Scan.publication.scan_result_ledger import ScanResultLedgerAccumulator
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name


def _record_materializer(value: object) -> object:
    return contract_make_json_safe(value)


def _selected_materializer(candidate: object | None) -> object:
    return candidate if callable(candidate) else _record_materializer


def _deterministic_streaming_enabled(value: bool | None) -> bool:
    if value is None:
        return deterministic_mode_enabled()
    if type(value) is bool:
        return value
    raise TypeError("unsupported_final_json_deterministic_mode:" + no_hook_type_name(value))


def _write_mapping_output(
    resolved: str,
    results: object,
    *,
    make_json_safe: object | None,
    fsync_file: bool,
    verify_written: bool,
    deterministic_mode: bool | None,
    compact_records: bool,
    ledger_accumulator: ScanResultLedgerAccumulator | None,
) -> bool:
    temporary = None
    try:
        Path(resolved).parent.mkdir(parents=True, exist_ok=True)
        temporary = finalizer_tmp_path(resolved)
        items = stream_result_items(
            results,
            deterministic=_deterministic_streaming_enabled(deterministic_mode),
        )
        expected = write_mapping_temporary(
            temporary,
            items,
            make_json_safe=_selected_materializer(make_json_safe),
            compact_records=compact_records,
            fsync_file=fsync_file,
            ledger_accumulator=ledger_accumulator,
        )
        commit_streamed_file(
            temporary,
            resolved,
            expected,
            fsync_file=fsync_file,
            verify_written=verify_written,
        )
        finalize_partial_evidence(resolved, fsync_file=fsync_file)
        return True
    except TELEMETRY_FAILURE_ERRORS as exc:
        safe_unlink(temporary)
        raise stream_write_failure(resolved, exc) from exc


def stream_json_mapping(
    path: str,
    results: Mapping[str, object],
    *,
    make_json_safe: object | None = None,
    fsync_file: bool = True,
    verify_written: bool = True,
    deterministic_mode: bool | None = None,
    compact_records: bool = True,
    ledger_accumulator: ScanResultLedgerAccumulator | None = None,
) -> bool:
    return _write_mapping_output(
        resolved_output_path(path),
        results,
        make_json_safe=make_json_safe,
        fsync_file=fsync_file,
        verify_written=verify_written,
        deterministic_mode=deterministic_mode,
        compact_records=compact_records,
        ledger_accumulator=ledger_accumulator,
    )


def write_partial_scan_results(
    path: str,
    results: object,
    *,
    make_json_safe: object | None = None,
) -> bool:
    """Commit an incremental journal delta or one explicit snapshot."""
    if type(results) is JsonSafeCheckpointDelta:
        return append_checkpoint_delta(path, results)
    return stream_json_mapping(
        path,
        results,
        make_json_safe=make_json_safe,
        fsync_file=False,
        verify_written=False,
        compact_records=False,
    )


def _finalize_scalar(
    path: str,
    result: object,
    *,
    make_json_safe: object | None,
) -> bool:
    resolved = resolved_output_path(path)
    temporary = None
    try:
        Path(resolved).parent.mkdir(parents=True, exist_ok=True)
        temporary = finalizer_tmp_path(resolved)
        expected = write_scalar_temporary(
            temporary,
            json_safe_record(result, _selected_materializer(make_json_safe)),
        )
        commit_streamed_file(
            temporary,
            resolved,
            expected,
            fsync_file=True,
            verify_written=True,
        )
        finalize_partial_evidence(resolved, fsync_file=True)
        return True
    except TELEMETRY_FAILURE_ERRORS as exc:
        safe_unlink(temporary)
        raise stream_write_failure(resolved, exc) from exc


def finalize_scan_results(
    path: str,
    results: Mapping[str, object],
    *,
    make_json_safe: object | None = None,
    deterministic_mode: bool | None = None,
    ledger_accumulator: ScanResultLedgerAccumulator | None = None,
) -> bool:
    """Write final results once with bounded verification and atomic replacement."""
    if isinstance(results, Mapping):
        return stream_json_mapping(
            path,
            results,
            make_json_safe=make_json_safe,
            fsync_file=True,
            deterministic_mode=deterministic_mode,
            ledger_accumulator=ledger_accumulator,
        )
    return _finalize_scalar(
        path,
        results,
        make_json_safe=make_json_safe,
    )


__all__ = (
    "finalize_scan_results",
    "stream_json_mapping",
    "write_partial_scan_results",
)
