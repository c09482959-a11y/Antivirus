"""Streaming payload write, atomic commit, and checkpoint-retention steps."""
from __future__ import annotations

import json
import os
from pathlib import Path

from Virus_Scan.publication.json_finalization.checkpoint_evidence import (
    partial_output_path,
    preserve_checkpoint_evidence,
)
from Virus_Scan.publication.json_finalization.stream_digest import (
    DigestingBinaryWriter,
    file_digest_and_size,
)
from Virus_Scan.publication.json_finalization.stream_file_io import (
    safe_unlink,
)
from Virus_Scan.publication.json_finalization.stream_record import json_safe_record
from Virus_Scan.publication.scan_result_ledger import ScanResultLedgerAccumulator
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
)


def write_mapping_temporary(
    temporary: str,
    items: tuple[tuple[str, object], ...],
    *,
    make_json_safe: object | None,
    compact_records: bool,
    fsync_file: bool,
    ledger_accumulator: ScanResultLedgerAccumulator | None,
) -> tuple[str, int]:
    with Path(temporary).open("wb") as stream:
        writer = DigestingBinaryWriter(stream)
        writer.write_text("{")
        for index, (key_text, value) in enumerate(items):
            if index:
                writer.write_text(",")
            payload = json_safe_record(
                value,
                make_json_safe,
                key_text=key_text,
                compact_records=compact_records,
            )
            writer.write_text(json.dumps(key_text, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            writer.write_text(":")
            writer.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            if type(ledger_accumulator) is ScanResultLedgerAccumulator:
                ledger_accumulator.observe(key_text, payload)
        writer.write_text("}")
        stream.flush()
        if fsync_file:
            flush_open_writable_file(stream.fileno())
        return writer.result()


def write_scalar_temporary(temporary: str, payload: object) -> tuple[str, int]:
    with Path(temporary).open("wb") as stream:
        writer = DigestingBinaryWriter(stream)
        writer.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
        stream.flush()
        flush_open_writable_file(stream.fileno())
        return writer.result()


def commit_streamed_file(
    temporary: str,
    resolved: str,
    expected: tuple[str, int],
    *,
    fsync_file: bool,
    verify_written: bool,
) -> None:
    digest, size = expected
    if size < 2:
        raise IOError("streamed_results_too_small")
    durable_replace_regular_file(Path(temporary), Path(resolved))
    if (verify_written or fsync_file) and file_digest_and_size(resolved) != (digest, size):
        raise ValueError("streamed_results_final_verify_failed")


def finalize_partial_evidence(resolved: str, *, fsync_file: bool) -> None:
    partial = Path(partial_output_path(resolved))
    if fsync_file and partial.exists() and not preserve_checkpoint_evidence(resolved):
        raise RuntimeError("partial_checkpoint_evidence_publication_failed")
    safe_unlink(partial_output_path(resolved))


__all__ = (
    "commit_streamed_file",
    "finalize_partial_evidence",
    "write_mapping_temporary",
    "write_scalar_temporary",
)
