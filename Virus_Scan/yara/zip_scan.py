"""Bounded YARA ZIP-member scan helpers.

This module owns ZIP archive member extraction and bounded parallel member
matching for YARA scans.  The public scan entrypoint remains
``Virus_Scan.yara.match.yara_scan_with_optional_zip``.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

import os
from pathlib import Path
import queue as _queue
import tempfile
import threading
import zipfile
from concurrent.futures import as_completed

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.resource_quotas import (
    ExtractionQuotaTracker,
    ResourceQuotaExceeded,
    extract_zip_member_with_quota,
)
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.contracts.file_fingerprint import sha256_file
from Virus_Scan.contracts.yara_hits import YaraScanResult, merge_yara_scan_results
from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool
from Virus_Scan.yara.no_hook import yara_exception_text, yara_message, yara_nonnegative_int

if TYPE_CHECKING:
    from collections.abc import Callable

QuotaStopReasons = frozenset({
    "archive_total_file_limit",
    "archive_total_byte_limit",
    "archive_member_limit",
})


def extract_yara_zip_members(zip_path: str, target_dir: str) -> tuple[str, ...]:
    """Extract scan-eligible ZIP members under the YARA archive quota."""
    with zipfile.ZipFile(zip_path, "r") as archive:
        quota = ExtractionQuotaTracker.from_env(depth=0)
        for member in archive.infolist():
            try:
                extract_zip_member_with_quota(archive, member, target_dir, quota)
            except ResourceQuotaExceeded as exc:
                log_error(yara_message("zip member quota skipped: ", member.filename, ": ", exc))
                if yara_exception_text(exc) in QuotaStopReasons:
                    break
            except SCAN_CONTENT_ERRORS as exc:
                log_error(yara_message("zip member skipped: ", member.filename, ": ", exc))
    return collect_extracted_member_paths(target_dir)


def collect_extracted_member_paths(root_dir: str) -> tuple[str, ...]:
    """Return extracted member files in deterministic path order."""
    return tuple(
        sorted(
            str(Path(root) / name)
            for root, _, files in os.walk(root_dir)
            for name in sorted(files)
        )
    )


def yara_zip_worker_count(member_count: int) -> int:
    """Bound the worker count for independent YARA member scans."""
    count = yara_nonnegative_int(member_count, default=0)
    return max(1, min(8, count, 32))


def scan_yara_zip_members(
    member_paths: tuple[str, ...],
    *,
    compiled_rules: object,
    scan_member: Callable[..., object],
    artifact_path: str,
    member_root: str,
) -> tuple[YaraScanResult, ...]:
    """Scan extracted members once each and return their exact results."""
    if not member_paths:
        return ()
    workers = yara_zip_worker_count(len(member_paths))
    if workers <= 1 or len(member_paths) <= 1:
        results: list[YaraScanResult] = []
        for path in member_paths:
            result = scan_member(
                path, compiled_rules=compiled_rules, artifact_path=artifact_path,
                archive_member=Path(path).relative_to(member_root).as_posix(),
            )
            if type(result) is not YaraScanResult:
                raise TypeError("yara_zip_member_result_invalid")
            results.append(result)
        return tuple(sorted(results, key=lambda item: item.scan_pass_id))
    return scan_yara_zip_members_parallel(
        member_paths, compiled_rules=compiled_rules, scan_member=scan_member,
        workers=workers, artifact_path=artifact_path, member_root=member_root,
    )


def scan_yara_zip_members_parallel(
    member_paths: tuple[str, ...],
    *,
    compiled_rules: object,
    scan_member: Callable[..., object],
    workers: int,
    artifact_path: str,
    member_root: str,
) -> tuple[YaraScanResult, ...]:
    """Scan extracted ZIP members once with a bounded scheduler-owned pool."""
    pending: _queue.Queue[str] = _queue.Queue()
    for path in member_paths:
        pending.put(path)
    results: list[YaraScanResult] = []
    result_lock = threading.Lock()

    def worker() -> None:
        local_results: list[YaraScanResult] = []
        while True:
            try:
                path = pending.get_nowait()
            except _queue.Empty:
                break
            try:
                result = scan_member(
                    path, compiled_rules=compiled_rules, artifact_path=artifact_path,
                    archive_member=Path(path).relative_to(member_root).as_posix(),
                )
                if type(result) is not YaraScanResult:
                    raise TypeError("yara_zip_member_result_invalid")
                local_results.append(result)
            except SCAN_CONTENT_ERRORS as exc:
                log_error(yara_message("parallel YARA zip member scan failed: ", exc))
                raise
            finally:
                pending.task_done()
        if local_results:
            with result_lock:
                results.extend(local_results)

    with SchedulerThreadPool(max_workers=workers, thread_name_prefix="umige-yara-zip-q") as executor:
        futures = [executor.submit(worker) for _ in range(workers)]
        for future in as_completed(futures):
            future.result()
    return tuple(sorted(results, key=lambda item: item.scan_pass_id))


def scan_yara_zip_archive(
    zip_path: str, *, compiled_rules: object, scan_member: Callable[..., object]
) -> YaraScanResult:
    """Extract and scan an archive, then publish one canonical parent result."""
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            member_paths = extract_yara_zip_members(zip_path, tmp_dir)
            if not member_paths:
                raise ValueError(yara_message("YARA zip scan found no extractable members: ", zip_path))
            member_results = scan_yara_zip_members(
                member_paths, compiled_rules=compiled_rules, scan_member=scan_member,
                artifact_path=zip_path, member_root=tmp_dir,
            )
            return merge_yara_scan_results(
                member_results,
                physical_target_identity="content_sha256:" + sha256_file(zip_path),
            )
    except SCAN_CONTENT_ERRORS as exc:
        log_error(yara_message("YARA zip scan failed for ", zip_path, ": ", exc))
        raise


__all__ = (
    "collect_extracted_member_paths",
    "extract_yara_zip_members",
    "scan_yara_zip_archive",
    "scan_yara_zip_members",
    "scan_yara_zip_members_parallel",
    "yara_zip_worker_count",
)
