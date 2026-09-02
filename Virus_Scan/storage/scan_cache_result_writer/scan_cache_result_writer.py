"""Canonical parent-side writer for derived final semantic scan-cache results."""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.contracts.result_record import (
    normalize_result_record,
    result_is_cache_reusable,
)
from Virus_Scan.contracts.scan_cache_fingerprint import ScanCacheExecutionIdentity
from Virus_Scan.contracts.scan_cache_publication import (
    ScanCachePublicationIdentity,
    scan_cache_publication_identity_from_result,
)
from Virus_Scan.core.jsonio import deepcopy_jsonable
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.storage.cache_repository import scan_cache_repository
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleError
from Virus_Scan.utils.tagging import norm_lower_set


def _lower_text(value: object) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scan_cache_result_text",
        unsupported_reason="unsafe_scan_cache_result_text_rejected",
    )
    if reason:
        return "", reason
    return str.lower(text), ""


def _stable_result_projection(result: dict[str, object]) -> dict[str, object] | None:
    """Remove run-local scheduler timing/process evidence before cache persistence."""
    cached_result = deepcopy_jsonable(result)
    if type(cached_result) is not dict:
        return None
    for field in (
        "cache_hit",
        "cache_source",
        "scan_duration_seconds",
        "slow_file_seconds",
        "timeout_budget",
        "timeout_evidence",
        "worker_state",
    ):
        cached_result.pop(field, None)
    return cached_result


@dataclass(frozen=True, slots=True)
class ScanCacheResultWriter:
    """One session-bound owner for writing derived final semantic cache results."""

    execution_identity: ScanCacheExecutionIdentity

    def __post_init__(self) -> None:
        if type(self.execution_identity) is not ScanCacheExecutionIdentity:
            raise TypeError("scan_cache_result_writer_execution_identity_required")

    def __call__(self, result: object) -> bool:
        """Write one reusable result without becoming an authoritative result barrier."""
        execution_identity = self.execution_identity
        if not execution_identity.cache_eligible:
            return False
        if type(result) is not dict:
            return False
        publication_identity: ScanCachePublicationIdentity | None = None
        try:
            publication_identity = scan_cache_publication_identity_from_result(result)
            if publication_identity is None:
                return False
            repository = scan_cache_repository()
            if not repository.enabled():
                return False
            if dict.get(result, "cache_hit") is True:
                return repository.record_result_hit(
                    content_sha256=publication_identity.content_sha256,
                    content_size=publication_identity.content_size,
                    canonical_path=publication_identity.canonical_path,
                    file_name=publication_identity.file_name,
                    execution_identity=execution_identity,
                    stat_mtime_ns=publication_identity.stat_mtime_ns,
                )
            raw_classification = dict.get(result, "classification")
            if raw_classification is None:
                raw_classification = dict.get(result, "class")
            _classification, classification_reason = _lower_text(raw_classification)
            if classification_reason:
                return False
            normalized = normalize_result_record(
                result,
                file_path=publication_identity.canonical_path,
                source="scan_cache_store",
            )
            if normalized is None:
                return False
            raw_classification = dict.get(normalized, "classification")
            if raw_classification is None:
                raw_classification = dict.get(normalized, "class")
            classification, classification_reason = _lower_text(raw_classification)
            if classification_reason:
                return False
            tags = norm_lower_set(dict.get(normalized, "tags") or [])
            if "tag_normalization_failure_evidence" in tags:
                return False
            raw_integrity = dict.get(normalized, "scan_integrity")
            integrity = raw_integrity if type(raw_integrity) is dict else {}
            if (
                classification in {"error", "timeout", "incomplete_scan"}
                or dict.get(normalized, "error")
                or "scan_incomplete" in tags
                or dict.get(integrity, "allow_learning") is False
                or not result_is_cache_reusable(normalized)
            ):
                return False
            cached_result = _stable_result_projection(normalized)
            if cached_result is None:
                return False
            return repository.put_result(
                content_sha256=publication_identity.content_sha256,
                content_size=publication_identity.content_size,
                canonical_path=publication_identity.canonical_path,
                file_name=publication_identity.file_name,
                execution_identity=execution_identity,
                result=cached_result,
                stat_mtime_ns=publication_identity.stat_mtime_ns,
            )
        except (sqlite3.Error, SQLiteLifecycleError, *RECOVERABLE_RUNTIME_ERRORS) as exc:
            path_text = (
                publication_identity.canonical_path
                if type(publication_identity) is ScanCachePublicationIdentity
                else "unknown_path"
            )
            log_error(
                "".join(
                    (
                        "store SQLite scan cache failed for ",
                        path_text,
                        ": ",
                        no_hook_type_name(exc),
                    )
                )
            )
            return False


__all__ = ("ScanCacheResultWriter",)
