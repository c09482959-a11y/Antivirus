"""Archive ecosystem complexity gates."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float, no_hook_text
from Virus_Scan.scanners.archives.ecosystem_evidence import append_archive_ecosystem_boundary_evidence
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot

_ARCHIVE_POLICY = load_archive_policy_snapshot()
_NESTED_ARCHIVE_SUFFIXES = _ARCHIVE_POLICY.nested_archive_suffixes

@dataclass(frozen=True, slots=True)
class ArchiveEcosystemGateRequest:
    tags: list[str]
    suspicious: bool
    ecosystem_score: object
    member_count: object
    max_members: object
    path: object = None

def _archive_ecosystem_nonnegative_int(value: object, reason: str, *, default: int = 0) -> tuple[int, int]:
    numeric, numeric_reason = no_hook_exact_nonnegative_int(value, default=default, reason=reason, non_finite_reason=reason)
    return numeric, 1 if numeric_reason else 0

def _archive_ecosystem_name_items(names: object) -> tuple[tuple[object, ...], int]:
    if isinstance(names, tuple) and type(names) is tuple:
        return names, 0
    if isinstance(names, list) and type(names) is list:
        return tuple(names), 0
    return (), 1

def _archive_ecosystem_name_texts(names: object) -> tuple[tuple[str, ...], int]:
    name_items, unsafe_count = _archive_ecosystem_name_items(names)
    safe_names: list[str] = []
    for name in name_items:
        text, reason = no_hook_text(
            name,
            missing_reason="archive_ecosystem_name_missing",
            unsupported_reason="archive_ecosystem_name_unsafe",
        )
        if reason:
            unsafe_count += 1
            continue
        safe_names.append(text)
    return tuple(safe_names), unsafe_count

def archive_ecosystem_inputs(members: int, compressed_bytes: int, extracted_bytes: int, depth: int, names: tuple[str, ...]) -> dict[str, int | float]:
    """Build deterministic archive ecosystem scoring inputs."""
    safe_members, member_failures = _archive_ecosystem_nonnegative_int(members, "archive_ecosystem_members_unsafe")
    safe_compressed, compressed_failures = _archive_ecosystem_nonnegative_int(compressed_bytes, "archive_ecosystem_compressed_bytes_unsafe")
    safe_extracted, extracted_failures = _archive_ecosystem_nonnegative_int(extracted_bytes, "archive_ecosystem_extracted_bytes_unsafe")
    safe_depth, depth_failures = _archive_ecosystem_nonnegative_int(depth, "archive_ecosystem_depth_unsafe")
    safe_names, name_failures = _archive_ecosystem_name_texts(names)
    corrupt_members = member_failures + compressed_failures + extracted_failures + depth_failures + name_failures
    non_empty_names = tuple(name for name in safe_names if name != "")
    return {
        "members": safe_members,
        "compressed_bytes": safe_compressed,
        "extracted_bytes": safe_extracted,
        "depth": safe_depth,
        "nested_archives": sum(1 for name in non_empty_names if str.lower(name).endswith(_NESTED_ARCHIVE_SUFFIXES)),
        "corrupt_members": corrupt_members,
        "distinct_extensions": len({PurePosixPath(name).suffix.lower() for name in non_empty_names}) or 1,
    }

def apply_ecosystem_gate(request: ArchiveEcosystemGateRequest) -> tuple[bool, int]:
    """Apply immutable archive policy score gates and return member scan limit."""
    suspicious = request.suspicious
    safe_score, score_reason = no_hook_finite_float(
        request.ecosystem_score,
        default=0.0,
        minimum=0.0,
        reason="archive_ecosystem_score_unsafe",
        non_finite_reason="archive_ecosystem_score_unsafe",
    )
    safe_member_count, member_reason = _archive_ecosystem_nonnegative_int(
        request.member_count,
        "archive_ecosystem_member_count_unsafe",
    )
    safe_max_members, max_reason = _archive_ecosystem_nonnegative_int(
        request.max_members,
        "archive_ecosystem_max_members_unsafe",
        default=1,
    )
    safe_limit_cap = max(1, safe_max_members)
    limit = safe_member_count
    if score_reason or member_reason or max_reason:
        request.tags[:] = append_archive_ecosystem_boundary_evidence(
            request.tags,
            path=request.path,
            boundary_tag="archive_ecosystem_gate_input_unsafe",
            score=safe_score,
            limited=True,
        )
        return True, max(1, min(safe_member_count or 1, max(1, safe_limit_cap // 2)))
    if safe_score >= _ARCHIVE_POLICY.ecosystem_score_limit:
        request.tags[:] = append_archive_ecosystem_boundary_evidence(
            request.tags,
            path=request.path,
            boundary_tag="archive_ecosystem_score_limit",
            score=safe_score,
            limited=True,
        )
        suspicious = True
        limit = max(1, min(safe_member_count, safe_limit_cap // 2))
    elif safe_score >= _ARCHIVE_POLICY.ecosystem_score_warn:
        request.tags[:] = append_archive_ecosystem_boundary_evidence(
            request.tags,
            path=request.path,
            boundary_tag="archive_ecosystem_high_complexity",
            score=safe_score,
            limited=False,
        )
        suspicious = True
    return suspicious, limit

__all__ = (
    'ArchiveEcosystemGateRequest',
    'apply_ecosystem_gate',
    'archive_ecosystem_inputs',
)
