"""Binary failover evidence helpers owned by the binary scanner domain."""

from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags


def _binary_failover_text(value: object, *, missing_reason: str, unsupported_reason: str, default: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return default
    return text.strip().lower() or default


def _binary_failover_base_tags(base_tags: object) -> list[str]:
    if type(base_tags) not in (list, tuple):
        return []
    return [str.__str__(tag) for tag in base_tags if type(tag) is str]


def _append_missing_tags(final_tags: object, evidence_tags: list[str]) -> None:
    if type(final_tags) is not list:
        return
    existing = {str.__str__(tag) for tag in final_tags if type(tag) is str}
    for tag in evidence_tags:
        if tag not in existing:
            final_tags.append(tag)
            existing.add(tag)


def append_binary_failover_evidence(final_tags: object, category: str, exc: BaseException | str, base_tags: list[str], *, state: str = 'degraded') -> list[str]:
    """Append canonical binary failover evidence tags to a mutable tag list."""
    category_text = _binary_failover_text(
        category,
        missing_reason="missing_binary_failover_category",
        unsupported_reason="unsafe_binary_failover_category_rejected",
        default="unsafe_binary_failover_category_rejected",
    )
    state_text = _binary_failover_text(
        state,
        missing_reason="missing_binary_failover_state",
        unsupported_reason="unsafe_binary_failover_state_rejected",
        default="degraded",
    )
    evidence_tags = scanner_failure_evidence_tags(
        'binary',
        category_text,
        exc,
        [*_binary_failover_base_tags(base_tags), 'binary_failover_final_json_must_record'],
        state=state_text,
        error_category='binary_' + category_text,
        error_source='binary.should_binary_failover',
        file_type='binary',
    )
    _append_missing_tags(final_tags, evidence_tags)
    return evidence_tags


__all__ = ('append_binary_failover_evidence',)
