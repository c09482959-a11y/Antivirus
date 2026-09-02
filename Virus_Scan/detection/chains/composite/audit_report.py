"""Tag/chain registry audit reporting owned by composite chain detection."""

from Virus_Scan.detection.chains.composite.behavior_mapping import chain_expected_behavior_mapping
from Virus_Scan.detection.registries.chain_registry import (
    CONCRETE_SCORE_TAGS,
    CONTEXTUAL_DANGEROUS_ANCHOR_TAGS,
    SUPPORT_ONLY_SCORE_TAGS,
    TAG_BEHAVIOR_SCOREABLE,
    CHAIN_REGISTRY_VERSION,
    CANONICAL_CHAIN_RULES,
    CHAIN_CONCLUSION_TAGS,
    TAG_RISK_SCORES,
    TAG_STRUCTURAL_ONLY,
    TAG_WEAK_CONTEXT_ONLY,
)
from Virus_Scan.detection.tags.heuristics.behavior_buckets import BUCKET_TAGS
from Virus_Scan.detection.tags.heuristics.behavior_mapping import tag_expected_behavior_mapping
from Virus_Scan.detection.tags.heuristics.normalization_runtime import canonical_tag_name
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.chains.composite.text_boundaries import exact_mapping_keys, exact_mapping_values, exact_record_value
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence



def _audit_registry_tags(failures: list[object]) -> set[object]:
    tags: set[object] = set()
    registry_sources = (
        TAG_WEAK_CONTEXT_ONLY,
        TAG_STRUCTURAL_ONLY,
        TAG_BEHAVIOR_SCOREABLE,
        CHAIN_CONCLUSION_TAGS,
        TAG_RISK_SCORES,
        CONCRETE_SCORE_TAGS,
        SUPPORT_ONLY_SCORE_TAGS,
        CONTEXTUAL_DANGEROUS_ANCHOR_TAGS,
    )
    for source in registry_sources:
        mapping_keys = exact_mapping_keys(source)
        if mapping_keys:
            tags.update(mapping_keys)
        elif type(source) in (tuple, list, set, frozenset):
            tags.update(source)
        else:
            failures.append(recoverable_failure_evidence(
                stage_name="tag_chain_audit_registry_source",
                error=TypeError("unsupported_registry_source_type"),
                error_source="detection.chains.composite.audit_report",
                affected_context=type(source).__name__,
            ))
    return tags


def _add_bucket_audit_tags(tags: set[object], failures: list[object]) -> None:
    bucket_values = exact_mapping_values(BUCKET_TAGS)
    if bucket_values:
        for values in bucket_values:
            if type(values) in (tuple, list, set, frozenset):
                tags.update(values)
    else:
        failures.append(recoverable_failure_evidence(
            stage_name="tag_chain_audit_bucket_tags",
            error=TypeError("bucket_tags_unavailable"),
            error_source="detection.chains.composite.audit_report",
            affected_context="BUCKET_TAGS",
        ))



def _first_audit_record_value(record: object, keys: tuple[str, ...], default: object) -> object:
    for key in keys:
        value = exact_record_value(record, key)
        if value:
            return value
    return default


def _audit_chain_name_pattern(chain: object) -> tuple[object, object]:
    if type(chain) is dict:
        name = _first_audit_record_value(chain, ("name", "chain", "id"), "unnamed_chain")
        pattern = _first_audit_record_value(chain, ("pattern", "tags", "signals"), [])
    elif isinstance(chain, (list, tuple)) and chain:
        name = chain[0]
        pattern = chain[1] if len(chain) > 1 else []
    else:
        name = "unsupported_chain_record"
        pattern = []
    return name, pattern



def _audit_chain_records(failures: list[object]) -> list[object]:
    records: list[object] = []
    try:
        for rule in CANONICAL_CHAIN_RULES:
            records.append(chain_expected_behavior_mapping(rule))
    except RECOVERABLE_RUNTIME_ERRORS as error:
        failures.append(recoverable_failure_evidence(
            stage_name="tag_chain_audit_chain_records",
            error=error,
            error_source="detection.chains.composite.audit_report",
            affected_context="CANONICAL_CHAIN_RULES",
        ))
    return records


def runtime_tag_chain_audit_report() -> object:
    """Return a compact registry and chain mapping audit report."""
    failures: list[object] = []
    tags = _audit_registry_tags(failures)
    _add_bucket_audit_tags(tags, failures)
    tag_records = [
        tag_expected_behavior_mapping(tag)
        for tag in sorted(canonical_tag_name(item) for item in tags if canonical_tag_name(item))
    ]
    dead = [
        exact_record_value(record, "tag")
        for record in tag_records
        if exact_record_value(record, "role") == "unknown"
        and exact_record_value(record, "bucket") == "other_behavior"
        and exact_record_value(record, "risk_score") == 0.0
    ]
    chain_records = _audit_chain_records(failures)
    failure_payload = failure_evidence_payload(tuple(failures))
    return {
        "version": CHAIN_REGISTRY_VERSION,
        "tag_count": len(tag_records),
        "chain_count": len(chain_records),
        "dead_or_unmapped_tags": sorted(set(dead)),
        "tag_evidence_policy": "immutable canonical records own observation, derivation, correlation-root, and scoreability identity; strings are deterministic publication only",
        "json_engine_extension_policy": "engine selects JSON file; normalize_profile_extension(get_scan_extension(path)) selects the per-extension baseline bucket",
        "yara_policy": "YARA evidence remains an independent provenance channel and cannot manufacture chain steps or chain candidates",
        "tags": tag_records,
        "chains": chain_records,
        "degraded": failure_payload["degraded"],
        "failure_evidence": failure_payload["failures"],
        "failure_count": failure_payload["failure_count"],
    }
