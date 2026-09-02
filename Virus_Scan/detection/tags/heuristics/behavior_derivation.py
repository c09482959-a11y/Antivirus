"""Canonical behavior derivation from immutable tag-evidence records."""
from __future__ import annotations

import hashlib

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    deterministic_tag_evidence_id,
    tag_evidence_records,
    tag_evidence_observation_fields,
)
from Virus_Scan.contracts.tag_vocabulary import TAG_VOCABULARY_VERSION
from Virus_Scan.contracts.tag_taxonomy import TAG_CLASS_ATOMIC_OBSERVATION
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.registries.tag_behavior.vocabulary_graph import (
    TAG_DERIVATION_GRAPH_VERSION,
    attack_phase_for_tag,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence

BEHAVIOR_DERIVATION_VERSION = "behavior_derivation_v2"

_LATERAL_ANCHORS = frozenset({
    "wmi_exec", "win32_process_create", "winrm_exec", "psexec_usage",
    "admin_share_access", "smb_activity", "impacket_exec", "remote_service_creation",
    "remote_scheduled_task", "remote_registry",
})
_REMOTE_EXECUTION_ANCHORS = frozenset({"wmi_exec", "win32_process_create", "winrm_exec", "psexec_usage"})
_CREDENTIAL_ANCHORS = frozenset({
    "credential_dump_attempt", "lsass_access", "mimikatz_credential_dump",
    "browser_credential_access", "dpapi_access", "token_secret_access",
    "credential_api_access", "static_credential_store_discovery_operation",
    "static_credential_store_query_operation", "static_decrypt_operation",
})
_EXFILTRATION_ANCHORS = frozenset({
    "http_upload", "dns_tunneling", "static_network_send_operation",
    "static_network_upload_operation",
})


def _behavior_bucket(tag: str) -> str:
    mapping = detection_registry_value("TAG_TO_BEHAVIOR", {})
    items = no_hook_mapping_items(mapping)
    bucket = next((value for key, value in items if key == tag), "other_behavior") if items is not None else "other_behavior"
    return bucket if type(bucket) is str and bucket else "other_behavior"


def _family_record(parent: TagEvidenceRecord, target: str) -> TagEvidenceRecord:
    rule_id = BEHAVIOR_DERIVATION_VERSION + ":" + target
    return TagEvidenceRecord(
        canonical_tag_id=target,
        publication_name=target,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=parent.root_observation_id,
            canonical_tag_id=target,
            evidence_kind="derived",
            source_detector=parent.source_detector,
            source_stage=parent.source_stage,
            parent_evidence_ids=(parent.evidence_id,),
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=parent.source_detector,
        source_stage=parent.source_stage,
        evidence_kind="derived",
        parent_evidence_ids=(parent.evidence_id,),
        confidence=max(0.0, min(1.0, parent.confidence * 0.9)),
        support=parent.support,
        polarity="positive",
        behavior_bucket=_behavior_bucket(target),
        attack_phase=attack_phase_for_tag(target),
        scoreability_class="support",
        correlation_group=parent.correlation_group,
        root_observation_id=parent.root_observation_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        unavailable_reason=parent.unavailable_reason,
        **tag_evidence_observation_fields(parent, directness="derived"),
    )


def _composite_root_id(target: str, parents: tuple[TagEvidenceRecord, ...]) -> str:
    roots = sorted({parent.root_observation_id for parent in parents})
    payload = "\x1f".join((target, *roots)).encode("utf-8", "strict")
    return "tag_composite_root_" + hashlib.sha256(payload).hexdigest()[:32]


def _composite_record(target: str, parents: tuple[TagEvidenceRecord, ...]) -> TagEvidenceRecord:
    root_id = parents[0].root_observation_id
    parent_ids = tuple(sorted({parent.evidence_id for parent in parents}))
    detector_names = sorted({parent.source_detector for parent in parents})
    stage_names = sorted({parent.source_stage for parent in parents})
    confidence = min((parent.confidence for parent in parents), default=0.0)
    support = min((parent.support for parent in parents), default=0.0)
    return TagEvidenceRecord(
        canonical_tag_id=target,
        publication_name=target,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=root_id,
            canonical_tag_id=target,
            evidence_kind="composite",
            source_detector="+".join(detector_names) or "behavior_derivation",
            source_stage="+".join(stage_names) or "behavior_derivation",
            parent_evidence_ids=parent_ids,
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=BEHAVIOR_DERIVATION_VERSION,
        ),
        source_detector="+".join(detector_names) or "behavior_derivation",
        source_stage="+".join(stage_names) or "behavior_derivation",
        evidence_kind="composite",
        parent_evidence_ids=parent_ids,
        confidence=confidence,
        support=support,
        polarity="positive",
        behavior_bucket=_behavior_bucket(target),
        attack_phase=attack_phase_for_tag(target),
        scoreability_class="support",
        correlation_group=target,
        root_observation_id=root_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=BEHAVIOR_DERIVATION_VERSION,
        **tag_evidence_observation_fields(parents[0], directness="derived"),
    )


def _observed_by_tag(records: tuple[TagEvidenceRecord, ...]) -> dict[str, tuple[TagEvidenceRecord, ...]]:
    grouped: dict[str, list[TagEvidenceRecord]] = {}
    for record in records:
        if (
            record.evidence_kind != "observed"
            or record.polarity != "positive"
            or record.directness != "direct"
            or record.unavailable_reason
            or tag_class_for(record.canonical_tag_id) != TAG_CLASS_ATOMIC_OBSERVATION
        ):
            continue
        grouped.setdefault(record.canonical_tag_id, []).append(record)
        raw_name = record.raw_observation_name
        if raw_name and raw_name != record.canonical_tag_id:
            grouped.setdefault(raw_name, []).append(record)
    return {tag: tuple(values) for tag, values in grouped.items()}


def _distinct_required_parents(
    grouped: dict[str, tuple[TagEvidenceRecord, ...]], required_tags: frozenset[str],
) -> tuple[TagEvidenceRecord, ...]:
    selected: list[TagEvidenceRecord] = []
    roots: set[str] = set()
    for tag in sorted(required_tags):
        candidates = grouped.get(tag, ())
        candidate = next((record for record in candidates if record.root_observation_id not in roots), None)
        if candidate is None:
            return ()
        roots.add(candidate.root_observation_id)
        selected.append(candidate)
    return tuple(selected)


def derive_behavior_evidence(records: object) -> tuple[TagEvidenceRecord, ...]:
    """Derive families/composites without allowing aliases to satisfy signal gates."""
    canonical = tag_evidence_records(records)
    grouped = _observed_by_tag(canonical)
    additions: list[TagEvidenceRecord] = []
    seen = {(record.root_observation_id, record.canonical_tag_id, record.evidence_kind) for record in canonical}

    for anchors, target in (
        (_LATERAL_ANCHORS, "lateral_movement"),
        (_REMOTE_EXECUTION_ANCHORS, "remote_execution"),
        (_CREDENTIAL_ANCHORS, "credential_access"),
        (_EXFILTRATION_ANCHORS, "network_exfiltration"),
    ):
        for tag in sorted(anchors & grouped.keys()):
            for parent in grouped[tag]:
                record = _family_record(parent, target)
                key = (record.root_observation_id, record.canonical_tag_id, record.evidence_kind)
                if key not in seen:
                    seen.add(key)
                    additions.append(record)

    injection_parents = _distinct_required_parents(
        grouped, frozenset({"memory_write", "memory_protect", "thread_execution"}),
    )
    if not injection_parents:
        injection_parents = _distinct_required_parents(
            grouped, frozenset({
                "static_memory_write_operation",
                "static_memory_protect_operation",
                "static_thread_execute_operation",
            }),
        )
    if not injection_parents:
        injection_parents = _distinct_required_parents(
            grouped, frozenset({"write_process_memory", "remote_thread_create"}),
        )
    if not injection_parents:
        injection_parents = _distinct_required_parents(
            grouped, frozenset({
                "static_memory_write_operation", "static_thread_execute_operation",
            }),
        )
    if injection_parents:
        composite = _composite_record("process_injection", injection_parents)
        key = (composite.root_observation_id, composite.canonical_tag_id, composite.evidence_kind)
        if key not in seen:
            additions.append(composite)

    return tuple((*canonical, *additions))


def derive_behavior_tags(validated_tags: object) -> list[str]:
    """Return reporting categories; evidence scoring remains record-owned."""
    if type(validated_tags) in (tuple, list, set, frozenset):
        raw_values = tuple(validated_tags)
        if all(type(item) is str for item in raw_values):
            ordered: list[str] = []
            seen: set[str] = set()
            for item in raw_values:
                tag = str.__str__(item).strip().lower().replace("-", "_")
                if tag and tag not in seen:
                    seen.add(tag)
                    ordered.append(tag)
            present = frozenset(ordered)
            additions: list[str] = []
            for anchors, target in (
                (_LATERAL_ANCHORS, "lateral_movement"),
                (_REMOTE_EXECUTION_ANCHORS, "remote_execution"),
                (_CREDENTIAL_ANCHORS, "credential_access"),
                (_EXFILTRATION_ANCHORS, "network_exfiltration"),
            ):
                if anchors & present and target not in seen:
                    seen.add(target)
                    additions.append(target)
            injection = (
                frozenset({"memory_write", "memory_protect", "thread_execution"}) <= present
                or frozenset({"write_process_memory", "remote_thread_create"}) <= present
            )
            if injection and "process_injection" not in seen:
                additions.append("process_injection")
            return [*ordered, *additions]
    bundle = normalize_tag_evidence(
        validated_tags,
        source_detector="behavior_derivation",
        source_stage="derive_behavior_tags",
    )
    return list(TagEvidence.from_records(derive_behavior_evidence(bundle.records)).tags)


__all__ = (
    "BEHAVIOR_DERIVATION_VERSION",
    "derive_behavior_evidence",
    "derive_behavior_tags",
)
