"""Projection-only Cluster context and ATT&CK candidate summary.

The projector consumes only the final immutable ``attack_candidate_retrieval``
record already present in each local result.  It never queries clustering/model
state, reruns candidate retrieval, maps ATT&CK techniques, or changes evidence
or probability authority.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
import math

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.api.attack_candidate_retrieval_contracts import (
    ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION,
    ATTACK_CANDIDATE_RETRIEVAL_VERSION,
)
from Virus_Scan.publication.content_identity import (
    exact_content_sha256,
    final_record_content_sha256,
)

CLUSTER_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION = "cluster_evidence_summary_row_v2"
CLUSTER_CANDIDATE_SUMMARY_ROW_SCHEMA_VERSION = "cluster_candidate_summary_row_v2"
CLUSTER_FINDINGS_SUMMARY_SCHEMA_VERSION = "cluster_findings_summary_v2"
_SUSPICIOUS_COUNT_UNAVAILABLE = "canonical_cluster_model_has_no_suspicious_label"
_MAX_RECORDS = 200_000
_MAX_ITEMS = 512
_MAX_TEXT = 4096


def _mapping(value: object, reason: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise TypeError(reason)
    return {key: item for key, item in items if type(key) is str}


def _mapping_value(value: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for candidate, item in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return item
    return default


def _text(value: object, reason: str, *, allow_blank: bool = False, maximum: int = _MAX_TEXT) -> str:
    return exact_bounded_text(value, reason, maximum=maximum, allow_blank=allow_blank)


def _bool(value: object, reason: str) -> bool:
    if type(value) is not bool:
        raise TypeError(reason)
    return value


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise TypeError(reason)
    return value


def _unit(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(reason)
    return number


def _sequence(value: object, reason: str, *, limit: int = _MAX_ITEMS) -> tuple[object, ...]:
    values = no_hook_sequence_items(value)
    if len(values) > limit:
        raise ValueError(reason)
    return tuple(values)


def _text_tuple(
    value: object,
    reason: str,
    *,
    limit: int = _MAX_ITEMS,
    sorted_unique: bool = True,
) -> tuple[str, ...]:
    values = tuple(_text(item, reason) for item in _sequence(value, reason, limit=limit))
    if sorted_unique and values != tuple(sorted(set(values))):
        raise ValueError(reason)
    return values


def _validate_cluster_context(context: dict[str, object], record_key: str) -> None:
    digest = _text(dict.get(context, "semantic_digest"), "cluster_summary_context_digest_invalid", maximum=64)
    core = dict(context)
    core.pop("semantic_digest", None)
    payload = {"schema_version": ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION, **core}
    if canonical_json_sha256(payload) != digest:
        raise RuntimeError("cluster_summary_context_digest_mismatch:" + record_key)
    available = _bool(dict.get(context, "available"), "cluster_summary_context_available_invalid")
    reason = _text(
        dict.get(context, "unavailable_reason", ""),
        "cluster_summary_context_reason_invalid",
        allow_blank=available,
        maximum=256,
    )
    cluster_id = _text(
        dict.get(context, "cluster_id", ""),
        "cluster_summary_cluster_id_invalid",
        allow_blank=not available,
        maximum=256,
    )
    model_version = _text(
        dict.get(context, "cluster_model_version", ""),
        "cluster_summary_model_version_invalid",
        allow_blank=not available,
        maximum=128,
    )
    if available and (not cluster_id or not model_version or reason):
        raise RuntimeError("cluster_summary_context_availability_invalid:" + record_key)
    if not available and not reason:
        raise RuntimeError("cluster_summary_context_unavailable_reason_missing:" + record_key)
    _nonnegative_int(dict.get(context, "cluster_members"), "cluster_summary_member_count_invalid")
    _nonnegative_int(dict.get(context, "trusted_support"), "cluster_summary_trusted_support_invalid")
    for field in ("maturity", "purity", "drift", "cluster_quality"):
        _unit(dict.get(context, field), "cluster_summary_context_metric_invalid")
    for field in ("tag_signature", "chain_signature", "behavior_signature"):
        _text_tuple(dict.get(context, field, ()), "cluster_summary_context_signature_invalid", limit=256)


def _validate_candidate(candidate: dict[str, object], expected_rank: int, record_key: str) -> None:
    rank = _nonnegative_int(dict.get(candidate, "rank"), "cluster_summary_candidate_rank_invalid")
    if rank != expected_rank or rank < 1:
        raise RuntimeError("cluster_summary_candidate_rank_sequence_invalid:" + record_key)
    technique = _text(dict.get(candidate, "technique_id"), "cluster_summary_candidate_technique_invalid", maximum=16)
    if not technique.startswith("T"):
        raise RuntimeError("cluster_summary_candidate_technique_invalid:" + record_key)
    for field, limit in (
        ("implementation_ids", 16),
        ("claim_scopes", 16),
        ("matched_cluster_chain_ids", 32),
        ("matched_direct_chain_ids", 32),
        ("shared_physical_root_ids", 128),
        ("missing_direct_requirements", 64),
    ):
        _text_tuple(dict.get(candidate, field, ()), "cluster_summary_candidate_sequence_invalid", limit=limit)
    _text(dict.get(candidate, "admission_state"), "cluster_summary_candidate_admission_invalid", maximum=32)
    _text(dict.get(candidate, "correlation_group"), "cluster_summary_candidate_group_invalid", maximum=128)
    _unit(dict.get(candidate, "score"), "cluster_summary_candidate_score_invalid")
    if dict.get(candidate, "evidence_authority") != "context_only":
        raise RuntimeError("cluster_summary_candidate_authority_invalid:" + record_key)
    if dict.get(candidate, "eligible_for_confirmation") is not False:
        raise RuntimeError("cluster_summary_candidate_confirmation_authority_invalid:" + record_key)
    if dict.get(candidate, "eligible_for_probability") is not False:
        raise RuntimeError("cluster_summary_candidate_probability_authority_invalid:" + record_key)


def _source_candidate_retrieval(record: object, record_key: str) -> dict[str, object] | None:
    model_evidence = _mapping_value(record, "model_evidence")
    if model_evidence is None:
        return None
    value = _mapping_value(model_evidence, "attack_candidate_retrieval")
    if value is None:
        return None
    materialized = no_hook_materialize(
        value,
        max_depth=24,
        max_items=20_000,
        reason_prefix="cluster_summary_source",
    )
    if type(materialized) is not dict:
        raise RuntimeError("cluster_summary_source_invalid:" + record_key)
    if dict.get(materialized, "schema_version") != ATTACK_CANDIDATE_RETRIEVAL_SCHEMA_VERSION:
        raise RuntimeError("cluster_summary_source_schema_invalid:" + record_key)
    if dict.get(materialized, "retriever_version") != ATTACK_CANDIDATE_RETRIEVAL_VERSION:
        raise RuntimeError("cluster_summary_source_retriever_invalid:" + record_key)
    published_digest = _text(
        dict.get(materialized, "semantic_digest"),
        "cluster_summary_source_digest_invalid",
        maximum=64,
    )
    core = dict(materialized)
    core.pop("semantic_digest", None)
    if canonical_json_sha256(core) != published_digest:
        raise RuntimeError("cluster_summary_source_digest_mismatch:" + record_key)
    if dict.get(materialized, "evidence_authority") != "context_only":
        raise RuntimeError("cluster_summary_source_authority_invalid:" + record_key)
    if dict.get(materialized, "eligible_for_confirmation") is not False:
        raise RuntimeError("cluster_summary_source_confirmation_authority_invalid:" + record_key)
    if dict.get(materialized, "eligible_for_probability") is not False:
        raise RuntimeError("cluster_summary_source_probability_authority_invalid:" + record_key)
    if dict.get(materialized, "official_decision_effect") != "none":
        raise RuntimeError("cluster_summary_source_official_effect_invalid:" + record_key)
    context = _mapping(dict.get(materialized, "cluster_context"), "cluster_summary_context_invalid")
    _validate_cluster_context(context, record_key)
    for field in ("tag_signatures", "chain_signatures", "static_operation_signatures"):
        _text_tuple(dict.get(materialized, field, ()), "cluster_summary_source_signature_invalid", limit=256)
    _unit(dict.get(materialized, "markov_context_signal"), "cluster_summary_markov_signal_invalid")
    _unit(dict.get(materialized, "temporal_context_signal"), "cluster_summary_temporal_signal_invalid")
    candidates = _sequence(dict.get(materialized, "ranked_candidates", ()), "cluster_summary_candidates_invalid", limit=16)
    candidate_count = _nonnegative_int(dict.get(materialized, "candidate_count"), "cluster_summary_candidate_count_invalid")
    if candidate_count != len(candidates):
        raise RuntimeError("cluster_summary_candidate_count_mismatch:" + record_key)
    for index, raw_candidate in enumerate(candidates, 1):
        _validate_candidate(_mapping(raw_candidate, "cluster_summary_candidate_invalid"), index, record_key)
    abstained = _bool(dict.get(materialized, "abstained"), "cluster_summary_abstained_invalid")
    reason = _text(
        dict.get(materialized, "unavailable_reason", ""),
        "cluster_summary_source_reason_invalid",
        allow_blank=not abstained,
        maximum=256,
    )
    if abstained and (candidates or not reason):
        raise RuntimeError("cluster_summary_abstention_contract_invalid:" + record_key)
    if not abstained and (not candidates or reason):
        raise RuntimeError("cluster_summary_available_contract_invalid:" + record_key)
    return materialized


@dataclass(frozen=True, slots=True)
class ClusterEvidenceSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    available: bool
    abstained: bool
    cluster_id: str
    cluster_model_version: str
    cluster_members: int | None
    trusted_support: int | None
    suspicious_member_count: None
    suspicious_member_count_unavailable_reason: str
    maturity: float | None
    purity: float | None
    drift: float | None
    drift_state: str
    cluster_quality: float | None
    tag_signature: tuple[str, ...]
    chain_signature: tuple[str, ...]
    behavior_signature: tuple[str, ...]
    direct_tag_signatures: tuple[str, ...]
    direct_chain_signatures: tuple[str, ...]
    static_operation_signatures: tuple[str, ...]
    markov_context_signal: float
    temporal_context_signal: float
    repository_digest: str
    dataset_version: str
    retriever_version: str
    profile_digest: str
    candidate_count: int
    unavailable_reason: str
    evidence_authority: str
    eligible_for_confirmation: bool
    eligible_for_probability: bool
    official_decision_effect: str
    cluster_context_semantic_digest: str
    evidence_semantic_digest: str
    schema_version: str = CLUSTER_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION

    def to_record(self) -> dict[str, object]:
        exact_content_sha256(self.content_sha256, "cluster_evidence_summary_content_sha256_invalid")
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ClusterCandidateSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    cluster_id: str
    cluster_model_version: str
    rank: int
    technique_id: str
    implementation_ids: tuple[str, ...]
    claim_scopes: tuple[str, ...]
    admission_state: str
    correlation_group: str
    score: float
    matched_cluster_chain_ids: tuple[str, ...]
    matched_direct_chain_ids: tuple[str, ...]
    shared_physical_root_ids: tuple[str, ...]
    missing_direct_requirements: tuple[str, ...]
    evidence_authority: str
    eligible_for_confirmation: bool
    eligible_for_probability: bool
    official_decision_effect: str
    cluster_context_semantic_digest: str
    retrieval_semantic_digest: str
    candidate_semantic_digest: str
    schema_version: str = CLUSTER_CANDIDATE_SUMMARY_ROW_SCHEMA_VERSION

    def to_record(self) -> dict[str, object]:
        exact_content_sha256(self.content_sha256, "cluster_candidate_summary_content_sha256_invalid")
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ClusterFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    source_record_count: int
    evidence_record_count: int
    duplicate_alias_count: int
    source_rows: tuple[ClusterEvidenceSummaryRow, ...]
    candidate_rows: tuple[ClusterCandidateSummaryRow, ...]
    schema_version: str = CLUSTER_FINDINGS_SUMMARY_SCHEMA_VERSION

    def counts_record(self) -> dict[str, int]:
        return {
            "source_record_count": self.source_record_count,
            "evidence_record_count": self.evidence_record_count,
            "unique_evidence_count": len(self.source_rows),
            "duplicate_alias_count": self.duplicate_alias_count,
            "available_cluster_count": sum(row.available for row in self.source_rows),
            "unavailable_cluster_count": sum(not row.available for row in self.source_rows),
            "candidate_count": len(self.candidate_rows),
        }

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def core_record(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "schema_version": self.schema_version,
            "counts": self.counts_record(),
            "source_rows": tuple(row.to_record() for row in self.source_rows),
            "candidate_rows": tuple(row.to_record() for row in self.candidate_rows),
            "projection_policy": {
                "source": "final_immutable_attack_candidate_retrieval_only",
                "report_time_cluster_lookup": False,
                "report_time_candidate_retrieval": False,
                "report_time_attack_mapping": False,
                "evidence_authority": "context_only",
                "eligible_for_confirmation": False,
                "eligible_for_probability": False,
                "official_decision_effect": "none",
                "unknown_is_negative": False,
            },
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record


def _source_row(content_sha256: str, record_keys: tuple[str, ...], evidence: dict[str, object]) -> ClusterEvidenceSummaryRow:
    context = _mapping(dict.get(evidence, "cluster_context"), "cluster_summary_context_invalid")
    available = _bool(dict.get(context, "available"), "cluster_summary_context_available_invalid")
    drift = _unit(dict.get(context, "drift"), "cluster_summary_context_drift_invalid") if available else None
    return ClusterEvidenceSummaryRow(
        record_keys=record_keys,
        content_sha256=exact_content_sha256(content_sha256, "cluster_summary_content_sha256_invalid"),
        available=available,
        abstained=_bool(dict.get(evidence, "abstained"), "cluster_summary_abstained_invalid"),
        cluster_id=_text(dict.get(context, "cluster_id", ""), "cluster_summary_cluster_id_invalid", allow_blank=not available, maximum=256),
        cluster_model_version=_text(dict.get(context, "cluster_model_version", ""), "cluster_summary_model_version_invalid", allow_blank=not available, maximum=128),
        cluster_members=_nonnegative_int(dict.get(context, "cluster_members"), "cluster_summary_member_count_invalid") if available else None,
        trusted_support=_nonnegative_int(dict.get(context, "trusted_support"), "cluster_summary_trusted_support_invalid") if available else None,
        suspicious_member_count=None,
        suspicious_member_count_unavailable_reason=_SUSPICIOUS_COUNT_UNAVAILABLE,
        maturity=_unit(dict.get(context, "maturity"), "cluster_summary_maturity_invalid") if available else None,
        purity=_unit(dict.get(context, "purity"), "cluster_summary_purity_invalid") if available else None,
        drift=drift,
        drift_state=("unavailable" if not available else ("stable" if drift == 0.0 else "drift_or_purity_alarm")),
        cluster_quality=_unit(dict.get(context, "cluster_quality"), "cluster_summary_quality_invalid") if available else None,
        tag_signature=_text_tuple(dict.get(context, "tag_signature", ()), "cluster_summary_tag_signature_invalid", limit=256),
        chain_signature=_text_tuple(dict.get(context, "chain_signature", ()), "cluster_summary_chain_signature_invalid", limit=256),
        behavior_signature=_text_tuple(dict.get(context, "behavior_signature", ()), "cluster_summary_behavior_signature_invalid", limit=256),
        direct_tag_signatures=_text_tuple(dict.get(evidence, "tag_signatures", ()), "cluster_summary_direct_tags_invalid", limit=256),
        direct_chain_signatures=_text_tuple(dict.get(evidence, "chain_signatures", ()), "cluster_summary_direct_chains_invalid", limit=256),
        static_operation_signatures=_text_tuple(dict.get(evidence, "static_operation_signatures", ()), "cluster_summary_static_operations_invalid", limit=256),
        markov_context_signal=_unit(dict.get(evidence, "markov_context_signal"), "cluster_summary_markov_signal_invalid"),
        temporal_context_signal=_unit(dict.get(evidence, "temporal_context_signal"), "cluster_summary_temporal_signal_invalid"),
        repository_digest=_text(dict.get(evidence, "repository_digest", ""), "cluster_summary_repository_digest_invalid", allow_blank=True, maximum=64),
        dataset_version=_text(dict.get(evidence, "dataset_version", ""), "cluster_summary_dataset_version_invalid", allow_blank=True, maximum=64),
        retriever_version=_text(dict.get(evidence, "retriever_version"), "cluster_summary_retriever_version_invalid", maximum=128),
        profile_digest=_text(dict.get(evidence, "profile_digest"), "cluster_summary_profile_digest_invalid", maximum=64),
        candidate_count=_nonnegative_int(dict.get(evidence, "candidate_count"), "cluster_summary_candidate_count_invalid"),
        unavailable_reason=_text(dict.get(evidence, "unavailable_reason", ""), "cluster_summary_unavailable_reason_invalid", allow_blank=not _bool(dict.get(evidence, "abstained"), "cluster_summary_abstained_invalid"), maximum=256),
        evidence_authority="context_only",
        eligible_for_confirmation=False,
        eligible_for_probability=False,
        official_decision_effect="none",
        cluster_context_semantic_digest=_text(dict.get(context, "semantic_digest"), "cluster_summary_context_digest_invalid", maximum=64),
        evidence_semantic_digest=_text(dict.get(evidence, "semantic_digest"), "cluster_summary_evidence_digest_invalid", maximum=64),
    )


def _candidate_row(
    content_sha256: str,
    record_keys: tuple[str, ...],
    evidence: dict[str, object],
    candidate: dict[str, object],
) -> ClusterCandidateSummaryRow:
    context = _mapping(dict.get(evidence, "cluster_context"), "cluster_summary_context_invalid")
    materialized = no_hook_materialize(candidate, max_depth=12, max_items=2_000, reason_prefix="cluster_summary_candidate")
    if type(materialized) is not dict:
        raise RuntimeError("cluster_summary_candidate_materialization_invalid")
    return ClusterCandidateSummaryRow(
        record_keys=record_keys,
        content_sha256=exact_content_sha256(content_sha256, "cluster_summary_content_sha256_invalid"),
        cluster_id=_text(dict.get(context, "cluster_id"), "cluster_summary_cluster_id_invalid", maximum=256),
        cluster_model_version=_text(dict.get(context, "cluster_model_version"), "cluster_summary_model_version_invalid", maximum=128),
        rank=_nonnegative_int(dict.get(candidate, "rank"), "cluster_summary_candidate_rank_invalid"),
        technique_id=_text(dict.get(candidate, "technique_id"), "cluster_summary_candidate_technique_invalid", maximum=16),
        implementation_ids=_text_tuple(dict.get(candidate, "implementation_ids", ()), "cluster_summary_candidate_implementation_ids_invalid", limit=16),
        claim_scopes=_text_tuple(dict.get(candidate, "claim_scopes", ()), "cluster_summary_candidate_claim_scopes_invalid", limit=16),
        admission_state=_text(dict.get(candidate, "admission_state"), "cluster_summary_candidate_admission_invalid", maximum=32),
        correlation_group=_text(dict.get(candidate, "correlation_group"), "cluster_summary_candidate_group_invalid", maximum=128),
        score=_unit(dict.get(candidate, "score"), "cluster_summary_candidate_score_invalid"),
        matched_cluster_chain_ids=_text_tuple(dict.get(candidate, "matched_cluster_chain_ids", ()), "cluster_summary_candidate_cluster_chains_invalid", limit=32),
        matched_direct_chain_ids=_text_tuple(dict.get(candidate, "matched_direct_chain_ids", ()), "cluster_summary_candidate_direct_chains_invalid", limit=32),
        shared_physical_root_ids=_text_tuple(dict.get(candidate, "shared_physical_root_ids", ()), "cluster_summary_candidate_roots_invalid", limit=128),
        missing_direct_requirements=_text_tuple(dict.get(candidate, "missing_direct_requirements", ()), "cluster_summary_candidate_missing_invalid", limit=64),
        evidence_authority="context_only",
        eligible_for_confirmation=False,
        eligible_for_probability=False,
        official_decision_effect="none",
        cluster_context_semantic_digest=_text(dict.get(context, "semantic_digest"), "cluster_summary_context_digest_invalid", maximum=64),
        retrieval_semantic_digest=_text(dict.get(evidence, "semantic_digest"), "cluster_summary_evidence_digest_invalid", maximum=64),
        candidate_semantic_digest=canonical_json_sha256(materialized),
    )


def build_cluster_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
) -> ClusterFindingsSummary:
    scan_id_text = _text(scan_id, "cluster_findings_summary_scan_id_invalid", maximum=128)
    snapshot_digest = _text(snapshot_semantic_digest, "cluster_findings_summary_snapshot_digest_invalid", maximum=64)
    items = no_hook_mapping_items(local_results)
    if items is None or len(items) > _MAX_RECORDS:
        raise TypeError("cluster_findings_summary_local_results_invalid")
    source_record_count = len(items)
    evidence_record_count = 0
    evidence_groups: dict[tuple[str, str], dict[str, object]] = {}
    for raw_key, record in items:
        record_key = _text(raw_key, "cluster_summary_record_key_invalid")
        evidence = _source_candidate_retrieval(record, record_key)
        if evidence is None:
            continue
        evidence_record_count += 1
        content_sha256 = final_record_content_sha256(
            record, "cluster_summary_content_sha256_invalid:" + record_key
        )
        digest = _text(dict.get(evidence, "semantic_digest"), "cluster_summary_evidence_digest_invalid", maximum=64)
        source_identity = (content_sha256, digest)
        group = evidence_groups.get(source_identity)
        if group is None:
            evidence_groups[source_identity] = {
                "content_sha256": content_sha256,
                "evidence": evidence,
                "record_keys": {record_key},
            }
        else:
            if group["evidence"] != evidence:
                raise RuntimeError("cluster_summary_evidence_digest_collision")
            group["record_keys"].add(record_key)

    source_rows: list[ClusterEvidenceSummaryRow] = []
    candidate_rows: list[ClusterCandidateSummaryRow] = []
    for (content_sha256, digest), group in evidence_groups.items():
        evidence = group["evidence"]
        if type(evidence) is not dict:
            raise RuntimeError("cluster_summary_group_invalid")
        record_keys = tuple(sorted(group["record_keys"]))
        source_rows.append(_source_row(content_sha256, record_keys, evidence))
        for raw_candidate in _sequence(dict.get(evidence, "ranked_candidates", ()), "cluster_summary_candidates_invalid", limit=16):
            candidate_rows.append(_candidate_row(content_sha256, record_keys, evidence, _mapping(raw_candidate, "cluster_summary_candidate_invalid")))

    return ClusterFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=snapshot_digest,
        source_record_count=source_record_count,
        evidence_record_count=evidence_record_count,
        duplicate_alias_count=evidence_record_count - len(source_rows),
        source_rows=tuple(sorted(source_rows, key=lambda row: (row.content_sha256, not row.available, row.cluster_id, row.evidence_semantic_digest))),
        candidate_rows=tuple(sorted(candidate_rows, key=lambda row: (row.content_sha256, row.technique_id, row.cluster_id, row.rank, row.retrieval_semantic_digest))),
    )


def cluster_findings_json_bytes(summary: ClusterFindingsSummary) -> bytes:
    if type(summary) is not ClusterFindingsSummary:
        raise TypeError("cluster_findings_summary_required")
    return (json.dumps(summary.to_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def cluster_findings_markdown_bytes(summary: ClusterFindingsSummary) -> bytes:
    if type(summary) is not ClusterFindingsSummary:
        raise TypeError("cluster_findings_summary_required")
    counts = summary.counts_record()
    lines = [
        "# Cluster Findings Summary",
        "",
        f"- Scan ID: `{summary.scan_id}`",
        f"- Snapshot semantic digest: `{summary.snapshot_semantic_digest}`",
        f"- Summary semantic digest: `{summary.semantic_digest}`",
        f"- Available / unavailable cluster contexts: {counts['available_cluster_count']} / {counts['unavailable_cluster_count']}",
        f"- ATT&CK candidate rows: {counts['candidate_count']}",
        "- Evidence authority: `context_only`; confirmation/probability authority: disabled.",
        "- Suspicious-member count: unavailable because the canonical cluster model has no suspicious label.",
        "- Projection policy: final immutable candidate-retrieval evidence only; no report-time model lookup, retrieval, or ATT&CK mapping.",
        "",
        "| Content SHA-256 | Cluster | Model | Members | Trusted support | Maturity | Purity | Drift | Quality | Candidates | State |",
        "|---|---|---|---:|---:|---:|---:|---|---:|---:|---|",
    ]
    for row in summary.source_rows:
        lines.append("| " + " | ".join((
            _md(row.content_sha256),
            _md(row.cluster_id or "unavailable"),
            _md(row.cluster_model_version or "unavailable"),
            _md(row.cluster_members if row.cluster_members is not None else "unavailable"),
            _md(row.trusted_support if row.trusted_support is not None else "unavailable"),
            _md(row.maturity if row.maturity is not None else "unavailable"),
            _md(row.purity if row.purity is not None else "unavailable"),
            _md(row.drift_state),
            _md(row.cluster_quality if row.cluster_quality is not None else "unavailable"),
            str(row.candidate_count),
            _md("available" if row.available else row.unavailable_reason),
        )) + " |")
    if summary.candidate_rows:
        lines.extend(("", "## Candidate ranking", "", "| Content SHA-256 | Rank | Technique | Score | Cluster chains | Direct chains | Missing direct requirements |", "|---|---:|---|---:|---|---|---|"))
        for row in summary.candidate_rows:
            lines.append("| " + " | ".join((
                _md(row.content_sha256),
                str(row.rank),
                _md(row.technique_id),
                str(row.score),
                _md(",".join(row.matched_cluster_chain_ids)),
                _md(",".join(row.matched_direct_chain_ids)),
                _md(",".join(row.missing_direct_requirements)),
            )) + " |")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def cluster_findings_csv_bytes(summary: ClusterFindingsSummary) -> bytes:
    if type(summary) is not ClusterFindingsSummary:
        raise TypeError("cluster_findings_summary_required")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow((
        "record_keys", "content_sha256", "available", "cluster_id", "cluster_model_version", "cluster_members",
        "trusted_support", "suspicious_member_count", "suspicious_member_count_unavailable_reason",
        "maturity", "purity", "drift", "drift_state", "cluster_quality", "candidate_count",
        "tag_signature", "chain_signature", "behavior_signature", "repository_digest", "dataset_version",
        "evidence_authority", "eligible_for_confirmation", "eligible_for_probability", "official_decision_effect",
        "cluster_context_semantic_digest", "evidence_semantic_digest",
    ))
    for row in summary.source_rows:
        writer.writerow((
            ";".join(row.record_keys), row.content_sha256, row.available, row.cluster_id, row.cluster_model_version,
            "" if row.cluster_members is None else row.cluster_members,
            "" if row.trusted_support is None else row.trusted_support,
            "", row.suspicious_member_count_unavailable_reason,
            "" if row.maturity is None else row.maturity,
            "" if row.purity is None else row.purity,
            "" if row.drift is None else row.drift,
            row.drift_state,
            "" if row.cluster_quality is None else row.cluster_quality,
            row.candidate_count,
            ";".join(row.tag_signature), ";".join(row.chain_signature), ";".join(row.behavior_signature),
            row.repository_digest, row.dataset_version, row.evidence_authority,
            row.eligible_for_confirmation, row.eligible_for_probability, row.official_decision_effect,
            row.cluster_context_semantic_digest, row.evidence_semantic_digest,
        ))
    writer.writerow(())
    writer.writerow((
        "candidate_record_keys", "content_sha256", "cluster_id", "cluster_model_version", "rank", "technique_id", "score",
        "implementation_ids", "claim_scopes", "admission_state", "correlation_group",
        "matched_cluster_chain_ids", "matched_direct_chain_ids", "shared_physical_root_ids",
        "missing_direct_requirements", "evidence_authority", "eligible_for_confirmation",
        "eligible_for_probability", "official_decision_effect", "retrieval_semantic_digest", "candidate_semantic_digest",
    ))
    for row in summary.candidate_rows:
        writer.writerow((
            ";".join(row.record_keys), row.content_sha256, row.cluster_id, row.cluster_model_version, row.rank, row.technique_id, row.score,
            ";".join(row.implementation_ids), ";".join(row.claim_scopes), row.admission_state, row.correlation_group,
            ";".join(row.matched_cluster_chain_ids), ";".join(row.matched_direct_chain_ids),
            ";".join(row.shared_physical_root_ids), ";".join(row.missing_direct_requirements),
            row.evidence_authority, row.eligible_for_confirmation, row.eligible_for_probability,
            row.official_decision_effect, row.retrieval_semantic_digest, row.candidate_semantic_digest,
        ))
    return stream.getvalue().encode("utf-8")


def render_cluster_findings_summary(summary: ClusterFindingsSummary) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not ClusterFindingsSummary:
        raise TypeError("cluster_findings_summary_required")
    return (
        ("cluster_findings_summary.json", cluster_findings_json_bytes(summary)),
        ("cluster_findings_summary.md", cluster_findings_markdown_bytes(summary)),
        ("cluster_findings_summary.csv", cluster_findings_csv_bytes(summary)),
    )


__all__ = (
    "CLUSTER_CANDIDATE_SUMMARY_ROW_SCHEMA_VERSION",
    "CLUSTER_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION",
    "CLUSTER_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "ClusterCandidateSummaryRow",
    "ClusterEvidenceSummaryRow",
    "ClusterFindingsSummary",
    "build_cluster_findings_summary",
    "cluster_findings_csv_bytes",
    "cluster_findings_json_bytes",
    "cluster_findings_markdown_bytes",
    "render_cluster_findings_summary",
)
