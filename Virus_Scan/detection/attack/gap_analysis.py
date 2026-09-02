"""Deterministic read-only ATT&CK requirement and local-capability gap analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json

from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.admission import (
    AttackTechniqueAdmissionRecord,
    build_attack_technique_admission_records,
)
from Virus_Scan.detection.attack.alignment import (
    TAG_STIX_ALIGNMENT_SPECS,
    TagStixAlignmentSpec,
)
from Virus_Scan.detection.attack.capabilities import (
    SCANNER_CAPABILITIES,
    ScannerCapabilitySpec,
)
from Virus_Scan.detection.attack.gap_contracts import (
    ATTACK_GAP_ANALYSIS_VERSION,
    AttackAnalyticObservability,
    AttackCapabilityGapReport,
    AttackImplementationBindingStatus,
    _attack_gap_report_digest,
)
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATIONS,
    AttackAnalyticImplementationSpec,
)


def _platforms(value: tuple[str, ...]) -> frozenset[str]:
    return frozenset(item.casefold() for item in value)


def _records_digest(values: tuple[object, ...]) -> str:
    records = tuple(item.to_record() for item in values)
    payload = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _validate_sequences(
    alignments: tuple[TagStixAlignmentSpec, ...],
    capabilities: tuple[ScannerCapabilitySpec, ...],
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
    admissions: tuple[AttackTechniqueAdmissionRecord, ...],
) -> None:
    contracts = (
        (alignments, TagStixAlignmentSpec, "attack_gap_alignments_invalid"),
        (capabilities, ScannerCapabilitySpec, "attack_gap_capabilities_invalid"),
        (implementations, AttackAnalyticImplementationSpec, "attack_gap_implementations_invalid"),
        (admissions, AttackTechniqueAdmissionRecord, "attack_gap_admissions_invalid"),
    )
    for values, owner, reason in contracts:
        if type(values) is not tuple or len(values) > 4096:
            raise TypeError(reason)
        if any(type(item) is not owner for item in values):
            raise TypeError(reason)


def _producer_match(
    alignment: TagStixAlignmentSpec,
    capability: ScannerCapabilitySpec,
    analytic_platforms: tuple[str, ...],
) -> tuple[bool, set[str], set[str], set[str]]:
    missing_fields = set(alignment.required_observation_fields) - set(
        capability.emitted_observation_fields
    )
    missing_modalities = set()
    if not set(alignment.supported_modalities).intersection(
        capability.supported_modalities
    ):
        missing_modalities.update(alignment.supported_modalities)
    platform_overlap = (
        _platforms(analytic_platforms)
        & _platforms(alignment.supported_platforms)
        & _platforms(capability.supported_platforms)
    )
    missing_platforms = set() if platform_overlap else set(
        alignment.supported_platforms
    )
    matched = not missing_fields and not missing_modalities and bool(platform_overlap)
    return matched, missing_fields, missing_modalities, missing_platforms


@dataclass(slots=True)
class _AlignmentEvidence:
    matched: set[str] = field(default_factory=set)
    missing_producers: set[str] = field(default_factory=set)
    missing_fields: set[str] = field(default_factory=set)
    missing_modalities: set[str] = field(default_factory=set)
    missing_platforms: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _ObservabilityState:
    relevant: tuple[TagStixAlignmentSpec, ...]
    covered: set[str] = field(default_factory=set)
    exact_covered: set[str] = field(default_factory=set)
    matched_tags: set[str] = field(default_factory=set)
    matched_producers: set[str] = field(default_factory=set)
    missing_producers: set[str] = field(default_factory=set)
    missing_fields: set[str] = field(default_factory=set)
    missing_modalities: set[str] = field(default_factory=set)
    missing_platforms: set[str] = field(default_factory=set)
    digest_mismatch: bool = False

    def absorb(self, evidence: _AlignmentEvidence) -> None:
        self.missing_producers.update(evidence.missing_producers)
        self.missing_fields.update(evidence.missing_fields)
        self.missing_modalities.update(evidence.missing_modalities)
        self.missing_platforms.update(evidence.missing_platforms)


def _alignment_evidence(
    alignment: TagStixAlignmentSpec,
    capabilities: tuple[ScannerCapabilitySpec, ...],
    analytic_platforms: tuple[str, ...],
) -> _AlignmentEvidence:
    by_producer = {item.producer_id: item for item in capabilities}
    evidence = _AlignmentEvidence()
    for producer_id in alignment.producer_ids:
        capability = by_producer.get(producer_id)
        if capability is None or alignment.tag_id not in capability.observable_tag_ids:
            evidence.missing_producers.add(producer_id)
            continue
        matched, fields, modalities, platforms = _producer_match(
            alignment, capability, analytic_platforms,
        )
        evidence.missing_fields.update(fields)
        evidence.missing_modalities.update(modalities)
        evidence.missing_platforms.update(platforms)
        if matched:
            evidence.matched.add(producer_id)
    return evidence


def _collect_observability(
    component_ids: tuple[str, ...],
    requirement_digest: str,
    analytic_platforms: tuple[str, ...],
    alignments: tuple[TagStixAlignmentSpec, ...],
    capabilities: tuple[ScannerCapabilitySpec, ...],
) -> _ObservabilityState:
    required = set(component_ids)
    relevant = tuple(
        item for item in alignments
        if set(item.data_component_ids).intersection(required)
    )
    state = _ObservabilityState(relevant)
    for alignment in relevant:
        evidence = _alignment_evidence(alignment, capabilities, analytic_platforms)
        state.absorb(evidence)
        digest_matches = alignment.dataset_requirement_digest == requirement_digest
        state.digest_mismatch = state.digest_mismatch or not digest_matches
        if evidence.matched and digest_matches:
            covered = set(alignment.data_component_ids).intersection(required)
            state.covered.update(covered)
            state.matched_tags.add(alignment.tag_id)
            state.matched_producers.update(evidence.matched)
            if alignment.alignment_state == "exact":
                state.exact_covered.update(covered)
    return state


def _classification_and_limitations(
    required: set[str],
    state: _ObservabilityState,
) -> tuple[str, tuple[str, ...]]:
    gaps = bool(
        state.missing_producers
        or state.missing_fields
        or state.missing_modalities
        or state.missing_platforms
        or state.digest_mismatch
    )
    if required and state.exact_covered == required and not gaps:
        return "exact", ()
    classification = "partial" if state.relevant else "unsupported"
    checks = (
        (not state.relevant, "no_reviewed_active_data_component_alignment"),
        (state.digest_mismatch, "dataset_requirement_digest_mismatch"),
        (required - state.covered, "required_data_components_unobserved"),
        (state.missing_producers, "declared_producer_unavailable"),
        (state.missing_fields, "required_observation_fields_unavailable"),
        (state.missing_modalities, "required_observation_modalities_unavailable"),
        (state.missing_platforms, "required_platform_telemetry_unavailable"),
        (
            state.relevant and state.exact_covered != required,
            "exact_alignment_coverage_incomplete",
        ),
    )
    return classification, tuple(sorted(
        reason for condition, reason in checks if condition
    ))

def _analytic_record(
    snapshot: AttackRepositorySnapshot,
    technique_id: str,
    strategy_id: str,
    analytic_id: str,
    alignments: tuple[TagStixAlignmentSpec, ...],
    capabilities: tuple[ScannerCapabilitySpec, ...],
) -> AttackAnalyticObservability:
    analytic = snapshot.analytic_by_attack_id[analytic_id]
    components = snapshot.data_components_by_analytic_id[analytic_id]
    component_ids = tuple(sorted(item.attack_id for item in components))
    digest = snapshot.analytic_requirement_digest_by_id[analytic_id]
    state = _collect_observability(
        component_ids, digest, analytic.platforms, alignments, capabilities,
    )
    required = set(component_ids)
    classification, limitations = _classification_and_limitations(required, state)
    missing_components = required - state.covered
    log_sources = tuple(sorted({
        "|".join((reference.data_component_stix_id, reference.name, reference.channel))
        for reference in analytic.log_source_references
    }))
    draft_chain_id = (
        f"draft.chain.{technique_id.casefold().replace('.', '_')}."
        f"{strategy_id.casefold()}.{analytic_id.casefold()}"
        if technique_id and strategy_id
        else f"draft.chain.unbound.{analytic_id.casefold()}"
    )
    if not technique_id:
        classification = "unsupported"
        limitations = tuple(sorted({
            *limitations,
            "official_analytic_unbound_to_active_strategy",
        }))
    return AttackAnalyticObservability(
        technique_id, strategy_id, analytic_id, digest, component_ids,
        analytic.platforms,
        tuple(sorted(item.field for item in analytic.mutable_elements)),
        log_sources, classification, tuple(sorted(state.matched_tags)),
        tuple(sorted(state.matched_producers)),
        tuple(sorted(missing_components)),
        tuple(sorted(state.missing_producers)),
        tuple(sorted(state.missing_fields)),
        tuple(sorted(state.missing_modalities)),
        tuple(sorted(state.missing_platforms)),
        tuple(
            f"draft.observation.{analytic_id.casefold()}.{item.casefold()}"
            for item in sorted(missing_components)
        ),
        draft_chain_id,
        "draft_only_not_activated",
        limitations,
    )


def _official_binding_reasons(
    snapshot: AttackRepositorySnapshot,
    implementation: AttackAnalyticImplementationSpec,
) -> tuple[str, ...]:
    reasons: set[str] = set()
    if implementation.technique_id not in snapshot.by_attack_id:
        reasons.add("technique_missing")
    if implementation.strategy_id not in snapshot.strategy_by_attack_id:
        reasons.add("strategy_missing")
    else:
        techniques = snapshot.techniques_by_strategy_id.get(implementation.strategy_id, ())
        analytics = snapshot.analytics_by_strategy_id.get(implementation.strategy_id, ())
        if implementation.technique_id not in {item.attack_id for item in techniques}:
            reasons.add("strategy_technique_binding_changed")
        if implementation.analytic_id not in {item.attack_id for item in analytics}:
            reasons.add("strategy_analytic_binding_changed")
    current = snapshot.analytic_requirement_digest_by_id.get(implementation.analytic_id, "")
    if not current:
        reasons.add("analytic_missing")
    elif current != implementation.requirement_digest:
        reasons.add("requirement_digest_changed")
    components = tuple(
        item.attack_id
        for item in snapshot.data_components_by_analytic_id.get(
            implementation.analytic_id, ()
        )
    )
    if current and components != implementation.required_data_component_ids:
        reasons.add("data_component_set_changed")
    return tuple(sorted(reasons))


def _binding_status(
    snapshot: AttackRepositorySnapshot,
    implementation: AttackAnalyticImplementationSpec,
) -> AttackImplementationBindingStatus:
    if implementation.support_mode != "exact_official":
        return AttackImplementationBindingStatus(
            implementation.implementation_id, implementation.technique_id,
            implementation.analytic_id, "unbound", implementation.requirement_digest,
            "", ("local_or_unsupported_implementation_has_no_official_binding",),
        )
    reasons = _official_binding_reasons(snapshot, implementation)
    current = snapshot.analytic_requirement_digest_by_id.get(implementation.analytic_id, "")
    state = "current" if not reasons else (
        "missing" if any(item.endswith("_missing") for item in reasons) else "stale"
    )
    return AttackImplementationBindingStatus(
        implementation.implementation_id, implementation.technique_id,
        implementation.analytic_id, state, implementation.requirement_digest,
        current, reasons,
    )


def _analytic_records(
    snapshot: AttackRepositorySnapshot,
    alignments: tuple[TagStixAlignmentSpec, ...],
    capabilities: tuple[ScannerCapabilitySpec, ...],
) -> tuple[AttackAnalyticObservability, ...]:
    bound_records = tuple(
        _analytic_record(
            snapshot, technique_id, strategy.attack_id, analytic.attack_id,
            alignments, capabilities,
        )
        for technique_id, strategies in sorted(
            snapshot.strategies_by_technique_id.items()
        )
        for strategy in strategies
        for analytic in snapshot.analytics_by_strategy_id[strategy.attack_id]
    )
    bound_analytic_ids = {item.analytic_id for item in bound_records}
    unbound_records = tuple(
        _analytic_record(
            snapshot, "", "", analytic_id, alignments, capabilities,
        )
        for analytic_id in sorted(snapshot.analytic_by_attack_id)
        if analytic_id not in bound_analytic_ids
    )
    return tuple(sorted(
        (*bound_records, *unbound_records),
        key=lambda item: (item.technique_id, item.strategy_id, item.analytic_id),
    ))


def _report_values(
    snapshot: AttackRepositorySnapshot,
    analytics: tuple[AttackAnalyticObservability, ...],
    bindings: tuple[AttackImplementationBindingStatus, ...],
    alignments: tuple[TagStixAlignmentSpec, ...],
    capabilities: tuple[ScannerCapabilitySpec, ...],
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
    admissions: tuple[AttackTechniqueAdmissionRecord, ...],
) -> dict[str, object]:
    digests = tuple(_records_digest(items) for items in (
        capabilities, alignments, implementations, admissions,
    ))
    combined = sha256("|".join(digests).encode("ascii")).hexdigest()
    return {
        "repository_digest": snapshot.digest,
        "dataset_version": snapshot.version.dataset_version,
        "source_ref": snapshot.version.source_ref,
        "repository_object_count": len(snapshot.objects),
        "active_strategy_count": len(snapshot.strategy_by_attack_id),
        "active_analytic_count": len(snapshot.analytic_by_attack_id),
        "active_data_component_count": len(snapshot.data_component_by_attack_id),
        "capability_count": len(capabilities),
        "active_alignment_count": len(alignments),
        "admission_record_count": len(admissions),
        "candidate_only_count": sum(item.admission_state == "candidate_only" for item in admissions),
        "unsupported_policy_count": sum(
            item.admission_state == "unsupported_by_sensors" for item in admissions
        ),
        "capability_manifest_digest": digests[0],
        "alignment_manifest_digest": digests[1],
        "implementation_manifest_digest": digests[2],
        "admission_manifest_digest": digests[3],
        "local_manifest_digest": combined,
        "exact_count": sum(item.classification == "exact" for item in analytics),
        "partial_count": sum(item.classification == "partial" for item in analytics),
        "unsupported_count": sum(item.classification == "unsupported" for item in analytics),
        "analytics": analytics,
        "implementation_bindings": bindings,
        "version": ATTACK_GAP_ANALYSIS_VERSION,
    }


def build_attack_capability_gap_report(
    snapshot: AttackRepositorySnapshot,
    *,
    alignments: tuple[TagStixAlignmentSpec, ...] = TAG_STIX_ALIGNMENT_SPECS,
    capabilities: tuple[ScannerCapabilitySpec, ...] = SCANNER_CAPABILITIES,
    implementations: tuple[AttackAnalyticImplementationSpec, ...] = ATTACK_ANALYTIC_IMPLEMENTATIONS,
    admissions: tuple[AttackTechniqueAdmissionRecord, ...] | None = None,
) -> AttackCapabilityGapReport:
    """Compare one validated immutable repository with reviewed local manifests."""
    if type(snapshot) is not AttackRepositorySnapshot:
        raise TypeError("attack_gap_repository_required")
    if admissions is None:
        admissions = build_attack_technique_admission_records(snapshot)
    _validate_sequences(alignments, capabilities, implementations, admissions)
    active_alignments = tuple(
        item for item in alignments if item.alignment_state in {"exact", "partial"}
    )
    analytics = _analytic_records(snapshot, active_alignments, capabilities)
    bindings = tuple(sorted(
        (_binding_status(snapshot, item) for item in implementations),
        key=lambda item: item.implementation_id,
    ))
    values = _report_values(
        snapshot, analytics, bindings, active_alignments, capabilities,
        implementations, admissions,
    )
    values["report_digest"] = _attack_gap_report_digest(values)
    return AttackCapabilityGapReport(**values)


__all__ = (
    "build_attack_capability_gap_report",
)
