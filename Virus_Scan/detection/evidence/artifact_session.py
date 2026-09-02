"""Canonical bounded artifact-evidence lifecycle for one full-analysis generation."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.contracts.evidence_discovery_plan import (
    EVIDENCE_DISCOVERY_QUERY_KINDS,
    EvidenceDiscoveryBudget,
    EvidenceDiscoveryPlan,
)
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.contracts.model_projection_identity import model_projection_identity
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.contracts.static_program_analysis import StaticProgramAnalysis
from Virus_Scan.contracts.yara_hits import YaraScanResult
from Virus_Scan.detection.attack.candidate_retrieval import (
    AttackCandidateRetrievalResult,
    retrieve_current_attack_candidates,
)
from Virus_Scan.detection.attack.evidence_discovery import build_evidence_discovery_plan
from Virus_Scan.detection.correlation.multi_signal.model_context import build_detection_model_context
from Virus_Scan.detection.profiles.selection import build_detection_profile_context
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence


_FULL_DISCOVERY_BUDGET = EvidenceDiscoveryBudget(
    maximum_query_count=4096,
    maximum_cost_units=1_000_000,
)


def _physical_observation_roots(
    tag_evidence: TagEvidence,
    yara_scan_result: YaraScanResult,
) -> tuple[DetectionObservation, ...]:
    """Materialize one root-preserving physical observation per non-YARA root.

    TagEvidence observed/failure records retain the canonical physical identity
    fields of their source DetectionObservation.  This function does not infer a
    fact from a derived/model record: it only re-materializes an observed root so
    the final ArtifactEvidenceSnapshot can prove every TagEvidence root is
    physically anchored.  YARA roots remain owned by YaraScanResult and are not
    duplicated here.
    """
    if type(tag_evidence) is not TagEvidence:
        raise TypeError("artifact_evidence_session_tag_evidence_required")
    if type(yara_scan_result) is not YaraScanResult:
        raise TypeError("artifact_evidence_session_yara_result_required")
    yara_roots = {hit.root_observation_id for hit in yara_scan_result.hits}
    selected: dict[str, object] = {}
    for record in tag_evidence.records:
        if record.root_observation_id in yara_roots:
            continue
        if record.evidence_kind not in {"observed", "failure"}:
            continue
        root = record.root_observation_id
        if not root.startswith("obs_"):
            continue
        previous = selected.get(root)
        if previous is None:
            selected[root] = record
            continue
        # Prefer a positive observed projection over a failure projection when
        # both represent the same physical root.  The root identity itself is
        # identical, so this cannot manufacture evidence independence.
        if previous.evidence_kind == "failure" and record.evidence_kind == "observed":
            selected[root] = record

    observations: list[DetectionObservation] = []
    for root in sorted(selected):
        record = selected[root]
        tag = record.raw_observation_name or record.canonical_tag_id
        observation = DetectionObservation(
            observation_id=record.observation_id,
            root_observation_id=record.root_observation_id,
            tag=tag,
            producer_id=record.source_detector,
            stage_id=record.source_stage,
            modality=record.modality,
            platform=record.platform,
            actor_identity=record.actor_identity,
            target_identity=record.target_identity,
            artifact_identity=record.artifact_identity,
            process_identity=record.process_identity,
            host_identity=record.host_identity,
            connection_identity=record.connection_identity,
            source_location=record.source_location,
            ordinal=record.ordinal,
            timestamp=record.timestamp,
            timing_provenance=record.timing_provenance,
            integrity_status=record.integrity_status,
            directness=record.directness,
            confidence=record.confidence,
            evidence={},
            unavailable_reason=record.unavailable_reason,
        )
        if observation.root_observation_id != root:
            raise ValueError("artifact_evidence_session_root_materialization_mismatch")
        observations.append(observation)

    materialized_roots = {item.root_observation_id for item in observations}
    required_roots = {
        record.root_observation_id
        for record in tag_evidence.records
        if record.root_observation_id.startswith("obs_")
    } - yara_roots
    if not required_roots.issubset(materialized_roots):
        raise ValueError("artifact_evidence_session_physical_root_missing")
    return tuple(observations)


def _static_analyses(value: object) -> tuple[StaticProgramAnalysis, ...]:
    if type(value) is not tuple:
        raise TypeError("artifact_evidence_session_static_analyses_invalid")
    if any(type(item) is not StaticProgramAnalysis for item in value):
        raise TypeError("artifact_evidence_session_static_analysis_owner_invalid")
    ordered = tuple(sorted(value, key=lambda item: item.semantic_digest))
    if len({item.semantic_digest for item in ordered}) != len(ordered):
        raise ValueError("artifact_evidence_session_static_analysis_duplicate")
    return ordered


def _analysis_limitations(analyses: tuple[StaticProgramAnalysis, ...]) -> tuple[str, ...]:
    limitations: set[str] = set()
    for analysis in analyses:
        limitations.update(analysis.limitations)
        limitations.update(analysis.unresolved_constructs)
        if analysis.unavailable_reason:
            limitations.add(analysis.unavailable_reason)
        if analysis.parser_status not in {"complete", "not_applicable"}:
            limitations.add("static_parser_status:" + analysis.parser_status)
    return tuple(sorted(limitations))


def _frontend_query_capabilities(
    analyses: tuple[StaticProgramAnalysis, ...],
) -> tuple[str, ...]:
    # Refinement queries execute only against already-produced immutable static
    # analyses.  No second frontend invocation exists.  If no static analysis was
    # applicable there is no static refinement substrate and every requirement is
    # explicitly deferred by the planner.
    if not analyses:
        return ()
    return tuple(sorted(EVIDENCE_DISCOVERY_QUERY_KINDS))


def _refinement_limitations(plan: EvidenceDiscoveryPlan) -> tuple[str, ...]:
    limitations: list[str] = []
    for query in plan.queries:
        if query.execution_state == "already_satisfied":
            continue
        if query.execution_state == "selected":
            # The selected query is deterministically checked against the already
            # computed StaticProgramAnalysis.  Phase 11 intentionally does not
            # rerun a scanner.  A requirement that remains missing is recorded as
            # incomplete evidence rather than a negative fact.
            limitations.append("evidence_discovery_unresolved:" + query.requirement_id)
        else:
            limitations.append(
                "evidence_discovery_unavailable:"
                + query.requirement_id
                + ":"
                + query.execution_state
            )
    return tuple(sorted(set(limitations)))


def _completeness(
    read_snapshot: ArtifactReadSnapshot,
    limitations: tuple[str, ...],
) -> str:
    if not read_snapshot.complete:
        return "unavailable"
    return "partial" if limitations else "complete"


class ArtifactEvidenceSession:
    """Single bounded lifecycle owner for one artifact evidence generation."""

    __slots__ = (
        "_artifact_read_snapshot",
        "_static_program_analyses",
        "_yara_scan_result",
        "_base_limitations",
        "_provisional_evidence",
        "_model_context",
        "_discovery_plan",
        "_refinement_limitations",
        "_final_evidence",
        "_state",
    )

    def __init__(
        self,
        *,
        artifact_read_snapshot: ArtifactReadSnapshot,
        static_program_analyses: tuple[StaticProgramAnalysis, ...],
        yara_scan_result: YaraScanResult,
    ) -> None:
        if type(artifact_read_snapshot) is not ArtifactReadSnapshot:
            raise TypeError("artifact_evidence_session_read_snapshot_required")
        if type(yara_scan_result) is not YaraScanResult:
            raise TypeError("artifact_evidence_session_yara_result_required")
        analyses = _static_analyses(static_program_analyses)
        self._artifact_read_snapshot = artifact_read_snapshot
        self._static_program_analyses = analyses
        self._yara_scan_result = yara_scan_result
        self._base_limitations = _analysis_limitations(analyses)
        self._provisional_evidence = None
        self._model_context = None
        self._discovery_plan = None
        self._refinement_limitations = ()
        self._final_evidence = None
        self._state = "baseline"

    def provisional_evidence(
        self,
        *,
        tag_evidence: TagEvidence,
        chain_evidence: ChainEvidence,
    ) -> ArtifactEvidenceSnapshot:
        if self._state != "baseline":
            raise RuntimeError("artifact_evidence_session_provisional_state_invalid")
        observations = _physical_observation_roots(tag_evidence, self._yara_scan_result)
        evidence = ArtifactEvidenceSnapshot(
            artifact_read_snapshot=self._artifact_read_snapshot,
            physical_observations=observations,
            static_program_analyses=self._static_program_analyses,
            yara_scan_result=self._yara_scan_result,
            tag_evidence=tag_evidence,
            chain_evidence=chain_evidence,
            parser_analysis_limitations=self._base_limitations,
            evidence_completeness=_completeness(
                self._artifact_read_snapshot, self._base_limitations,
            ),
        )
        self._provisional_evidence = evidence
        self._state = "provisional"
        return evidence

    def bind_model_context(self, model_context: ModelContextSnapshot) -> None:
        if self._state != "provisional":
            raise RuntimeError("artifact_evidence_session_context_state_invalid")
        if type(model_context) is not ModelContextSnapshot:
            raise TypeError("artifact_evidence_session_model_context_required")
        if model_context.source_artifact_evidence_digest != self._provisional_evidence.semantic_digest:
            raise ValueError("artifact_evidence_session_model_context_source_mismatch")
        self._model_context = model_context
        self._state = "context"

    def bind_discovery_plan(self, plan: EvidenceDiscoveryPlan) -> None:
        if self._state != "context":
            raise RuntimeError("artifact_evidence_session_plan_state_invalid")
        if type(plan) is not EvidenceDiscoveryPlan:
            raise TypeError("artifact_evidence_session_discovery_plan_required")
        if plan.source_artifact_evidence_digest != self._provisional_evidence.semantic_digest:
            raise ValueError("artifact_evidence_session_discovery_source_mismatch")
        if plan.model_context_digest != self._model_context.semantic_digest:
            raise ValueError("artifact_evidence_session_discovery_context_mismatch")
        self._discovery_plan = plan
        self._state = "planned"

    def refine(self) -> tuple[str, ...]:
        if self._state != "planned":
            raise RuntimeError("artifact_evidence_session_refinement_state_invalid")
        self._refinement_limitations = _refinement_limitations(self._discovery_plan)
        self._state = "refined"
        return self._refinement_limitations

    def freeze_final(
        self,
        *,
        tag_evidence: TagEvidence,
        chain_evidence: ChainEvidence,
    ) -> ArtifactEvidenceSnapshot:
        if self._state != "refined":
            raise RuntimeError("artifact_evidence_session_freeze_state_invalid")
        limitations = tuple(sorted(set((*self._base_limitations, *self._refinement_limitations))))
        observations = _physical_observation_roots(tag_evidence, self._yara_scan_result)
        evidence = ArtifactEvidenceSnapshot(
            artifact_read_snapshot=self._artifact_read_snapshot,
            physical_observations=observations,
            static_program_analyses=self._static_program_analyses,
            yara_scan_result=self._yara_scan_result,
            tag_evidence=tag_evidence,
            chain_evidence=chain_evidence,
            parser_analysis_limitations=limitations,
            evidence_completeness=_completeness(self._artifact_read_snapshot, limitations),
        )
        self._final_evidence = evidence
        self._state = "frozen"
        return evidence

    @property
    def frozen(self) -> bool:
        return self._state == "frozen"


@dataclass(frozen=True, slots=True)
class ArtifactEvidenceLifecycleResult:
    provisional_evidence: ArtifactEvidenceSnapshot
    model_context: ModelContextSnapshot
    candidate_retrieval: AttackCandidateRetrievalResult
    discovery_plan: EvidenceDiscoveryPlan
    final_evidence: ArtifactEvidenceSnapshot


def build_artifact_evidence_lifecycle(
    *,
    artifact_read_snapshot: ArtifactReadSnapshot,
    scan_session_snapshot: ScanSessionSnapshot,
    static_program_analyses: tuple[StaticProgramAnalysis, ...],
    yara_scan_result: YaraScanResult,
    tag_evidence: TagEvidence,
    chain_evidence: ChainEvidence,
    node: object,
    path: object,
    strings_blob: object,
    api_result: object,
    ordered_events: object,
    behavior_timeline: object,
    prev_stage: object,
    curr_stage: object,
    model_context_builder: object = build_detection_model_context,
    profile_context_builder: object = build_detection_profile_context,
) -> ArtifactEvidenceLifecycleResult:
    """Execute one bounded evidence lifecycle and construct model context after E0."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("artifact_evidence_session_scan_session_required")
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=artifact_read_snapshot,
        static_program_analyses=static_program_analyses,
        yara_scan_result=yara_scan_result,
    )
    provisional = session.provisional_evidence(
        tag_evidence=tag_evidence,
        chain_evidence=chain_evidence,
    )
    api_calls = api_result.get("api_calls", ()) if hasattr(api_result, "get") else ()
    model_context = model_context_builder(
        node,
        tags=tag_evidence,
        chain_evidence=chain_evidence,
        projection_identity=model_projection_identity(scan_session_snapshot),
        source_artifact_evidence_digest=provisional.semantic_digest,
        file_structure=path,
        strings_blob=strings_blob,
        api_calls=api_calls,
        ordered_events=ordered_events,
        behavior_timeline=behavior_timeline,
        prev_stage="unknown" if prev_stage is None else prev_stage,
        curr_stage="unknown" if curr_stage is None else curr_stage,
        profile_context_builder=profile_context_builder,
        update_cluster=False,
    )
    if type(model_context) is not ModelContextSnapshot:
        raise TypeError("artifact_evidence_session_model_context_required")
    if model_context.source_artifact_evidence_digest != provisional.semantic_digest:
        raise ValueError("artifact_evidence_session_model_context_source_mismatch")
    session.bind_model_context(model_context)
    candidate_retrieval = retrieve_current_attack_candidates(
        node,
        tag_evidence,
        chain_evidence,
        model_context,
    )
    plan = build_evidence_discovery_plan(
        provisional,
        model_context,
        candidate_retrieval,
        frontend_capability_query_kinds=_frontend_query_capabilities(static_program_analyses),
        resource_budget=_FULL_DISCOVERY_BUDGET,
    )
    session.bind_discovery_plan(plan)
    session.refine()
    final = session.freeze_final(
        tag_evidence=tag_evidence,
        chain_evidence=chain_evidence,
    )
    if not session.frozen:
        raise RuntimeError("artifact_evidence_session_final_freeze_missing")
    return ArtifactEvidenceLifecycleResult(
        provisional_evidence=provisional,
        model_context=model_context,
        candidate_retrieval=candidate_retrieval,
        discovery_plan=plan,
        final_evidence=final,
    )

