"""Phase 7 gates for StaticFlowEdge-backed canonical Chain causality."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import (
    ChainEvent,
    ChainRule,
    ChainStep,
    StaticChainRelationConstraint,
)
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.static_program_analysis import (
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
    StaticSourceLocation,
    project_static_operation_observations,
    static_artifact_identity,
)
from Virus_Scan.detection.chains.execution.anchors import (
    evaluate_chain_evidence,
    evaluate_chain_evidence_generation,
)
from Virus_Scan.detection.chains.execution.matching import evaluate_chain_rule
from Virus_Scan.detection.registries.chain_registry import chain_rule
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.scanners.static_program_analysis.python_frontend import analyze_python_renpy_snapshot


_INJECTION_CHAIN = "static.artifact.virtualallocex_writeprocessmemory_createremotethread"
_INJECTION_SOURCE = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)


def _injection_analysis(tmp_path: Path) -> StaticProgramAnalysis:
    target = tmp_path / "injection.py"
    target.write_text(_INJECTION_SOURCE, encoding="utf-8")
    return analyze_python_renpy_snapshot(build_artifact_read_snapshot(target)).analysis


def _tags(analysis: StaticProgramAnalysis):
    observations = tuple(
        observation
        for operation in analysis.operations
        for observation in project_static_operation_observations(analysis, operation)
    )
    return normalize_tag_evidence(observations, derive=False)


def _decision(evidence):
    return next(item for item in evidence.decisions if item.candidate.chain_id == _INJECTION_CHAIN)


def test_phase7_canonical_static_injection_requires_exact_ir_relations(tmp_path: Path) -> None:
    analysis = _injection_analysis(tmp_path)
    tags = _tags(analysis)
    rule = chain_rule(_INJECTION_CHAIN)
    assert rule is not None
    assert len(rule.static_relations) == 2
    assert all(item.require_data_flow_path for item in rule.static_relations)
    assert all(item.same_program_entity and item.same_resource for item in rule.static_relations)

    tags_only = _decision(evaluate_chain_evidence(tags=tags, rule_ids=(_INJECTION_CHAIN,)))
    assert tags_only.status == "candidate"
    assert any("operation_unavailable" in item for item in tags_only.candidate.unmet_requirements)

    verified = _decision(evaluate_chain_evidence(
        tags=tags,
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(analysis,),
    ))
    assert verified.status == "confirmed"
    assert verified.candidate.order_class == "static_control_flow"
    assert verified.candidate.unmet_requirements == ()


def test_phase7_removing_static_flow_invalidates_confirmation_and_incremental_reuse(tmp_path: Path) -> None:
    analysis = _injection_analysis(tmp_path)
    tags = _tags(analysis)
    initial = evaluate_chain_evidence_generation(
        tags=tags,
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(analysis,),
    )
    assert _decision(initial.evidence).status == "confirmed"

    disconnected = replace(analysis, flow_edges=(), semantic_digest="")
    changed = evaluate_chain_evidence_generation(
        tags=tags,
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(disconnected,),
        previous_generation=initial,
    )
    decision = _decision(changed.evidence)
    assert changed.static_relation_digest != initial.static_relation_digest
    assert changed.evaluated_rule_ids == (_INJECTION_CHAIN,)
    assert changed.reused_rule_ids == ()
    assert decision.status == "candidate"
    assert any("data_flow_path_unsatisfied" in item for item in decision.candidate.unmet_requirements)


def _manual_analysis(*, wrong_resource: bool = False, unresolved: bool = False, include_control: bool = True, include_data: bool = True):
    content = b"phase7-static-chain-causality"
    digest = hashlib.sha256(content).hexdigest()
    artifact = static_artifact_identity(digest)
    source = StaticOperation.create(
        language="python", operation_kind="file_read",
        source_location=StaticSourceLocation(artifact, line=1, column=0, end_line=1, end_column=4),
        enclosing_function_id="fn_main", basic_block_id="bb_0", control_flow_ordinal=0,
        control_flow_provenance="static_control_flow", reachability_state="entrypoint_reachable",
        platform="linux", actor_program_entity="spe_main", target_resource_identity="res_shared",
        input_value_ids=(), output_value_ids=("val_payload",), flow_identity="flow_payload",
        resolved_arguments={}, resolution_state="resolved", limitations=(), integrity_status="verified",
    )
    target = StaticOperation.create(
        language="python", operation_kind="network_send",
        source_location=StaticSourceLocation(artifact, line=2, column=0, end_line=2, end_column=4),
        enclosing_function_id="fn_main", basic_block_id="bb_1", control_flow_ordinal=1,
        control_flow_provenance="static_control_flow", reachability_state="entrypoint_reachable",
        platform="linux", actor_program_entity="spe_main",
        target_resource_identity="res_other" if wrong_resource else "res_shared",
        input_value_ids=("val_payload",), output_value_ids=(), flow_identity="flow_payload",
        resolved_arguments={}, resolution_state="partial" if unresolved else "resolved",
        limitations=("target_unresolved",) if unresolved else (),
        integrity_status="partial" if unresolved else "verified",
    )
    edges = []
    if include_control:
        edges.append(StaticFlowEdge.create(
            flow_identity="", edge_kind="fallthrough", source_value_id="", target_value_id="",
            source_operation_id=source.operation_id, target_operation_id=target.operation_id,
            resolution_state="resolved", limitations=(), integrity_status="verified",
        ))
    if include_data:
        edges.append(StaticFlowEdge.create(
            flow_identity="flow_payload", edge_kind="source_to_sink",
            source_value_id="val_payload", target_value_id="val_payload",
            source_operation_id=source.operation_id, target_operation_id=target.operation_id,
            resolution_state="resolved", limitations=(), integrity_status="verified",
        ))
    analysis = StaticProgramAnalysis(
        content_sha256=digest, content_size=len(content), artifact_identity=artifact,
        language="python", language_version="3", parser_status="partial" if unresolved else "complete",
        parser_schema_version="phase7_test_parser_v1", parser_digest="a" * 64,
        operations=(source, target), flow_edges=tuple(edges), entrypoint_function_ids=("fn_main",),
        unresolved_constructs=(), limitations=("target_unresolved",) if unresolved else (),
        integrity_status="partial" if unresolved else "verified",
    )
    events = tuple(
        ChainEvent(
            evidence_id=f"ev_{index}", root_evidence_id=f"obs_phase7_root_{index}", term=term,
            source="tag_evidence", ordinal=index, observation_id=f"obs_phase7_event_{index}",
            modality="static_control_flow", platform="linux",
            actor_identity=operation.actor_program_entity, target_identity=operation.target_resource_identity,
            artifact_identity=artifact,
            source_location=ObservationSourceLocation(
                "static_operation", locator=operation.source_location.locator, event_id=operation.operation_id,
            ),
            timing_provenance="static_control_flow", integrity_status=operation.integrity_status,
            directness="direct",
        )
        for index, (term, operation) in enumerate((("phase7_source", source), ("phase7_sink", target)))
    )
    return analysis, events


def _manual_rule() -> ChainRule:
    return ChainRule(
        chain_id="phase7.static.causality", version="phase7", family="generic", match_mode="ordered",
        steps=(ChainStep(("phase7_source",)), ChainStep(("phase7_sink",))), minimum_distinct_roots=2,
        confidence=1.0, operational_severity=1.0, score_points=0.0, required_modalities=("static_control_flow",),
        static_relations=(StaticChainRelationConstraint(
            source_step_index=0, target_step_index=1,
            require_control_flow_path=True, allowed_control_edge_kinds=("fallthrough",),
            require_data_flow_path=True, allowed_data_edge_kinds=("source_to_sink",),
            require_same_value=True, same_program_entity=True, same_resource=True,
            source_reachability_states=("entrypoint_reachable",),
            target_reachability_states=("entrypoint_reachable",),
            source_resolution_states=("resolved",), target_resolution_states=("resolved",),
            relation_resolution_states=("resolved",),
        ),),
    )


def test_phase7_generic_chain_relation_supports_control_data_same_value_resource_and_resolution() -> None:
    rule = _manual_rule()
    analysis, events = _manual_analysis()
    assert evaluate_chain_rule(rule, events, static_program_analyses=(analysis,)).status == "confirmed"

    for kwargs, expected in (
        ({"include_control": False}, "control_flow_path_unsatisfied"),
        ({"include_data": False}, "data_flow_path_unsatisfied"),
        ({"wrong_resource": True}, "resource_mismatch"),
        ({"unresolved": True}, "target_resolution_unsatisfied"),
    ):
        changed, changed_events = _manual_analysis(**kwargs)
        decision = evaluate_chain_rule(rule, changed_events, static_program_analyses=(changed,))
        assert decision is not None
        assert decision.status == "candidate"
        assert any(expected in item for item in decision.candidate.unmet_requirements)



def test_phase7_compact_python_injection_emits_unique_flow_roots_and_confirms(tmp_path: Path) -> None:
    source = (
        "import ctypes\n"
        "k=ctypes.windll.kernel32\n"
        "p=k.OpenProcess(1,False,1)\n"
        "r=k.VirtualAllocEx(p,None,4096,0x3000,0x40)\n"
        "k.WriteProcessMemory(p,r,b'x',1,None)\n"
        "k.CreateRemoteThread(p,None,0,r,None,0,None)\n"
    )
    target = tmp_path / "compact_injection.py"
    target.write_text(source, encoding="utf-8")
    analysis = analyze_python_renpy_snapshot(build_artifact_read_snapshot(target)).analysis
    assert len({edge.edge_id for edge in analysis.flow_edges}) == len(analysis.flow_edges)
    tags = _tags(analysis)
    decision = _decision(evaluate_chain_evidence(
        tags=tags,
        rule_ids=(_INJECTION_CHAIN,),
        static_program_analyses=(analysis,),
    ))
    assert decision.status == "confirmed"
    assert decision.candidate.unmet_requirements == ()

def test_phase7_model_behavior_flow_cannot_enter_chain_relation_authority() -> None:
    anchors_parameters = inspect.signature(evaluate_chain_evidence).parameters
    matcher_parameters = inspect.signature(evaluate_chain_rule).parameters
    assert "behavior_flow" not in anchors_parameters
    assert "model_context" not in anchors_parameters
    assert "behavior_flow" not in matcher_parameters
    assert "model_context" not in matcher_parameters
