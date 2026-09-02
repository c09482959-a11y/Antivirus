"""Merged Phase 15 canonical static-program-analysis contract gates."""
from __future__ import annotations

import hashlib

import pytest

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_LIMITATION_CODES,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
    StaticSourceLocation,
    project_static_operation_observations,
    static_artifact_identity,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


_PHASE15_CONTENT = b"phase15-static-contract"
_PHASE15_CONTENT_SHA256 = hashlib.sha256(_PHASE15_CONTENT).hexdigest()


def _operation(*, limitations: tuple[str, ...] = (), resolved_arguments: object = None) -> StaticOperation:
    return StaticOperation.create(
        language="python",
        operation_kind="network_send",
        source_location=StaticSourceLocation(
            static_artifact_identity(_PHASE15_CONTENT_SHA256),
            line=2, column=0, end_line=2, end_column=12,
        ),
        enclosing_function_id="fn_main",
        basic_block_id="bb_entry",
        control_flow_ordinal=1,
        control_flow_provenance="static_control_flow",
        reachability_state="entrypoint_reachable",
        platform="windows",
        actor_program_entity="spe_module",
        target_resource_identity="res_endpoint",
        input_value_ids=("val_payload",),
        output_value_ids=("val_result",),
        flow_identity="flow_payload",
        resolved_arguments={"url": "https://example.invalid"} if resolved_arguments is None else resolved_arguments,
        resolution_state="resolved",
        limitations=limitations,
        integrity_status="verified",
    )


def _analysis(operation: StaticOperation, *, limitations: tuple[str, ...] = ()) -> StaticProgramAnalysis:
    content = _PHASE15_CONTENT
    digest = _PHASE15_CONTENT_SHA256
    edge = StaticFlowEdge.create(
        flow_identity=operation.flow_identity,
        edge_kind="source_to_sink",
        source_value_id=operation.input_value_ids[0],
        target_value_id=operation.output_value_ids[0],
        source_operation_id=operation.operation_id,
        target_operation_id=operation.operation_id,
        resolution_state="resolved",
        limitations=limitations,
        integrity_status="verified",
    )
    return StaticProgramAnalysis(
        content_sha256=digest,
        content_size=len(content),
        artifact_identity=static_artifact_identity(digest),
        language="python",
        language_version="3",
        parser_status="complete",
        parser_schema_version="phase15_test_parser_v1",
        parser_digest="a" * 64,
        operations=(operation,),
        flow_edges=(edge,),
        entrypoint_function_ids=("fn_main",),
        unresolved_constructs=(),
        limitations=limitations,
        integrity_status="verified",
    )



def test_phase15_analysis_rejects_path_instance_locator() -> None:
    operation = _operation()
    forged = StaticOperation.create(
        language=operation.language,
        operation_kind=operation.operation_kind,
        source_location=StaticSourceLocation(
            "/tmp/path-instance.py", line=2, column=0, end_line=2, end_column=12,
        ),
        enclosing_function_id=operation.enclosing_function_id,
        basic_block_id=operation.basic_block_id,
        control_flow_ordinal=operation.control_flow_ordinal,
        control_flow_provenance=operation.control_flow_provenance,
        reachability_state=operation.reachability_state,
        platform=operation.platform,
        actor_program_entity=operation.actor_program_entity,
        target_resource_identity=operation.target_resource_identity,
        input_value_ids=operation.input_value_ids,
        output_value_ids=operation.output_value_ids,
        flow_identity=operation.flow_identity,
        resolved_arguments=dict(operation.resolved_arguments),
        resolution_state=operation.resolution_state,
        limitations=operation.limitations,
        integrity_status=operation.integrity_status,
    )
    with pytest.raises(ValueError, match="static_analysis_operation_source_locator_mismatch"):
        _analysis(forged)

def test_phase15_rejects_hostile_operation_and_edge_before_attribute_access() -> None:
    class HostileOperation:
        touched = 0

        @property
        def operation_id(self) -> str:  # pragma: no cover - must never execute
            type(self).touched += 1
            raise AssertionError("hostile operation hook executed")

    class HostileEdge:
        touched = 0

        @property
        def edge_id(self) -> str:  # pragma: no cover - must never execute
            type(self).touched += 1
            raise AssertionError("hostile edge hook executed")

    kwargs = dict(
        content_sha256="b" * 64,
        content_size=1,
        artifact_identity="content_sha256:" + "b" * 64,
        language="python",
        language_version="3",
        parser_status="partial",
        parser_schema_version="phase15_test_parser_v1",
        parser_digest="c" * 64,
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(),
        integrity_status="partial",
    )
    with pytest.raises(TypeError, match="static_analysis_operation_owner_invalid"):
        StaticProgramAnalysis(operations=(HostileOperation(),), flow_edges=(), **kwargs)  # type: ignore[arg-type]
    assert HostileOperation.touched == 0

    with pytest.raises(TypeError, match="static_analysis_flow_edge_owner_invalid"):
        StaticProgramAnalysis(operations=(), flow_edges=(HostileEdge(),), **kwargs)  # type: ignore[arg-type]
    assert HostileEdge.touched == 0


def test_phase15_limitation_vocabulary_is_single_bounded_and_deterministic() -> None:
    assert "source_size_limit_exceeded" in STATIC_LIMITATION_CODES
    assert "powershell_token_limit_exceeded" in STATIC_LIMITATION_CODES
    assert "typescript_parser_bridge_output_limit_exceeded" in STATIC_LIMITATION_CODES

    left = _operation(limitations=("target_unresolved", "ambiguous_source_flow", "target_unresolved"))
    right = _operation(limitations=("ambiguous_source_flow", "target_unresolved"))
    assert left.limitations == ("ambiguous_source_flow", "target_unresolved")
    assert left == right

    left_analysis = _analysis(left, limitations=("control_flow_unresolved", "parser_timeout"))
    right_analysis = _analysis(right, limitations=("parser_timeout", "control_flow_unresolved"))
    assert left_analysis.limitations == ("control_flow_unresolved", "parser_timeout")
    assert left_analysis.flow_edges[0].limitations == ("control_flow_unresolved", "parser_timeout")
    assert left_analysis.semantic_digest == right_analysis.semantic_digest

    with pytest.raises(ValueError, match="static_operation_limitation_invalid"):
        _operation(limitations=("arbitrary_unregistered_limitation",))
    with pytest.raises(ValueError, match="static_flow_limitation_invalid"):
        StaticFlowEdge.create(
            flow_identity="flow_x",
            edge_kind="source_to_sink",
            source_value_id="val_a",
            target_value_id="val_b",
            source_operation_id="",
            target_operation_id="",
            limitations=("arbitrary_unregistered_limitation",),
            integrity_status="partial",
        )


def test_phase15_resolved_json_integer_is_bounded_and_schema_bound() -> None:
    with pytest.raises(ValueError, match="static_analysis_json_integer_exceeded"):
        _operation(resolved_arguments={"value": 1 << 300})
    assert len(STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST) == 64


def test_phase15_only_validated_static_reference_can_mint_flow_correlation() -> None:
    analysis = _analysis(_operation())
    projected = project_static_operation_observations(analysis, analysis.operations[0])[0]
    projected_record = normalize_tag_evidence((projected,), derive=False).records[0]
    assert projected_record.correlation_group == analysis.operations[0].flow_identity

    forged_flow = "flow_" + "f" * 32
    forged = DetectionObservation.create(
        tag="static_network_send_operation",
        producer_id="phase15_test",
        stage_id="static_reference_validation",
        modality="static_control_flow",
        actor_identity="spe_forged",
        artifact_identity="content_sha256:" + "d" * 64,
        source_location=ObservationSourceLocation(
            "static_operation",
            locator="forged.py",
            event_id="sop_" + "e" * 40,
        ),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
        evidence={
            "claim_scope": "static_operation",
            "execution_observed": False,
            "static_observation_reference": {"flow_identity": forged_flow},
        },
    )
    forged_record = normalize_tag_evidence((forged,), derive=False).records[0]
    assert forged_record.correlation_group != forged_flow
