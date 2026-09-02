"""Phase 11 canonical static-program-analysis contract and cache gates."""
from __future__ import annotations

from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path

import pytest

from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
    StaticSourceLocation,
    project_static_operation_observations,
    static_artifact_identity,
)
from Virus_Scan.orchestration.scan_session import (
    build_scan_session_snapshot,
    validate_scan_session_runtime,
)
from Virus_Scan.storage import ScanCacheRepository, SQLiteLifecycleOwner, sqlite_lifecycle


_PHASE11_CONTENT = b"phase11-static-analysis"
_PHASE11_CONTENT_SHA256 = hashlib.sha256(_PHASE11_CONTENT).hexdigest()


def _operation(
    *,
    operation_kind: str = "file_open",
    ordinal: int = 1,
    reachability: str = "entrypoint_reachable",
    provenance: str = "static_control_flow",
    input_value_ids: tuple[str, ...] = ("val_path",),
    output_value_ids: tuple[str, ...] = ("val_handle",),
    flow_identity: str = "flow_open",
    resolved_arguments: object = None,
    integrity_status: str = "verified",
    resolution_state: str = "resolved",
) -> StaticOperation:
    return StaticOperation.create(
        language="python",
        operation_kind=operation_kind,
        source_location=StaticSourceLocation(
            static_artifact_identity(_PHASE11_CONTENT_SHA256),
            line=3, column=4, end_line=3, end_column=24,
        ),
        enclosing_function_id="fn_main",
        basic_block_id="bb_entry",
        control_flow_ordinal=ordinal,
        control_flow_provenance=provenance,
        reachability_state=reachability,
        platform="windows",
        actor_program_entity="spe_module",
        target_resource_identity="res_login_store",
        input_value_ids=input_value_ids,
        output_value_ids=output_value_ids,
        flow_identity=flow_identity,
        resolved_arguments={"path": "Login Data"} if resolved_arguments is None else resolved_arguments,
        resolution_state=resolution_state,
        limitations=(),
        integrity_status=integrity_status,
    )


def _analysis(*, operation: StaticOperation | None = None) -> StaticProgramAnalysis:
    content_sha256 = _PHASE11_CONTENT_SHA256
    owned_operation = _operation() if operation is None else operation
    edge = StaticFlowEdge.create(
        flow_identity=owned_operation.flow_identity,
        edge_kind="source_to_sink",
        source_value_id=owned_operation.input_value_ids[0],
        target_value_id=owned_operation.output_value_ids[0],
        source_operation_id=owned_operation.operation_id,
        target_operation_id=owned_operation.operation_id,
        resolution_state="resolved",
        limitations=(),
        integrity_status="verified",
    )
    return StaticProgramAnalysis(
        content_sha256=content_sha256,
        content_size=len(_PHASE11_CONTENT),
        artifact_identity=static_artifact_identity(content_sha256),
        language="python",
        language_version="3",
        parser_status="complete",
        parser_schema_version="python_ast_static_program_v1",
        parser_digest="b" * 64,
        operations=(owned_operation,),
        flow_edges=(edge,),
        entrypoint_function_ids=("fn_main",),
        unresolved_constructs=(),
        limitations=(),
        integrity_status="verified",
    )


def test_phase11_round_trip_is_deterministic_and_current_schema_only() -> None:
    analysis = _analysis()
    record = analysis.to_record()
    rebuilt = StaticProgramAnalysis.from_record(record)
    assert rebuilt == analysis
    assert rebuilt.to_record() == record
    assert rebuilt.semantic_digest == analysis.semantic_digest
    assert analysis.schema_version == STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION
    assert len(STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST) == 64
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
    assert json.loads(encoded) == record


def test_phase11_operation_identity_binds_reachability_and_resolved_arguments() -> None:
    baseline = _operation()
    different_reachability = _operation(reachability="unreachable")
    different_argument = _operation(resolved_arguments={"path": "Local State"})
    assert baseline.operation_id != different_reachability.operation_id
    assert baseline.operation_id != different_argument.operation_id


def test_phase11_static_identities_cannot_be_runtime_identities() -> None:
    with pytest.raises(ValueError, match="static_operation_actor_identity_invalid"):
        StaticOperation.create(
            language="python",
            operation_kind="process_open",
            source_location=StaticSourceLocation("sample.py", line=1),
            enclosing_function_id="fn_main",
            basic_block_id="bb_entry",
            control_flow_ordinal=0,
            control_flow_provenance="static_control_flow",
            reachability_state="entrypoint_reachable",
            platform="windows",
            actor_program_entity="pid:1234",
            resolution_state="resolved",
            integrity_status="verified",
        )
    assert "process_identity" not in {item.name for item in fields(StaticOperation)}
    assert "host_identity" not in {item.name for item in fields(StaticOperation)}


def test_phase11_physical_records_contain_no_attack_or_probability_authority() -> None:
    record = _analysis().to_record()
    serialized = json.dumps(record, sort_keys=True).lower()
    for forbidden in ("technique", "p_mitre", "probability", "attack_id"):
        assert forbidden not in serialized


def test_phase11_projector_preserves_static_scope_without_runtime_claim() -> None:
    analysis = _analysis()
    operation = analysis.operations[0]
    observation = project_static_operation_observations(analysis, operation)[0]
    record = observation.to_record()
    assert observation.modality == "static_control_flow"
    assert observation.directness == "direct"
    assert observation.process_identity == ""
    assert observation.host_identity == ""
    assert observation.connection_identity == ""
    assert observation.source_location.event_id == operation.operation_id
    assert record["evidence"]["execution_observed"] is False
    assert record["evidence"]["claim_scope"] == "static_operation"
    assert record["evidence"]["static_observation_reference"]["analysis_semantic_digest"] == analysis.semantic_digest


def test_phase11_unreachable_operation_is_context_only_parsed_fact() -> None:
    operation = _operation(reachability="unreachable")
    analysis = _analysis(operation=operation)
    observation = project_static_operation_observations(analysis, analysis.operations[0])[0]
    assert observation.directness == "context"
    assert observation.evidence["reachability_state"] == "unreachable"
    assert observation.evidence["execution_observed"] is False


def test_phase11_syntactic_only_operation_does_not_claim_control_flow() -> None:
    operation = _operation(
        provenance="syntactic_order",
        reachability="unresolved",
        resolution_state="partial",
        integrity_status="partial",
    )
    operation = StaticOperation.create(
        language=operation.language,
        operation_kind=operation.operation_kind,
        source_location=StaticSourceLocation(
            static_artifact_identity("c" * 64), line=3, column=4, end_line=3, end_column=24,
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
    analysis = StaticProgramAnalysis(
        content_sha256="c" * 64,
        content_size=1,
        artifact_identity="content_sha256:" + "c" * 64,
        language="python",
        language_version="3",
        parser_status="partial",
        parser_schema_version="python_ast_static_program_v1",
        parser_digest="d" * 64,
        operations=(operation,),
        flow_edges=(),
        entrypoint_function_ids=("fn_main",),
        unresolved_constructs=("dynamic_dispatch",),
        limitations=("control_flow_unresolved",),
        integrity_status="partial",
    )
    observation = project_static_operation_observations(analysis, analysis.operations[0])[0]
    assert observation.modality == "static_structure"
    assert observation.timing_provenance == "syntactic_order"
    assert observation.confidence == 0.5


def test_phase11_hostile_container_subclasses_are_rejected_without_hooks() -> None:
    class HostileDict(dict):
        touched = 0

        def items(self):  # pragma: no cover - must never execute
            type(self).touched += 1
            raise AssertionError("hostile mapping hook executed")

        def __iter__(self):  # pragma: no cover - must never execute
            type(self).touched += 1
            raise AssertionError("hostile iterator hook executed")

    with pytest.raises(TypeError, match="static_analysis_json_value_invalid"):
        _operation(resolved_arguments=HostileDict({"path": "Login Data"}))
    assert HostileDict.touched == 0
    with pytest.raises(TypeError, match="static_program_analysis_record_invalid"):
        StaticProgramAnalysis.from_record(HostileDict(_analysis().to_record()))
    assert HostileDict.touched == 0


def test_phase11_static_source_ranges_are_structurally_validated() -> None:
    with pytest.raises(ValueError, match="static_source_column_without_line"):
        StaticSourceLocation("sample.py", column=1)
    with pytest.raises(ValueError, match="static_source_column_range_invalid"):
        StaticSourceLocation("sample.py", line=1, column=4, end_line=1, end_column=2)


def test_phase11_static_analysis_cache_is_exact_and_fails_closed(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    repository = ScanCacheRepository(lifecycle)
    repository.configure(tmp_path / "profiles", enabled=True)
    analysis = _analysis()
    dependency = "e" * 64
    try:
        assert repository.put_static_analysis(
            content_sha256=analysis.content_sha256,
            content_size=analysis.content_size,
            analysis_dependency_digest=dependency,
            analysis=analysis,
        ) is True
        hit = repository.get_static_analysis(
            content_sha256=analysis.content_sha256,
            analysis_dependency_digest=dependency,
        )
        assert hit is not None
        assert hit.analysis == analysis
        assert hit.analysis_dependency_digest == dependency
        assert repository.get_static_analysis(
            content_sha256=analysis.content_sha256,
            analysis_dependency_digest="f" * 64,
        ) is None
        assert repository.stats()["static_analyses"] == 1

        lifecycle.connection("cache").execute(
            "UPDATE cache_static_operations SET result_sha256=? WHERE content_sha256=? AND analysis_digest=?",
            ("0" * 64, analysis.content_sha256, dependency),
        )
        assert repository.get_static_analysis(
            content_sha256=analysis.content_sha256,
            analysis_dependency_digest=dependency,
        ) is None
        assert lifecycle.connection("cache").execute(
            "SELECT 1 FROM cache_static_operations WHERE content_sha256=? AND analysis_digest=?",
            (analysis.content_sha256, dependency),
        ).fetchone() is None
    finally:
        lifecycle.close()


def test_phase11_session_binds_static_ir_and_packaged_parser_contracts(
    tmp_path: Path,
) -> None:
    previous_base_dir = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(tmp_path / "runtime")
    try:
        snapshot = build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )
        assert snapshot.static_ir_state == "available"
        assert snapshot.static_ir_schema_version == STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION
        assert snapshot.static_ir_reason == ""
        assert snapshot.parser_state == "available"
        assert snapshot.parser_reason == ""
        parser_subsystem = next(item for item in snapshot.subsystem_states if item.name == "language_parser_registry")
        assert parser_subsystem.state == "available"
        assert parser_subsystem.reason == ""
        native_decoder = next(item for item in snapshot.subsystem_states if item.name == "native_decoder")
        assert native_decoder.state == "available"
        assert len(native_decoder.identity_digest) == 64
        assert native_decoder.reason == ""
        subsystem = next(item for item in snapshot.subsystem_states if item.name == "static_program_analysis")
        assert subsystem.state == "available"
        assert subsystem.identity_digest == STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST
        assert subsystem.reason == ""
        assert validate_scan_session_runtime(snapshot) is snapshot
    finally:
        sqlite_lifecycle().close()
        if previous_base_dir is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous_base_dir
