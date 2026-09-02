from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.scanners.static_program_analysis.native_elf_x86_64_frontend import analyze_native_elf_x86_64_snapshot
from Virus_Scan.stress.static_semantic_binary_fixtures import build_semantic_elf64_x86_64_fixture


def _analysis(tmp_path: Path, variant: str):
    target = tmp_path / (variant + ".elf")
    target.write_bytes(build_semantic_elf64_x86_64_fixture(
        variant, identity_marker="UMIGE_STATIC_SEMANTIC:phase6-production-" + variant,
    ))
    return analyze_native_elf_x86_64_snapshot(build_artifact_read_snapshot(target)).analysis


def _kinds(analysis) -> set[str]:
    return {item.operation_kind for item in analysis.operations}


def _semantic_ops(analysis, kind: str):
    return tuple(item for item in analysis.operations if item.operation_kind == kind)


def test_phase6_public_frontend_is_orchestration_only_and_internal_owners_are_unique() -> None:
    root = Path(__file__).resolve().parents[1] / "scanners/static_program_analysis"
    public = (root / "native_elf_x86_64_frontend.py").read_text(encoding="utf-8")
    for module in (
        "elf_x86_64_structure", "elf_x86_64_symbols", "elf_x86_64_disassembly",
        "elf_x86_64_abstract_state", "elf_x86_64_semantics", "elf_x86_64_dataflow",
    ):
        assert (root / (module + ".py")).is_file()
        assert module in public
    assert "class _Analyzer" not in public
    assert "_ELF_HEADER =" not in public
    assert "def _parse_elf" not in public
    # There remains exactly one registered production native-ELF frontend.
    registry = (root / "frontend_registry.py").read_text(encoding="utf-8")
    assert registry.count('scanner_id="native_elf_x86_64_static_analysis"') == 1


def test_phase6_resolved_import_calls_become_semantic_operations_with_one_physical_root(tmp_path: Path) -> None:
    analysis = _analysis(tmp_path, "import_flow_positive")
    assert analysis.parser_status == "complete"
    read = _semantic_ops(analysis, "file_read")
    send = _semantic_ops(analysis, "network_send")
    assert len(read) == len(send) == 1
    assert dict(read[0].resolved_arguments)["resolved_external_symbol"] == "read"
    assert dict(send[0].resolved_arguments)["resolved_external_symbol"] == "send"
    assert read[0].output_value_ids
    assert send[0].input_value_ids == read[0].output_value_ids
    assert not any(item.operation_kind == "native_call" for item in analysis.operations)
    addresses = [dict(item.resolved_arguments)["virtual_address"] for item in analysis.operations]
    assert len(addresses) == len(set(addresses))
    flow = tuple(item for item in analysis.flow_edges if item.edge_kind == "source_to_sink")
    assert len(flow) == 1
    assert flow[0].source_operation_id == read[0].operation_id
    assert flow[0].target_operation_id == send[0].operation_id
    assert flow[0].source_value_id == flow[0].target_value_id == read[0].output_value_ids[0]


def test_phase6_symbol_presence_without_reachable_call_has_zero_semantic_authority(tmp_path: Path) -> None:
    symbols = _analysis(tmp_path, "symbols_no_calls")
    unreachable = _analysis(tmp_path, "calls_unreachable")
    for analysis in (symbols, unreachable):
        assert "file_read" not in _kinds(analysis)
        assert "network_send" not in _kinds(analysis)
        assert not any(item.edge_kind == "source_to_sink" for item in analysis.flow_edges)


def test_phase6_disconnected_value_flow_does_not_create_source_to_sink(tmp_path: Path) -> None:
    analysis = _analysis(tmp_path, "no_value_flow")
    assert {"file_read", "network_send"}.issubset(_kinds(analysis))
    assert not any(item.edge_kind == "source_to_sink" for item in analysis.flow_edges)


def test_phase6_wrong_target_identity_is_recovered_from_executable_call_argument(tmp_path: Path) -> None:
    positive = _analysis(tmp_path, "import_flow_positive")
    wrong = _analysis(tmp_path, "wrong_target_identity")

    assert _kinds(positive) == _kinds(wrong)
    positive_send = _semantic_ops(positive, "network_send")
    wrong_send = _semantic_ops(wrong, "network_send")
    assert len(positive_send) == len(wrong_send) == 1
    positive_read = _semantic_ops(positive, "file_read")
    wrong_read = _semantic_ops(wrong, "file_read")
    assert len(positive_read) == len(wrong_read) == 1
    assert positive_read[0].target_resource_identity == wrong_read[0].target_resource_identity
    assert positive_read[0].target_resource_identity
    assert positive_send[0].target_resource_identity
    assert wrong_send[0].target_resource_identity
    assert positive_send[0].target_resource_identity != wrong_send[0].target_resource_identity

    positive_flow = tuple(item for item in positive.flow_edges if item.edge_kind == "source_to_sink")
    wrong_flow = tuple(item for item in wrong.flow_edges if item.edge_kind == "source_to_sink")
    assert len(positive_flow) == len(wrong_flow) == 1
    assert positive_flow[0].source_value_id == positive_flow[0].target_value_id
    assert wrong_flow[0].source_value_id == wrong_flow[0].target_value_id

    # The differing authority comes from the recovered machine-code argument,
    # not from the fixture's inert resource marker.
    assert dict(positive_send[0].resolved_arguments)["call_arguments"]["rdi"] == {"constant": 1}
    assert dict(wrong_send[0].resolved_arguments)["call_arguments"]["rdi"] == {"constant": 2}


@pytest.mark.parametrize(
    ("variant", "required", "forbidden"),
    (
        ("wrong_sink", "file_write", "network_send"),
        ("adjacent_import", "network_download", "network_send"),
        ("data_only", "native_return", "network_send"),
    ),
)
def test_phase6_adjacent_semantics_do_not_alias_to_network_send(tmp_path: Path, variant: str, required: str, forbidden: str) -> None:
    analysis = _analysis(tmp_path, variant)
    assert required in _kinds(analysis)
    assert forbidden not in _kinds(analysis)


def test_phase6_required_resource_without_recovered_target_is_partial(tmp_path: Path) -> None:
    analysis = _analysis(tmp_path, "wrong_sink")
    for kind in ("file_read", "file_write"):
        operations = _semantic_ops(analysis, kind)
        assert len(operations) == 1
        assert operations[0].target_resource_identity == ""
        assert operations[0].resolution_state == "partial"
        assert operations[0].integrity_status == "partial"
        assert operations[0].limitations == ("target_unresolved",)


def test_phase6_unresolved_indirect_call_remains_native_and_partial(tmp_path: Path) -> None:
    analysis = _analysis(tmp_path, "unresolved_indirect")
    calls = _semantic_ops(analysis, "native_call")
    assert analysis.parser_status == "partial"
    assert len(calls) == 1
    assert calls[0].resolution_state == "unresolved"
    assert calls[0].limitations == ("indirect_call_target_unresolved",)
    assert not any(key.startswith("resolved_") for key in calls[0].resolved_arguments)


def test_phase6_syscall_number_and_value_flow_are_semantically_resolved(tmp_path: Path) -> None:
    positive = _analysis(tmp_path, "syscall_flow_positive")
    read = _semantic_ops(positive, "file_read")
    send = _semantic_ops(positive, "network_send")
    assert len(read) == len(send) == 1
    assert dict(read[0].resolved_arguments)["resolved_syscall_identity"] == "linux_x86_64:0:read"
    assert dict(send[0].resolved_arguments)["resolved_syscall_identity"] == "linux_x86_64:44:sendto"
    assert read[0].target_resource_identity
    assert send[0].target_resource_identity
    assert read[0].target_resource_identity != send[0].target_resource_identity
    assert read[0].output_value_ids == send[0].input_value_ids
    assert not any(item.operation_kind == "native_syscall" for item in positive.operations)
    addresses = [dict(item.resolved_arguments)["virtual_address"] for item in positive.operations]
    assert len(addresses) == len(set(addresses))
    assert any(item.edge_kind == "source_to_sink" for item in positive.flow_edges)

    adjacent = _analysis(tmp_path, "adjacent_syscall")
    assert {"file_read", "file_write"}.issubset(_kinds(adjacent))
    assert "network_send" not in _kinds(adjacent)
