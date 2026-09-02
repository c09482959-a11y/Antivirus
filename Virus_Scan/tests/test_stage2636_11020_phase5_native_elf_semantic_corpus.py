from __future__ import annotations

import struct

from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.static_semantic_binary_fixtures import build_semantic_elf64_x86_64_fixture
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_safety import validate_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import ArtifactRendererSpecification


_REQUIRED_SECTIONS = {
    ".text", ".rodata", ".dynstr", ".dynsym", ".rela.plt",
    ".plt", ".got.plt", ".dynamic", ".shstrtab",
}


def _section_names(data: bytes) -> set[str]:
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    shoff, shentsize, shnum, shstr_index = header[6], header[11], header[12], header[13]
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
    shstr = headers[shstr_index]
    names = data[shstr[4]:shstr[4] + shstr[5]]
    result = set()
    for item in headers[1:]:
        start = item[0]
        end = names.find(b"\x00", start)
        result.add(names[start:end].decode("ascii", "strict"))
    return result


def _truth(variant: str):
    sample_id = "phase5-" + variant
    specification = ArtifactRendererSpecification(
        renderer_kind="native_elf_x86_64", extension=".elf", member_extension="",
        language="native_x86_64", platform="Linux",
        source_text="Deterministic inert Phase-5 native semantic challenge; never executed.\n",
        fixture_variant=variant,
    )
    data = render_static_semantic_artifact(sample_id, specification)
    safety = validate_static_semantic_artifact(
        sample_id, data, renderer_kind=specification.renderer_kind,
        fixture_variant=specification.fixture_variant,
    )
    assert safety.safe is True, safety.reasons
    truth = derive_artifact_evidence_truth(sample_id, sample_id + ".elf", data)
    validation = validate_artifact_evidence_truth(sample_id, sample_id + ".elf", data, truth, ())
    assert validation["agreement"] is True, validation["errors"]
    return data, truth


def test_phase5_positive_fixture_has_real_dynamic_elf_structure_and_independent_truth() -> None:
    data, truth = _truth("import_flow_positive")
    assert _REQUIRED_SECTIONS.issubset(_section_names(data))
    assert truth.parser_status == "complete"
    assert {"read", "send"}.issubset(truth.resolved_import_identities)
    assert {"read@plt", "send@plt"}.issubset(truth.resolved_call_identities)
    assert {"file_read", "network_send", "native_return"}.issubset(truth.operation_kinds)
    assert {(item.source_operation_kind, item.sink_operation_kind, item.connected) for item in truth.flow} == {
        ("file_read", "network_send", True),
    }


def test_phase5_same_symbols_without_calls_have_no_semantic_operation_authority() -> None:
    _data, truth = _truth("symbols_no_calls")
    assert {"read", "send"}.issubset(truth.resolved_import_identities)
    assert not truth.resolved_call_identities
    assert "file_read" not in truth.operation_kinds
    assert "network_send" not in truth.operation_kinds
    assert not truth.flow


def test_phase5_same_calls_after_return_are_unreachable() -> None:
    _data, truth = _truth("calls_unreachable")
    states = {(item.operation_kind, item.reachability_state): item.minimum_count for item in truth.reachability}
    assert states[("file_read", "unreachable")] == 1
    assert states[("network_send", "unreachable")] == 1
    assert not truth.flow


def test_phase5_same_operations_with_wrong_target_identity_remain_physically_distinguishable() -> None:
    _positive_data, positive = _truth("import_flow_positive")
    _wrong_data, wrong = _truth("wrong_target_identity")
    assert positive.operation_kinds == wrong.operation_kinds
    assert positive.flow == wrong.flow
    assert "resource:channel:primary" in positive.resource_identities
    assert "resource:channel:secondary" in wrong.resource_identities
    assert set(positive.resource_identities) != set(wrong.resource_identities)


def test_phase5_source_and_sink_without_value_transfer_are_disconnected() -> None:
    _data, truth = _truth("no_value_flow")
    assert {"file_read", "network_send"}.issubset(truth.operation_kinds)
    assert {(item.source_operation_kind, item.sink_operation_kind, item.connected) for item in truth.flow} == {
        ("file_read", "network_send", False),
    }


def test_phase5_wrong_sink_and_adjacent_import_do_not_become_network_send() -> None:
    _wrong_data, wrong = _truth("wrong_sink")
    assert {"file_read", "file_write"}.issubset(wrong.operation_kinds)
    assert "network_send" not in wrong.operation_kinds
    _adjacent_data, adjacent = _truth("adjacent_import")
    assert {"file_read", "network_download"}.issubset(adjacent.operation_kinds)
    assert "network_send" not in adjacent.operation_kinds


def test_phase5_documentation_data_only_has_no_import_or_call_authority() -> None:
    data, truth = _truth("data_only")
    assert b"read\x00send\x00documentation-only\x00" in data
    assert not truth.resolved_import_identities
    assert not truth.resolved_call_identities
    assert "file_read" not in truth.operation_kinds
    assert "network_send" not in truth.operation_kinds


def test_phase5_unresolved_indirect_call_is_partial_not_invented_semantics() -> None:
    _data, truth = _truth("unresolved_indirect")
    assert truth.parser_status == "partial"
    assert truth.evidence_completeness == "partial"
    assert "native_call" in truth.operation_kinds
    assert "unresolved_indirect_native_call" in truth.analysis_limitations
    assert not truth.resolved_call_identities


def test_phase5_syscall_positive_and_adjacent_control_are_number_resolved() -> None:
    _positive_data, positive = _truth("syscall_flow_positive")
    assert {"linux_x86_64:0:read", "linux_x86_64:44:sendto"}.issubset(positive.resolved_syscall_identities)
    assert {"file_read", "network_send"}.issubset(positive.operation_kinds)
    assert positive.flow[0].connected is True

    _control_data, control = _truth("adjacent_syscall")
    assert {"linux_x86_64:0:read", "linux_x86_64:1:write"}.issubset(control.resolved_syscall_identities)
    assert {"file_read", "file_write"}.issubset(control.operation_kinds)
    assert "network_send" not in control.operation_kinds
    assert not control.flow


def test_phase5_fixture_bytes_are_deterministic_and_identity_bound() -> None:
    first = build_semantic_elf64_x86_64_fixture("import_flow_positive", identity_marker="UMIGE_STATIC_SEMANTIC:phase5-a")
    second = build_semantic_elf64_x86_64_fixture("import_flow_positive", identity_marker="UMIGE_STATIC_SEMANTIC:phase5-a")
    changed = build_semantic_elf64_x86_64_fixture("import_flow_positive", identity_marker="UMIGE_STATIC_SEMANTIC:phase5-b")
    assert first == second
    assert first != changed
