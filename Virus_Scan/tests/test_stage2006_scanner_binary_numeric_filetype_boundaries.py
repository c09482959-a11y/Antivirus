"""Stage 2006 scanner numeric/filetype boundary regressions."""
from __future__ import annotations

from pathlib import Path
import ast

import pytest

from Virus_Scan.scanners.binary_behavior_filetype_model import (
    FiletypeBucketModelRequest,
    filetype_bucket_model_signal,
)
from Virus_Scan.scanners.binary_behavior_semantics import (
    EffectiveEvidenceScoreRequest,
    tag_effective_evidence_score,
)
from Virus_Scan.scanners.binary_entropy_helpers import entropy_from_counts, shannon_entropy_bytes
from Virus_Scan.scanners.ci.archive_boundary_audit import _function_length
from Virus_Scan.scanners.entropy import byte_entropy, tag_entropy
from Virus_Scan.scanners.binary_failover_evidence import append_binary_failover_evidence
from Virus_Scan.scanners.binary_graph_context import binary_node_edge_status
from Virus_Scan.scanners.binary_numeric import safe_clamp, scanner_clamped_ratio
from Virus_Scan.scanners.binary_pe_bytes import pe_cstr, pe_u16
from Virus_Scan.scanners.binary_pe_evidence import mark_pe_helper_error


class HostileScalar:
    __slots__ = ("calls",)

    def __init__(self, calls: list[str]) -> None:
        object.__setattr__(self, "calls", calls)

    def __getattribute__(self, name: str):
        if name == "calls":
            return object.__getattribute__(self, name)
        object.__getattribute__(self, "calls").append("__getattribute__")
        raise AssertionError("caller-owned attribute hook executed")

    def __str__(self) -> str:
        self.calls.append("__str__")
        raise AssertionError("caller-owned str hook executed")

    def __repr__(self) -> str:
        self.calls.append("__repr__")
        raise AssertionError("caller-owned repr hook executed")

    def __format__(self, spec: str) -> str:
        self.calls.append("__format__")
        raise AssertionError("caller-owned format hook executed")

    def __bool__(self) -> bool:
        self.calls.append("__bool__")
        raise AssertionError("caller-owned bool hook executed")

    def __float__(self) -> float:
        self.calls.append("__float__")
        raise AssertionError("caller-owned float hook executed")

    def __int__(self) -> int:
        self.calls.append("__int__")
        raise AssertionError("caller-owned int hook executed")

    def __iter__(self):
        self.calls.append("__iter__")
        raise AssertionError("caller-owned iter hook executed")

    def __eq__(self, other: object) -> bool:
        self.calls.append("__eq__")
        raise AssertionError("caller-owned equality hook executed")


class PlainGraphNode:
    pass




class HostileAstNode(ast.AST):
    __slots__ = ("calls",)

    def __init__(self, calls: list[str]) -> None:
        object.__setattr__(self, "calls", calls)

    def __getattribute__(self, name: str):
        if name == "calls":
            return object.__getattribute__(self, name)
        object.__getattribute__(self, "calls").append("__getattribute__")
        raise AssertionError("caller-owned AST attribute hook executed")


class HostileGraphAccessor:
    __slots__ = ("calls",)

    def __init__(self, calls: list[str]) -> None:
        object.__setattr__(self, "calls", calls)

    def __getattribute__(self, name: str):
        if name == "calls":
            return object.__getattribute__(self, name)
        object.__getattribute__(self, "calls").append("__getattribute__")
        raise AssertionError("caller-owned graph attribute hook executed")

    def edges(self):
        self.calls.append("edges")
        raise AssertionError("caller-owned graph accessor executed")


def test_scanner_numeric_rejects_hostile_scalar_without_hooked_error_text():
    value_calls: list[str] = []
    field_calls: list[str] = []

    with pytest.raises(TypeError) as excinfo:
        safe_clamp(HostileScalar(value_calls), field=HostileScalar(field_calls))

    assert str(excinfo.value) == "unsupported scanner numeric object: value"
    assert value_calls == []
    assert field_calls == []


def test_scanner_ratio_uses_owned_denominator_policy():
    assert scanner_clamped_ratio(3.0, 6, field="score") == 0.5
    assert scanner_clamped_ratio(3.0, 0, field="score") == 1.0

    calls: list[str] = []
    with pytest.raises(TypeError):
        scanner_clamped_ratio(1.0, HostileScalar(calls), field="score")
    assert calls == []


def test_scanner_entropy_helpers_reject_hostile_numeric_inputs_without_hooks():
    assert shannon_entropy_bytes(None) == 0.0
    assert round(entropy_from_counts([1, 1], 2), 6) == 1.0

    value_calls: list[str] = []
    with pytest.raises(TypeError):
        entropy_from_counts([HostileScalar(value_calls)], 1)
    assert value_calls == []

    counts_calls: list[str] = []
    with pytest.raises(TypeError):
        entropy_from_counts(HostileScalar(counts_calls), 1)  # type: ignore[arg-type]
    assert counts_calls == []

    bytes_calls: list[str] = []
    with pytest.raises(TypeError):
        shannon_entropy_bytes(HostileScalar(bytes_calls))  # type: ignore[arg-type]
    assert bytes_calls == []


def test_scanner_behavior_filetype_and_semantics_reject_hostile_tags_without_hooks(tmp_path):
    calls: list[str] = []
    hostile = HostileScalar(calls)
    sample = tmp_path / "asset.png"
    sample.write_bytes(b"not-relevant")

    result = filetype_bucket_model_signal(FiletypeBucketModelRequest(
        "media",
        str(sample),
        ["process_exec", hostile],
        strings_blob="CreateProcess http://example.invalid",
    ))
    score = tag_effective_evidence_score(EffectiveEvidenceScoreRequest(str(sample), hostile))

    assert isinstance(result["filetype_anomaly"], float)
    assert any(record["tag"] == "tag_normalization_failure_evidence" for record in result["records"])
    assert score["reason"] == "unsafe_behavior_tag_rejected"
    assert score["failure_evidence_recorded"] is True
    assert calls == []


def test_binary_failover_evidence_owns_category_and_final_tag_membership():
    calls: list[str] = []
    final_tags = [HostileScalar(calls), "existing"]

    evidence_tags = append_binary_failover_evidence(
        final_tags,
        HostileScalar(calls),  # type: ignore[arg-type]
        "boom",
        ["base", HostileScalar(calls)],  # type: ignore[list-item]
        state=HostileScalar(calls),  # type: ignore[arg-type]
    )

    assert "unsafe_binary_failover_category_rejected_scan_error" in evidence_tags
    assert "scanner_failure_evidence:binary:unsafe_binary_failover_category_rejected" in evidence_tags
    assert "binary_failover_final_json_must_record" in evidence_tags
    final_text_tags = {tag for tag in final_tags if type(tag) is str}
    assert "unsafe_binary_failover_category_rejected_scan_error" in final_text_tags
    assert calls == []


def test_binary_graph_context_rejects_class_accessors_without_getattr_hooks():
    node = PlainGraphNode()
    node.edges = ["edge"]
    assert binary_node_edge_status(node) == ("present", True)

    calls: list[str] = []
    assert binary_node_edge_status(HostileGraphAccessor(calls)) == ("probe_error", False)
    assert calls == []


def test_pe_byte_helpers_reject_hostile_offsets_without_numeric_hooks():
    calls: list[str] = []

    with pytest.raises(ValueError, match="PE C-string offset rejected"):
        pe_cstr(b"abc", HostileScalar(calls))  # type: ignore[arg-type]
    assert calls == []

    with pytest.raises(ValueError, match="PE read offset rejected"):
        pe_u16(b"abc", HostileScalar(calls))  # type: ignore[arg-type]
    assert calls == []


def test_pe_helper_evidence_rejects_hostile_helper_name_without_text_hooks():
    calls: list[str] = []
    tags = mark_pe_helper_error(HostileScalar(calls), ValueError("bad pe"))  # type: ignore[arg-type]

    assert "pe_helper_unsupported_scan_error" in tags
    assert "scanner_failure_evidence:binary:pe_helper_unsupported" in tags
    assert calls == []




def test_scanner_entropy_public_boundary_rejects_hostile_tags_and_bytes_without_hooks():
    assert tag_entropy(None) == 0.0
    assert tag_entropy(["a", "b", "a"]) == pytest.approx(0.9182958311690995)

    tag_calls: list[str] = []
    assert tag_entropy(HostileScalar(tag_calls)) == 0.0  # type: ignore[arg-type]
    assert tag_calls == []

    item_calls: list[str] = []
    assert tag_entropy(["safe", HostileScalar(item_calls)]) == 0.0
    assert item_calls == []

    byte_calls: list[str] = []
    with pytest.raises(TypeError):
        byte_entropy(HostileScalar(byte_calls))  # type: ignore[arg-type]
    assert byte_calls == []


def test_archive_boundary_function_length_rejects_hostile_ast_without_getattr_or_int_hooks():
    node = ast.parse("async def sample():\n    return 1\n").body[0]
    assert _function_length(node) == 2

    calls: list[str] = []
    assert _function_length(HostileAstNode(calls)) == 0
    assert calls == []


def test_scanner_numeric_filetype_source_no_longer_contains_repaired_backlog_snippets():
    forbidden_by_path = {
        "Virus_Scan/scanners/binary_behavior_filetype_model.py": [
            '"filetype_anomaly": safe_clamp(score / max(1, len(tag_list))),',
        ],
        "Virus_Scan/scanners/binary_behavior_semantics.py": [
            '"risk": safe_clamp(risk_raw / 10.0),',
            '"confidence": safe_clamp(confidence),',
        ],
        "Virus_Scan/scanners/binary_numeric.py": [
            'raise TypeError(f"unsupported scanner numeric boolean: {field}")',
            'raise TypeError(f"unsupported scanner numeric object: {field}")',
        ],
        "Virus_Scan/scanners/binary_entropy_helpers.py": [
            "for count in counts.values():",
            "total_f = float(total or 0)",
            "count_f = float(count or 0)",
        ],
        "Virus_Scan/scanners/entropy.py": [
            "if not tags:",
            "for c in counts.values():",
            "if not data:",
            "for count in counts.values():",
        ],
        "Virus_Scan/scanners/ci/archive_boundary_audit.py": [
            'end = int(getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0)',
            'start = int(getattr(node, "lineno", end) or end)',
            'str(scanner_archive_file.relative_to(root))',
            'f"{node.name}:{_function_length(node)}"',
        ],
        "Virus_Scan/scanners/binary_failover_evidence.py": [
            "error_category=f'binary_{category}',",
            "if isinstance(final_tags, list):",
        ],
        "Virus_Scan/scanners/binary_filetype.py": [
            'return f"{engine_text}:{normalize_binary_profile_extension(file_path)}"',
            "for bucket, info in ENGINE_SPECIFIC_FILETYPE_BUCKETS.get(engine, {}).items():",
            "for bucket, info in GLOBAL_COMMON_FILETYPE_BUCKETS.items():",
        ],
        "Virus_Scan/scanners/binary_graph_context.py": [
            "value = getattr(node, name, None)",
        ],
        "Virus_Scan/scanners/binary_io.py": [
            'lowered = f" {text.lower()} "',
        ],
        "Virus_Scan/scanners/binary_micro_stage.py": [
            'missing_reason=f"missing_micro_stage_{field}",',
            'unsupported_reason=f"unsafe_micro_stage_{field}_rejected",',
            'return "", f"missing_micro_stage_{field}"',
            'return "", f"micro_stage_{field}_decode_failed"',
            'return "", f"micro_stage_{field}_path_text_failed"',
            'return "", f"unsafe_micro_stage_{field}_rejected"',
            'stage = f"micro_stage_{kind_text}" if kind_text else "micro_stage_unsupported"',
            'f"micro_stage_{kind_text}",',
            "isinstance(value, PurePath)",
        ],
        "Virus_Scan/scanners/binary_pe_bytes.py": [
            'raise ValueError(f"invalid PE C-string offset {off}")',
            'raise ValueError(f"truncated PE {field} read at offset {off}")',
        ],
        "Virus_Scan/scanners/binary_pe_dotnet.py": [
            'binary_log_message(f"extract_dotnet_metadata failed: {exc}")',
            'f"unsupported PE optional header magic {magic}"',
        ],
        "Virus_Scan/scanners/binary_pe_evidence.py": [
            'binary_log_message(f"{helper_name} failed: {exc}")',
            '[f"{helper_name}_scan_error"]',
            'f"scanner_failure_evidence:binary:{helper_name}"',
        ],
        "Virus_Scan/scanners/binary_pe_surface.py": [
            "for needle, mapped in PE_API_TAGS.items():",
        ],
        "Virus_Scan/scanners/binary_runtime_evidence.py": [
            'return default, f"{field}_missing"',
            'return default, f"{field}_rejected"',
        ],
    }
    for path, snippets in forbidden_by_path.items():
        source = Path(path).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source
