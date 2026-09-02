from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners.archives.path_safety import safe_archive_child_path_with_reason
from Virus_Scan.scanners.archives.publication_requests import (
    _safe_tag_text_with_reason,
    archive_graph_publication_edges,
)


class HostileValue:
    def __str__(self) -> str:  # pragma: no cover - must never execute
        raise AssertionError("__str__ hook executed")

    def __repr__(self) -> str:  # pragma: no cover - must never execute
        raise AssertionError("__repr__ hook executed")

    def __format__(self, _format_spec: str) -> str:  # pragma: no cover - must never execute
        raise AssertionError("__format__ hook executed")

    def __bool__(self) -> bool:  # pragma: no cover - must never execute
        raise AssertionError("__bool__ hook executed")

    def __iter__(self):  # pragma: no cover - must never execute
        raise AssertionError("__iter__ hook executed")

    def __fspath__(self) -> str:  # pragma: no cover - must never execute
        raise AssertionError("__fspath__ hook executed")

    def __getattribute__(self, name: str):  # pragma: no cover - must never execute
        if name.startswith("__") and name.endswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError("__getattribute__ hook executed")


def test_archive_path_rejects_hostile_root_and_member_without_hooks(tmp_path: Path) -> None:
    hostile = HostileValue()

    root_path, root_reason = safe_archive_child_path_with_reason(hostile, "member.txt")
    member_path, member_reason = safe_archive_child_path_with_reason(tmp_path, hostile)

    assert root_path is None
    assert root_reason == "unsafe_archive_root_rejected:HostileValue"
    assert member_path is None
    assert member_reason == "unsafe_archive_member_name_rejected:HostileValue"


def test_archive_publication_text_and_edges_reject_hostile_values_without_hooks() -> None:
    hostile = HostileValue()

    text, reason = _safe_tag_text_with_reason(
        hostile,
        missing_reason="missing_stage1988_text",
        unsupported_reason="unsafe_stage1988_text_rejected",
    )
    edges = archive_graph_publication_edges(edge_requests=hostile)

    assert text == "unsafe_stage1988_text_rejected:HostileValue"
    assert reason == "unsafe_stage1988_text_rejected"
    assert edges == (("archive_graph_edge_requests_rejected", "HostileValue", "archive_graph_input_rejected", 0.0),)


def test_stage1988_archive_sources_do_not_reintroduce_repaired_hook_patterns() -> None:
    root = Path(__file__).resolve().parents[2]
    forbidden_by_file = {
        "Virus_Scan/scanners/archives/member_scan.py": (
            'f"archive_member_ext:',
            "str(path).lower()",
        ),
        "Virus_Scan/scanners/archives/path_safety.py": (
            "isinstance(root, str)",
            "isinstance(member_name, str)",
            'f"unsafe_archive_root_rejected',
            'f"unsafe_archive_member_name_rejected',
        ),
        "Virus_Scan/scanners/archives/payload_no_hook.py": (
            "record.get(",
            'f"archive_member_payload_',
        ),
        "Virus_Scan/scanners/archives/publication_requests.py": (
            'f"{reason}:',
            'f"archive_graph_edge_request_',
            'missing_reason=f"missing_archive_graph_',
            'unsupported_reason=f"unsafe_archive_graph_',
            'f"archive_graph_publication_edge_count:',
            'f"archive_graph_publication_parent:',
            'f"archive_graph_publication_member_name:',
            'f"archive_graph_publication_edge_type:',
            "isinstance(limit, bool)",
        ),
        "Virus_Scan/scanners/archives/rpa.py": (
            'log_error(f"rpa',
            'log_error(f"scan_rpa_file',
        ),
        "Virus_Scan/scanners/archives/rpa_member_behavior.py": (
            'error_source=f"archives.rpa_member_behavior',
        ),
        "Virus_Scan/scanners/archives/scanner.py": (
            "= int(max_depth_value",
            "= int(max_members_value",
            "= int(max_member_size_value",
            'f"malformed_',
            'reason=f"unsupported or malformed archive',
        ),
        "Virus_Scan/scanners/archives/tar_scanner.py": (
            "getattr(member",
            'f"unsupported tar member type',
            'f"archive_inner:',
            'f"archive_member:',
            'f"tag:',
            "member.name",
        ),
        "Virus_Scan/scanners/archives/zip_scanner.py": (
            "getattr(info",
            "member.filename",
            'f"archive_inner:',
            'f"archive_member:',
            'f"tag:',
        ),
    }
    for relative_path, patterns in forbidden_by_file.items():
        source = (root / relative_path).read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern not in source, f"{relative_path} still contains {pattern}"
