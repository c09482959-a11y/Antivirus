from Virus_Scan.reporting import compact
from Virus_Scan.reporting import evidence_lines


def test_stage1072_reporting_compact_exports_public_helpers_only():
    assert compact.__all__ == (
        "cli_human_evidence_lines",
        "display_tags_for_result",
        "print_compact_scan_report",
    )
    assert not hasattr(compact, "_display_tags_for_result")
    assert not hasattr(compact, "_cli_human_evidence_lines")
    result = {"tags": ["file_seen", "cmd_exec", "encoded_powershell", "ext_py"]}
    assert compact.display_tags_for_result(result, 24.99) == []
    assert compact.display_tags_for_result(result, 25.0) == ["cmd_exec", "encoded_powershell"]


def test_stage1072_evidence_lines_public_export_is_canonical(tmp_path):
    sample = tmp_path / "payload.ps1"
    sample.write_text("powershell -enc AAAA", encoding="utf-8")
    result = {"tags": ["powershell_exec", "encoded_powershell"]}
    assert evidence_lines.__all__ == ("cli_human_evidence_lines",)
    assert not hasattr(evidence_lines, "_cli_human_evidence_lines")
    lines = evidence_lines.cli_human_evidence_lines(sample, result, max_lines=4)
    assert any(line.startswith("Script:") or line.startswith("PowerShell:") for line in lines)
