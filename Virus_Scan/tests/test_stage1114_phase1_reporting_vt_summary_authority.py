import ast
from pathlib import Path


def _function_names(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_stage1114_publication_virustotal_summary_is_canonical_summary_owner():
    owner = _function_names("Virus_Scan/publication/virustotal_summary.py")
    assert "build_virustotal_findings_summary" in owner
    assert "render_virustotal_publication" in owner
    generic = _function_names("Virus_Scan/reporting/summary.py")
    assert "vt_print_summary" not in generic
    assert "vt_engine_total_from_summary" not in generic


def test_stage1114_virustotal_runtime_has_no_direct_print_summary_owner():
    source = Path("Virus_Scan/virustotal/reporting.py").read_text(encoding="utf-8")
    assert "vt_print_summary" not in source
    assert "print(" not in source
    assert "emit_parent_scan_log_event" in source
