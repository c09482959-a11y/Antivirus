from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.contracts import binary_predicates
from Virus_Scan.detection.contracts.string_predicates import behavior_text_bits
from Virus_Scan.utils.entropy import strict_fast_entropy


class _BadPathString:
    def __str__(self) -> str:
        raise OSError("path stringify failed")


def test_stage1211_binary_predicates_do_not_define_duplicate_entropy_owner() -> None:
    source_path = Path(binary_predicates.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "strict_fast_entropy" not in function_names
    assert "strict_fast_entropy" not in binary_predicates.__all__
    assert not hasattr(binary_predicates, "_strict_fast_entropy")
    assert binary_predicates.strict_fast_entropy is strict_fast_entropy


def test_stage1211_binary_predicate_callers_use_canonical_entropy_owner() -> None:
    prefilter = read_python_file(Path("Virus_Scan/detection/enrichment/prefilter/scan.py"))
    il2cpp = read_python_file(Path("Virus_Scan/detection/enrichment/pe_analysis/il2cpp_static.py"))

    assert "Virus_Scan.utils.entropy import strict_fast_entropy" in prefilter
    assert "Virus_Scan.utils.entropy import strict_fast_entropy" in il2cpp
    assert "detection.contracts.binary_predicates import strict_fast_entropy" not in prefilter
    assert "detection.contracts.binary_predicates import strict_fast_entropy" not in il2cpp


def test_stage1211_binary_predicates_preserve_boring_text_behavior(tmp_path: Path) -> None:
    benign = tmp_path / "notes.txt"
    benign.write_text("plain configuration notes\n" * 32, encoding="utf-8")

    is_boring, meta = binary_predicates.strict_fast_file_is_boring_text(benign)

    assert is_boring is True
    assert meta["extension"] == ".txt"
    assert meta["entropy"] < 5.2


def test_stage1211_string_predicate_error_contract_is_imported_for_recoverable_paths() -> None:
    text, compact, name, ext = behavior_text_bits("safe text", _BadPathString())

    assert text == "safe text"
    assert compact == "safe text"
    assert name == ""
    assert ext == ""
