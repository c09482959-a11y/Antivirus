from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file, wildcard_import_findings

from pathlib import Path
from Virus_Scan.models.api import graph_contracts
import Virus_Scan.models.profiles as profiles

_MODEL_SCOPE_ROOTS = (
    "Virus_Scan/models",
    "Virus_Scan/runtime",
    "Virus_Scan/detection/models",
    "Virus_Scan/detection/scoring",
    "Virus_Scan/detection/profiles",
    "Virus_Scan/detection/enrichment",
    "Virus_Scan/detection/contracts",
    "Virus_Scan/publication",
)


def _model_scope_python_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for root in _MODEL_SCOPE_ROOTS:
        files.extend(python_files_under(root))
    return tuple(files)


def test_stage1447_model_scope_has_no_wildcard_imports() -> None:
    offenders = [
        finding
        for path in _model_scope_python_files()
        for finding in wildcard_import_findings(path)
    ]
    assert offenders == []


def test_stage1447_repository_python_has_no_wildcard_imports() -> None:
    offenders = [
        finding
        for path in python_files_under("Virus_Scan")
        for finding in wildcard_import_findings(path)
    ]
    assert offenders == []


def test_stage1447_graph_scan_regex_tags_are_real_not_empty_stub(tmp_path: Path) -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/scan.py"))
    assert "patterns = {}" not in source
    assert "_CS_GRAPH_REGEX_TAGS" in source

    sample = tmp_path / "Sample.cs"
    sample.write_text(
        "using System.Diagnostics; class A { void B() { Process.Start(\"cmd.exe\"); "
        "new WebClient().DownloadString(url); } }",
        encoding="utf-8",
    )

    tags = graph_contracts.scan_cs(sample)

    assert "process_exec" in tags
    assert "network_download" in tags
    assert tags == sorted(tags)


def test_stage1447_profile_package_exports_are_explicit_not_api_star_namespace() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/__init__.py"))
    assert "import *" not in source
    assert hasattr(profiles, "canonical_profile_learning_flow")
    assert hasattr(profiles, "profile_behavior_bucket_validation")
    assert not hasattr(profiles, "copy")
    assert not hasattr(profiles, "os")
