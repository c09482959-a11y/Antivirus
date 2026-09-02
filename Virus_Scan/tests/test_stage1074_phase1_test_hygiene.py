from Virus_Scan.tests.support.static_inventory import literal_placeholder_assertion_findings, local_import_and_dynamic_import_findings, repository_python_files, top_level_test_files

from pathlib import Path



def _python_files() -> tuple[Path, ...]:
    return repository_python_files()


def test_stage1074_repository_has_no_function_local_or_dynamic_imports() -> None:
    findings: list[str] = []
    for path in _python_files():
        findings.extend(local_import_and_dynamic_import_findings(path))
    assert findings == []


def test_stage1074_repository_tests_have_no_literal_placeholder_assertions() -> None:
    findings: list[str] = []
    for path in top_level_test_files():
        findings.extend(literal_placeholder_assertion_findings(path))
    assert findings == []
