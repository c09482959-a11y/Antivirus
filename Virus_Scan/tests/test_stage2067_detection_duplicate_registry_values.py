from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.tests.support.static_inventory import parse_python_file


_DETECTION_DUPLICATE_VALUE_FILES = (
    Path("Virus_Scan/detection/chains/composite/behavior_intent.py"),
    Path("Virus_Scan/detection/chains/execution/anchors.py"),
    Path("Virus_Scan/detection/registries/chain_gate_registry_defaults.py"),
    Path("Virus_Scan/detection/registries/runtime_profile_registry_defaults.py"),
    Path("Virus_Scan/detection/scoring/registries/scoring_registry_defaults.py"),
    Path("Virus_Scan/detection/scoring/weighting/prefilter_risk.py"),
)


def _duplicate_string_set_literals(path: Path) -> tuple[tuple[str, int, str], ...]:
    findings: list[tuple[str, int, str]] = []
    for node in ast.walk(parse_python_file(path)):
        if not isinstance(node, ast.Set):
            continue
        values = tuple(
            element.value
            for element in node.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        )
        seen: set[str] = set()
        duplicates: set[str] = set()
        for value in values:
            if value in seen:
                duplicates.add(value)
            seen.add(value)
        for duplicate in sorted(duplicates):
            findings.append((str(path), node.lineno, duplicate))
    return tuple(findings)


def test_stage2067_detection_duplicate_registry_values_are_removed() -> None:
    findings = tuple(
        finding
        for path in _DETECTION_DUPLICATE_VALUE_FILES
        for finding in _duplicate_string_set_literals(path)
    )

    assert findings == ()
