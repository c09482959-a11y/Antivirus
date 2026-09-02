from pathlib import Path

from Virus_Scan.contracts.telemetry import record_detector_error
from Virus_Scan.runtime import scan_dependencies

MODEL_FILES = (
    *tuple(sorted(Path("Virus_Scan/models/clustering").glob("*.py"))),
    *tuple(sorted(Path("Virus_Scan/models/graph").glob("*.py"))),
    *tuple(sorted(Path("Virus_Scan/models/markov").glob("*.py"))),
    Path("Virus_Scan/models/profiles/api.py"),
    *tuple(sorted(Path("Virus_Scan/models/replay").glob("*.py"))),
    Path("Virus_Scan/models/retention.py"),
    *tuple(sorted(Path("Virus_Scan/models/temporal").glob("*.py"))),
)


def test_models_use_neutral_telemetry_contract_not_scan_dependency_registry() -> None:
    violations = []
    for path in MODEL_FILES:
        source = path.read_text(encoding="utf-8")
        if "Virus_Scan.runtime.scan_dependencies import" in source:
            violations.append(str(path))
    assert violations == []


def test_runtime_scan_dependency_does_not_reexport_neutral_telemetry_contract() -> None:
    source = Path("Virus_Scan/runtime/scan_dependencies.py").read_text(encoding="utf-8")
    assert "from Virus_Scan.contracts.telemetry import log_error" not in source
    assert "from Virus_Scan.contracts.telemetry import record_detector_error" not in source
    assert "log_error" not in getattr(scan_dependencies, "__all__", ())
    assert "record_detector_error" not in getattr(scan_dependencies, "__all__", ())


def test_detector_error_contract_materializes_context_without_runtime_dependency_registry() -> None:
    record = record_detector_error("graph", "boom", context={"b": {"z", "a"}, "a": (1, 2)})
    assert record["detector"] == "graph"
    assert record["error"] == "boom"
    assert record["context"]["a"] == (1, 2)
    assert record["context"]["b"] == ["a", "z"]
    assert "time" in record
