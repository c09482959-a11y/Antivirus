from pathlib import Path

from Virus_Scan.runtime.resource_paths import resource_root_snapshot_from_program_root
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.virustotal.control_files import ensure_generated_controls
from Virus_Scan.virustotal.reporting import run_virustotal_reporting
from Virus_Scan.virustotal.runtime import initialize_virustotal_runtime


def _record_wheres() -> set[object]:
    return {record.get("where") for record in failure_snapshot().get("records", [])}


def test_virustotal_invalid_toml_records_publication_evidence(tmp_path: Path) -> None:
    clear_failure_records()
    roots = resource_root_snapshot_from_program_root(tmp_path)
    config_path = ensure_generated_controls(Path(roots.virustotal_root))["config"]
    config_path.write_text("enabled = [", encoding="utf-8")
    runtime = initialize_virustotal_runtime(roots)
    result = run_virustotal_reporting({}, runtime)
    assert result.status == "configuration_invalid"
    assert "virustotal_configuration_invalid" in _record_wheres()


def test_virustotal_unknown_config_field_records_publication_evidence(tmp_path: Path) -> None:
    clear_failure_records()
    roots = resource_root_snapshot_from_program_root(tmp_path)
    config_path = ensure_generated_controls(Path(roots.virustotal_root))["config"]
    config_path.write_text('config_version = "virustotal_config_v2"\nunknown = true\n', encoding="utf-8")
    runtime = initialize_virustotal_runtime(roots)
    result = run_virustotal_reporting({}, runtime)
    assert result.status == "configuration_invalid"
    assert "virustotal_configuration_invalid" in _record_wheres()
