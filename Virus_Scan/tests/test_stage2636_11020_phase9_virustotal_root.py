from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from Virus_Scan.core import jsonio
from Virus_Scan.cli.args import build_parser
from Virus_Scan.runtime.resource_paths import resource_root_snapshot_from_program_root
from Virus_Scan.virustotal.client import (
    VIRUSTOTAL_ANALYSIS_PREFIX,
    VIRUSTOTAL_API_HOST,
    VIRUSTOTAL_UPLOAD_URL,
    VirusTotalClient,
)
from Virus_Scan.virustotal.config import (
    VIRUSTOTAL_CONFIG_VERSION,
    VirusTotalConfig,
    config_schema_json,
    config_toml,
    load_config,
)
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.virustotal.control_files import ensure_generated_controls, prepare_package_controls
from Virus_Scan.virustotal.reporting import run_virustotal_reporting
from Virus_Scan.virustotal.runtime import VirusTotalRuntimeSnapshot, initialize_virustotal_runtime


class _HostilePath:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("hostile path string hook executed")

    def __fspath__(self):
        type(self).touched += 1
        raise AssertionError("hostile path fspath hook executed")


def _roots(tmp_path: Path):
    return resource_root_snapshot_from_program_root(tmp_path)


def test_phase9_controls_are_exact_four_and_preserve_editable_config(tmp_path: Path) -> None:
    paths = ensure_generated_controls(tmp_path)
    assert set(paths) == {"config", "defaults", "schema", "readme"}
    edited = config_toml(VirusTotalConfig(enabled=True, print_to_cli=False))
    paths["config"].write_text(edited, encoding="utf-8")
    paths["defaults"].write_text("damaged", encoding="utf-8")
    prepare_package_controls(tmp_path)
    assert paths["config"].read_text(encoding="utf-8") == edited
    assert paths["defaults"].read_text(encoding="utf-8") == config_toml()
    assert paths["schema"].read_text(encoding="utf-8") == config_schema_json()


def test_phase9_default_root_config_loads_automatically_disabled_without_network_or_credentials(tmp_path: Path) -> None:
    runtime = initialize_virustotal_runtime(_roots(tmp_path))
    assert type(runtime) is VirusTotalRuntimeSnapshot
    assert runtime.status == "disabled"
    assert runtime.config is not None and runtime.config.enabled is False
    assert runtime.network_checked is False
    assert runtime.credentials_checked is False
    assert runtime.client is None
    result = run_virustotal_reporting({}, runtime)
    assert type(result) is VirusTotalReportingResult
    assert result.status == "disabled"
    assert result.local_result_mutated is False


def test_phase9_invalid_canonical_config_is_explicit_and_does_not_probe_or_submit(tmp_path: Path) -> None:
    roots = _roots(tmp_path)
    controls = ensure_generated_controls(Path(roots.virustotal_root))
    controls["config"].write_text('config_version = "wrong"\n', encoding="utf-8")
    runtime = initialize_virustotal_runtime(roots)
    assert runtime.status == "configuration_invalid"
    assert runtime.network_checked is False
    assert runtime.credentials_checked is False
    assert runtime.client is None
    result = run_virustotal_reporting({}, runtime)
    assert result.status == "configuration_invalid"
    assert result.config_path == controls["config"].as_posix()
    assert result.api_key_environment_variable == ""
    assert result.submitted_count == 0


def test_phase9_enabled_runtime_states_are_exact_immutable_contracts(tmp_path: Path) -> None:
    controls = ensure_generated_controls(tmp_path)
    enabled_text = config_toml(VirusTotalConfig(enabled=True))
    controls["config"].write_text(enabled_text, encoding="utf-8")
    config = load_config(controls["config"])

    offline = VirusTotalRuntimeSnapshot(
        status="network_unavailable",
        config_path=controls["config"].as_posix(),
        config=config,
        network_checked=True,
        credentials_checked=False,
    )
    assert offline.client is None
    assert controls["config"].read_text(encoding="utf-8") == enabled_text
    offline_result = run_virustotal_reporting({}, offline)
    assert offline_result.status == "network_unavailable"
    assert offline_result.submitted_count == 0
    assert offline_result.local_result_mutated is False

    unconfigured = VirusTotalRuntimeSnapshot(
        status="unconfigured",
        config_path=controls["config"].as_posix(),
        config=config,
        network_checked=True,
        credentials_checked=True,
    )
    assert unconfigured.client is None
    unconfigured_result = run_virustotal_reporting({}, unconfigured)
    assert unconfigured_result.status == "unconfigured"
    assert unconfigured_result.submitted_count == 0

    client = VirusTotalClient(config=config, api_key="phase9-test-secret")
    enabled = VirusTotalRuntimeSnapshot(
        status="enabled",
        config_path=controls["config"].as_posix(),
        config=config,
        network_checked=True,
        credentials_checked=True,
        client=client,
    )
    assert enabled.client is client
    assert "phase9-test-secret" not in repr(enabled)
    assert "phase9-test-secret" not in repr(client)
    enabled_result = run_virustotal_reporting({}, enabled)
    assert enabled_result.status == "no_eligible_files"
    assert enabled_result.submitted_count == 0
    assert enabled_result.local_result_mutated is False


def test_phase9_config_rejects_hostile_path_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0
    with pytest.raises(ValueError, match="virustotal_config_file_invalid"):
        load_config(hostile)  # type: ignore[arg-type]
    assert _HostilePath.touched == 0


def test_phase9_configuration_contains_no_secret_endpoint_or_connectivity_bypass_owner() -> None:
    text = config_toml()
    schema = config_schema_json()
    assert VIRUSTOTAL_CONFIG_VERSION == "virustotal_config_v2"
    assert "enabled = false" in text
    assert "api_key =" not in text
    assert "api_url" not in text
    assert "network_check_host" not in text
    assert "pre_network_check" not in text
    assert "www.virustotal.com" not in text
    assert "api_url" not in schema
    assert "pre_network_check" not in schema
    assert VIRUSTOTAL_API_HOST == "www.virustotal.com"
    assert VIRUSTOTAL_UPLOAD_URL == "https://www.virustotal.com/api/v3/files"
    assert VIRUSTOTAL_ANALYSIS_PREFIX == "https://www.virustotal.com/api/v3/analyses/"


def test_phase9_enabled_startup_orders_probe_before_credential_resolution() -> None:
    source = Path("Virus_Scan/virustotal/runtime.py").read_text(encoding="utf-8")
    probe = source.index("VirusTotalClient.probe_connectivity")
    network_unavailable = source.index('"network_unavailable"', probe)
    credential = source.index("os.environ.get")
    unconfigured = source.index('"unconfigured"', credential)
    client = source.index("VirusTotalClient(config=config, api_key=api_key)")
    enabled = source.index('"enabled"', client)
    assert probe < network_unavailable < credential < unconfigured < client < enabled
    assert source.count("VirusTotalClient.probe_connectivity") == 1


def test_phase9_reporting_consumes_frozen_runtime_and_cannot_load_alternate_config_path() -> None:
    parameters = inspect.signature(run_virustotal_reporting).parameters
    assert tuple(parameters) == ("results", "runtime")
    source = Path("Virus_Scan/virustotal/reporting.py").read_text(encoding="utf-8")
    assert "load_config(" not in source
    assert "ensure_generated_controls(" not in source
    assert "os.environ" not in source
    assert "probe_connectivity" not in source


def test_phase9_client_repr_does_not_expose_api_key() -> None:
    client = VirusTotalClient(config=VirusTotalConfig(enabled=True), api_key="secret-value")
    assert "secret-value" not in repr(client)


def test_phase9_cli_has_no_virustotal_config_path_override() -> None:
    parser = build_parser()
    options = {option for action in parser._actions for option in action.option_strings}
    assert "--vt-config" not in options


def test_phase9_old_owners_and_paths_are_deleted() -> None:
    assert not Path("Virus_Scan/reporting/virustotal.py").exists()
    assert not hasattr(jsonio, "load_virustotal_config")
    default_literal_owners = []
    for path in Path("Virus_Scan").rglob("*.py"):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "Virus Total Config.json" not in source
        assert "Virus_Scan.reporting.virustotal" not in source
        assert "load_virustotal_config" not in source
        assert "VIRUSTOTAL_DEFAULT_CONFIG" not in source
        assert "pre_network_check" not in source
        assert "--vt-config" not in source
        if '"VIRUSTOTAL_API_KEY"' in source:
            default_literal_owners.append(path.as_posix())
    assert default_literal_owners == ["Virus_Scan/virustotal/config.py"]


def test_phase9_reporting_module_has_bounded_functions() -> None:
    tree = ast.parse(Path("Virus_Scan/virustotal/reporting.py").read_text(encoding="utf-8"))
    offenders = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.end_lineno is not None
        and node.end_lineno - node.lineno + 1 > 75
    }
    assert offenders == {}
