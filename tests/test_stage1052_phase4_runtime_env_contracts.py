
"""Stage 1052 Phase 4 regression tests for runtime env ownership surfaces."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.contracts.env_config import int_env_status
from tests.support.env_override import temporary_environ


def test_core_paths_and_init_no_longer_read_process_environment_directly():
    paths_source = read_python_file(Path("Virus_Scan/core/paths.py"))
    init_source = read_python_file(Path("Virus_Scan/core/init_parts/paths_logging_init.py"))
    assert "os.environ.get('UMIGE_FORCE_SANDBOXIE')" not in paths_source
    assert "os.environ.get('UMIGE_DISABLE_SANDBOXIE_CONSOLE_POLICY')" not in paths_source
    assert "os.environ.keys()" not in paths_source
    assert "os.environ.values()" not in paths_source
    assert 'os.environ.get("UMIGE_PROCESS_SHARD")' not in init_source
    assert 'os.environ.setdefault("UMIGE_BASE_DIR"' not in init_source
    assert 'RuntimeEnvironmentOwner' in init_source


def test_model_profile_init_and_scanner_retry_use_public_env_contracts():
    model_source = read_python_file(Path("Virus_Scan/models/init_parts/profile_and_learning_store_init.py"))
    pipeline_source = read_python_file(Path("Virus_Scan/scanners/pipeline.py"))
    assert "from Virus_Scan.contracts.env_config import str_env" in model_source
    assert "os.environ.get('UMIGE_BASE_DIR')" not in model_source
    assert "from Virus_Scan.contracts.env_config import int_env_status" in pipeline_source
    assert "env_reader=os.environ.get" not in pipeline_source


def test_cli_yara_and_core_logging_env_reads_use_public_contracts():
    checked_files = (
        "Virus_Scan/cli/args.py",
        "Virus_Scan/core/logging.py",
        "Virus_Scan/yara/download.py",
        "Virus_Scan/yara/match.py",
        "Virus_Scan/yara/phase_contracts.py",
        "Virus_Scan/yara/init_parts/yara_defaults_init.py",
    )
    for filename in checked_files:
        source = Path(filename).read_text()
        assert "os.environ.get" not in source
        assert "os.getenv" not in source


def test_int_env_status_preserves_parse_error_status():
    with temporary_environ({"UMIGE_STAGE1052_INT_STATUS": "bad"}):
        assert int_env_status("UMIGE_STAGE1052_INT_STATUS", 7, 1, None) == ("parse_error", 7)
    with temporary_environ({"UMIGE_STAGE1052_INT_STATUS": "0"}):
        assert int_env_status("UMIGE_STAGE1052_INT_STATUS", 7, 1, 5) == ("valid", 1)
