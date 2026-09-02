
"""Phase 4 regression tests for core env parsing through canonical contracts."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.contracts.env_config import bool_env, int_env
from tests.support.env_override import temporary_environ


def test_core_jsonio_and_logging_use_public_env_contracts():
    jsonio = read_python_file(Path("Virus_Scan/core/jsonio.py"))
    logging_src = read_python_file(Path("Virus_Scan/core/logging.py"))
    assert "from Virus_Scan.contracts.env_config import int_env" in jsonio
    assert "os.environ.get('UMIGE_QUEUE_JSON_READ_RETRIES'" not in jsonio
    assert "from Virus_Scan.contracts.env_config import bool_env, int_env" in logging_src
    assert "os.environ.get('UMIGE_QUEUE_FS_RETRIES'" not in logging_src
    assert "os.environ.get('UMIGE_PROCESS_SHARD') == '1'" not in logging_src


def test_core_env_contracts_preserve_retry_bounds():
    with temporary_environ({"UMIGE_QUEUE_FS_RETRIES": "0", "UMIGE_QUEUE_JSON_READ_RETRIES": "bad", "UMIGE_PROCESS_SHARD": "1"}):
        assert int_env("UMIGE_QUEUE_FS_RETRIES", 12, 1, None) == 1
        assert int_env("UMIGE_QUEUE_JSON_READ_RETRIES", 6, 1, None) == 6
        assert bool_env("UMIGE_PROCESS_SHARD", False) is True
