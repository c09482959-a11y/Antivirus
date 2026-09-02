
"""Phase 4 regression tests for scanner default env parsing ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.contracts.env_config import int_env, str_env
from tests.support.env_override import temporary_environ


def test_env_config_str_contract_preserves_default_and_values():
    with temporary_environ(clear=("UMIGE_STAGE1051_STRING",)):
        assert str_env("UMIGE_STAGE1051_STRING", "auto") == "auto"
    with temporary_environ({"UMIGE_STAGE1051_STRING": "deep"}):
        assert str_env("UMIGE_STAGE1051_STRING", "auto") == "deep"


def test_scanner_default_values_use_public_env_contracts():
    source = read_python_file(Path("Virus_Scan/scanners/init_parts/scanner_default_values.py"))
    assert "from Virus_Scan.contracts.env_config import int_env, str_env" in source
    assert 'os.environ.get("UMIGE_DEEP_SCAN_MODE"' not in source
    assert 'os.environ.get("UMIGE_MEDIA_PREFIX_BYTES"' not in source
    assert 'os.environ.get("UMIGE_MEDIA_SUFFIX_BYTES"' not in source
    assert 'os.environ.get("UMIGE_IMAGE_FAST_STRING_BYTES"' not in source


def test_scanner_default_numeric_env_contract_clamps_to_positive():
    with temporary_environ({"UMIGE_MEDIA_PREFIX_BYTES": "0"}):
        assert int_env("UMIGE_MEDIA_PREFIX_BYTES", 32768, 1, None) == 1
