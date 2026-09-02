
"""Phase 4 regression tests for orchestration env policy ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path


def test_orchestration_yara_auto_download_has_no_environment_authority():
    source = read_python_file(Path("Virus_Scan/orchestration/yara_initialization.py"))
    assert "from Virus_Scan.contracts.env_config import bool_env" not in source
    assert 'UMIGE_YARA_AUTO_DOWNLOAD' not in source
