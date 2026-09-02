
"""Phase 4 regression tests for model default env parsing ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.contracts.env_config import float_env
from tests.support.env_override import temporary_environ


def test_model_defaults_use_public_env_contract_for_temporal_half_lives():
    source = read_python_file(Path("Virus_Scan/models/init_parts/model_defaults_init.py"))
    assert "from Virus_Scan.contracts.env_config import float_env" in source
    assert "os.environ.get('UMIGE_TEMPORAL_CONFIDENCE_HALF_LIFE_SEC'" not in source
    assert "os.environ.get('UMIGE_TEMPORAL_HIDDEN_STATE_HALF_LIFE_SEC'" not in source


def test_model_defaults_temporal_half_life_values_follow_env_contract():
    with temporary_environ({"UMIGE_TEMPORAL_CONFIDENCE_HALF_LIFE_SEC": "12.5", "UMIGE_TEMPORAL_HIDDEN_STATE_HALF_LIFE_SEC": "0"}):
        assert float_env("UMIGE_TEMPORAL_CONFIDENCE_HALF_LIFE_SEC", 1800.0, 1.0, None) == 12.5
        assert float_env("UMIGE_TEMPORAL_HIDDEN_STATE_HALF_LIFE_SEC", 3600.0, 1.0, None) == 1.0
