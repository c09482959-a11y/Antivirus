from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from Virus_Scan.virustotal.config import VirusTotalConfig, config_toml, load_config
from Virus_Scan.virustotal.control_files import ensure_generated_controls


def test_stage1011_virustotal_default_config_is_frozen_and_secret_free() -> None:
    config = VirusTotalConfig()
    assert config.enabled is False
    assert config.api_key_environment_variable == "VIRUSTOTAL_API_KEY"
    assert "api_key =" not in config_toml(config)
    with pytest.raises(FrozenInstanceError):
        config.enabled = True  # type: ignore[misc]


def test_stage1011_virustotal_control_creation_writes_canonical_toml(tmp_path: Path) -> None:
    paths = ensure_generated_controls(tmp_path)
    loaded = load_config(paths["config"])
    assert loaded == VirusTotalConfig()
    assert paths["config"].name == "virustotal_config.toml"
    assert paths["defaults"].read_text(encoding="utf-8") == config_toml()
