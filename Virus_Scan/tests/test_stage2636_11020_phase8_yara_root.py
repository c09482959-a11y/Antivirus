"""Merged Phase 8 package-complete YARA root and default-load gates."""
from __future__ import annotations

from argparse import Namespace
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil

import pytest

from Virus_Scan.orchestration.yara_initialization import _config_from_args, initialize_yara_from_args
from Virus_Scan.runtime.api import RuntimeContext, release_yara_runtime, yara_runtime_snapshot
from Virus_Scan.yara.config import YaraConfig, config_toml
from Virus_Scan.yara.loader import load_yara_rules
from Virus_Scan.yara.control_files import (
    YARA_RESOURCE_MANIFEST_VERSION,
    prepare_package_controls,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def _base_dir(root: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(root)
    try:
        yield
    finally:
        release_yara_runtime()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _args(**updates: object) -> Namespace:
    values: dict[str, object] = {
        "deep_scan_mode": "auto",
        "no_yara": False,
        "no_yaralight": True,
        "scheduler": "serial",
        "yara": None,
        "yara_config": None,
        "yara_force_refresh": False,
        "yara_no_cache": True,
        "yara_no_download": True,
        "yara_release_api_url": None,
        "yara_status": False,
        "yaralight": None,
        "yaralight_no_download": True,
    }
    values.update(updates)
    return Namespace(**values)


def test_phase8_repository_yara_root_is_package_complete_and_integrity_bound() -> None:
    root = _REPOSITORY_ROOT / "Yara"
    paths = prepare_package_controls(root)
    required = {
        "README.md",
        "yara_defaults.toml",
        "yara_config.toml",
        "yara_config.schema.json",
        "yara_resource_manifest.json",
        "yara-forge-rules-core.zip",
        "yara-forge-rules-extended.zip",
    }
    assert required.issubset({path.name for path in root.iterdir() if path.is_file()})
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == YARA_RESOURCE_MANIFEST_VERSION
    assert [row["package_kind"] for row in manifest["resources"]] == ["core", "extended"]
    assert [row["sha256"] for row in manifest["resources"]] == [
        "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f",
        "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5",
    ]


def test_phase8_package_preparation_preserves_editable_config_and_repairs_projections(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    for filename in ("yara-forge-rules-core.zip", "yara-forge-rules-extended.zip"):
        shutil.copyfile(_REPOSITORY_ROOT / "Yara" / filename, root / filename)
    paths = prepare_package_controls(root)
    paths["config"].write_text(config_toml(YaraConfig(enabled=False)), encoding="utf-8")
    paths["readme"].write_text("incorrect", encoding="utf-8")

    repeated = prepare_package_controls(root)

    assert repeated["config"].read_text(encoding="utf-8") == config_toml(YaraConfig(enabled=False))
    readme = repeated["readme"].read_text(encoding="utf-8")
    assert "does not read Yara/yara_config.toml" in readme
    assert "loaded only when --yara-config explicitly selects" in readme
    assert repeated["defaults"].read_text(encoding="utf-8") == config_toml()


def test_phase8_missing_root_config_is_generated_but_typed_defaults_are_runtime_authority(tmp_path: Path) -> None:
    with _base_dir(tmp_path):
        compiled, ok = initialize_yara_from_args(RuntimeContext(), _args())
        snapshot = yara_runtime_snapshot()
    assert compiled is None
    assert ok is False
    assert (tmp_path / "Yara/yara_config.toml").read_text(encoding="utf-8") == config_toml()
    assert snapshot.status["config_source"] == "typed_defaults"


def test_phase8_user_root_config_is_inert_without_cli_selection(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    config_path = root / "yara_config.toml"
    configured = config_toml(YaraConfig(enabled=False))
    config_path.write_text(configured, encoding="utf-8")
    with _base_dir(tmp_path):
        compiled, ok = initialize_yara_from_args(RuntimeContext(), _args())
        snapshot = yara_runtime_snapshot()
    assert compiled is None
    assert ok is False
    assert snapshot.enabled is True
    assert snapshot.status["config_source"] == "typed_defaults"
    assert snapshot.status["unavailable_reason"] != "yara_disabled_by_config"
    assert config_path.read_text(encoding="utf-8") == configured


def test_phase8_invalid_root_config_is_inert_without_explicit_selection(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    (root / "yara_config.toml").write_text("enabled = true\n", encoding="utf-8")
    with _base_dir(tmp_path):
        compiled, ok = initialize_yara_from_args(RuntimeContext(), _args())
        snapshot = yara_runtime_snapshot()
    assert compiled is None
    assert ok is False
    assert snapshot.enabled is True
    assert snapshot.status["config_source"] == "typed_defaults"
    assert snapshot.status["unavailable_reason"] != "yara_initialization_failed:ValueError"


def test_phase8_explicit_selection_is_same_root_and_one_config_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    config_path = root / "yara_config.toml"
    config_path.write_text(config_toml(YaraConfig(enabled=False)), encoding="utf-8")
    with _base_dir(tmp_path):
        compiled, ok = initialize_yara_from_args(
            RuntimeContext(),
            _args(yara_config=str(config_path)),
        )
        snapshot = yara_runtime_snapshot()
    assert compiled is None
    assert ok is False
    assert snapshot.status["config_source"] == "explicit_validated_toml"


def test_phase8_invalid_explicit_config_fails_closed_without_default_fallback(tmp_path: Path) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    config_path = root / "yara_config.toml"
    config_path.write_text("enabled = false\n", encoding="utf-8")
    with _base_dir(tmp_path):
        compiled, ok = initialize_yara_from_args(
            RuntimeContext(),
            _args(yara_config=str(config_path)),
        )
        snapshot = yara_runtime_snapshot()
    assert compiled is None
    assert ok is False
    assert snapshot.enabled is True
    assert snapshot.available is False
    assert snapshot.status["config_source"] == "explicit_config_invalid"
    assert snapshot.status["unavailable_reason"] == "yara_initialization_failed:ValueError"


def test_phase8_lower_loader_has_no_internal_default_config_owner() -> None:
    with pytest.raises(TypeError, match="yara_loader_config_owner_invalid"):
        load_yara_rules(auto_download=False, config=None)  # type: ignore[arg-type]


def test_phase8_environment_cannot_override_canonical_download_policy(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Yara"
    root.mkdir()
    (root / "yara_config.toml").write_text(config_toml(YaraConfig(allow_full_download=False)), encoding="utf-8")
    previous = os.environ.get("UMIGE_YARA_AUTO_DOWNLOAD")
    os.environ["UMIGE_YARA_AUTO_DOWNLOAD"] = "1"
    try:
        config = _config_from_args(_args(yara_no_download=False), root)
    finally:
        if previous is None:
            os.environ.pop("UMIGE_YARA_AUTO_DOWNLOAD", None)
        else:
            os.environ["UMIGE_YARA_AUTO_DOWNLOAD"] = previous

    assert config.allow_full_download is False
