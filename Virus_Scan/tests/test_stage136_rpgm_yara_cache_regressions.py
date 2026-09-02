from hashlib import sha256
from types import ModuleType

from Virus_Scan.routing.magic import sniff_file_identity
from Virus_Scan.scheduler.queue.admission import classify_workload
from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.source import custom_rule_source


def test_rpgm_mv_encrypted_png_suffix_routes_to_image_lane(tmp_path):
    path = tmp_path / "Road1.png_"
    path.write_bytes(b"RPGMV\x00\x00\x00" + b"x" * 64)

    workload_identity = _sniff_workload_identity(str(path))
    full_identity = sniff_file_identity(str(path))

    assert workload_identity["magic_type"] == "rpgm_mv_encrypted_asset"
    assert "rpgm_encrypted_image" in workload_identity["tags"]
    assert classify_workload(str(path)) == "image"
    assert full_identity["magic_stage"] == "asset"
    assert full_identity["magic_type"] == "rpgm_mv_encrypted_asset"
    assert "rpgm_encrypted_image" in full_identity["tags"]


def test_yara_cache_identity_uses_explicit_yara_dependency_version(tmp_path):
    source_path = tmp_path / "rules.yar"
    source_path.write_text("rule A { condition: true }", encoding="utf-8")
    config = YaraConfig(custom_rule_expected_sha256=sha256(source_path.read_bytes()).hexdigest())
    source = custom_rule_source(source_path, config, package_kind="custom")
    first = ModuleType("yara")
    first.__version__ = "4.5.2"
    second = ModuleType("yara")
    second.__version__ = "4.6.0"
    assert build_cache_identity(source, first).digest != build_cache_identity(source, second).digest
