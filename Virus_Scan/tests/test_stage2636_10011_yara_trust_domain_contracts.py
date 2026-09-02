from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from Virus_Scan.yara.config import YaraConfig, config_readme, config_schema_json, config_toml, load_config
from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.integrity import parse_release_manifest
from Virus_Scan.yara.release_api import select_release_identity
from Virus_Scan.yara.rule_archive import validate_rule_archive
from Virus_Scan.yara.validation import YARA_RELEASE_MANIFEST_NAME
from Virus_Scan.yara.versioning import YARA_CONFIG_VERSION


def _release_bytes(*, duplicate_archive: bool = False, include_manifest: bool = True) -> bytes:
    tag = "20260712"
    base = f"https://github.com/YARAHQ/yara-forge/releases/download/{tag}/"
    assets = [
        {
            "id": 11,
            "name": "yara-forge-rules-extended.zip",
            "browser_download_url": base + "yara-forge-rules-extended.zip",
            "size": 4096,
            "state": "uploaded",
        },
        {
            "id": 13,
            "name": "yara-forge-log.txt",
            "browser_download_url": base + "yara-forge-log.txt",
            "size": 42,
            "state": "uploaded",
        },
    ]
    if include_manifest:
        assets.append({
            "id": 12,
            "name": YARA_RELEASE_MANIFEST_NAME,
            "browser_download_url": base + YARA_RELEASE_MANIFEST_NAME,
            "size": 256,
            "state": "uploaded",
        })
    if duplicate_archive:
        assets.append(dict(assets[0]))
    return json.dumps({"id": 99, "tag_name": tag, "draft": False, "prerelease": False, "assets": assets}).encode()


def _manifest(*, core: str = "a", extended: str = "b", full: str = "c") -> bytes:
    return (
        f"{core * 64}  yara-forge-rules-core.zip\n"
        f"{extended * 64}  yara-forge-rules-extended.zip\n"
        f"{full * 64}  yara-forge-rules-full.zip\n"
    ).encode("ascii")


def _write_zip(path: Path, members: tuple[tuple[str, bytes], ...]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)


def test_release_asset_pair_is_exact_and_immutable() -> None:
    identity = select_release_identity(_release_bytes(), "extended")
    assert identity.release_id == 99
    assert identity.release_tag == "20260712"
    assert identity.archive_name == "yara-forge-rules-extended.zip"
    assert identity.manifest_name == YARA_RELEASE_MANIFEST_NAME
    with pytest.raises(ValueError, match="yara_release_assets_duplicate"):
        select_release_identity(_release_bytes(duplicate_archive=True), "extended")
    with pytest.raises(ValueError, match="yara_release_manifest_asset_missing"):
        select_release_identity(_release_bytes(include_manifest=False), "extended")
    with pytest.raises(ValueError, match="yara_release_json_duplicate_key"):
        select_release_identity(b'{"id":1,"id":2}', "core")


def test_release_authority_rejects_userinfo_port_and_wrong_tag() -> None:
    record = json.loads(_release_bytes())
    asset = record["assets"][0]
    for bad_url in (
        "https://user@github.com/YARAHQ/yara-forge/releases/download/20260712/yara-forge-rules-extended.zip",
        "https://github.com:444/YARAHQ/yara-forge/releases/download/20260712/yara-forge-rules-extended.zip",
        "https://github.com/YARAHQ/yara-forge/releases/download/20260705/yara-forge-rules-extended.zip",
    ):
        asset["browser_download_url"] = bad_url
        with pytest.raises(ValueError, match="yara_release_asset_url_invalid"):
            select_release_identity(json.dumps(record).encode(), "extended")


def test_release_manifest_requires_exact_full_archive_set_and_grammar() -> None:
    manifest = parse_release_manifest(_manifest(), maximum_bytes=1024)
    assert manifest.expected_digest("yara-forge-rules-core.zip") == "a" * 64
    with pytest.raises(ValueError, match="yara_release_manifest_line_count_invalid"):
        parse_release_manifest(("a" * 64 + "\n").encode(), maximum_bytes=1024)
    with pytest.raises(ValueError, match="yara_release_manifest_line_invalid"):
        parse_release_manifest(
            _manifest().replace(b"  yara-forge-rules-core.zip", b" *yara-forge-rules-core.zip"),
            maximum_bytes=1024,
        )
    with pytest.raises(ValueError, match="yara_release_manifest_duplicate_filename"):
        duplicate = (
            f"{'a' * 64}  yara-forge-rules-core.zip\n"
            f"{'b' * 64}  yara-forge-rules-core.zip\n"
            f"{'c' * 64}  yara-forge-rules-full.zip\n"
        ).encode("ascii")
        parse_release_manifest(duplicate, maximum_bytes=1024)
    with pytest.raises(ValueError, match="yara_release_manifest_line_invalid"):
        parse_release_manifest(
            _manifest().replace(b"yara-forge-rules-full.zip", b"../yara-forge-rules-full.zip"),
            maximum_bytes=1024,
        )


def test_config_controls_are_deterministic_and_strict(tmp_path: Path) -> None:
    assert config_toml() == config_toml()
    assert config_schema_json() == config_schema_json()
    assert config_readme() == config_readme()
    schema = json.loads(config_schema_json())
    assert schema["properties"]["release_api_url"]["const"].startswith("https://api.github.com/")
    path = tmp_path / "yara_config.toml"
    path.write_text(config_toml(), encoding="utf-8")
    loaded = load_config(path)
    assert loaded == YaraConfig()
    path.write_text(config_toml() + "unknown = true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="yara_config_fields_rejected"):
        load_config(path)
    path.write_text(config_toml().replace(f'config_version = "{YARA_CONFIG_VERSION}"\n', f'config_version = "{YARA_CONFIG_VERSION}"\nconfig_version = "x"\n'), encoding="utf-8")
    with pytest.raises(Exception):
        load_config(path)




def test_yara_config_owns_independent_full_light_and_custom_digests(tmp_path: Path) -> None:
    full = "1" * 64
    light = "2" * 64
    custom = "3" * 64
    config = YaraConfig(
        full_expected_sha256=full,
        light_expected_sha256=light,
        custom_rule_expected_sha256=custom,
    )
    assert config.full_expected_sha256 == full
    assert config.light_expected_sha256 == light
    assert config.custom_rule_expected_sha256 == custom

    text = config_toml().replace(
        'full_expected_sha256 = ""', f'full_expected_sha256 = "{full}"',
    ).replace(
        'light_expected_sha256 = ""', f'light_expected_sha256 = "{light}"',
    ).replace(
        'custom_rule_expected_sha256 = ""',
        f'custom_rule_expected_sha256 = "{custom}"',
    )
    path = tmp_path / "yara_config.toml"
    path.write_text(text, encoding="utf-8")
    assert load_config(path) == config
    assert "custom_expected_sha256" not in text


def test_rule_archive_publishes_sorted_member_digests(tmp_path: Path) -> None:
    archive_path = tmp_path / "rules.zip"
    _write_zip(archive_path, (("rules/z.yar", b"rule z { condition: true }"), ("rules/a.yara", b"rule a { condition: true }"), ("README.md", b"ok")))
    members = validate_rule_archive(archive_path, YaraConfig())
    assert tuple(item.name for item in members) == ("rules/a.yara", "rules/z.yar")
    assert all(len(item.sha256) == 64 for item in members)


def test_rule_archive_rejects_symlink_and_unsupported_compression(tmp_path: Path) -> None:
    symlink = tmp_path / "symlink.zip"
    with zipfile.ZipFile(symlink, "w") as archive:
        info = zipfile.ZipInfo("rules/link.yar")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, b"target.yar")
    with pytest.raises(ValueError, match="yara_archive_special_member_rejected"):
        validate_rule_archive(symlink, YaraConfig())

    unsupported = tmp_path / "unsupported.zip"
    with zipfile.ZipFile(unsupported, "w", compression=zipfile.ZIP_BZIP2) as archive:
        archive.writestr("rules/one.yar", b"rule one { condition: true }")
    with pytest.raises(ValueError, match="yara_archive_compression_method_rejected"):
        validate_rule_archive(unsupported, YaraConfig())


def test_rule_archive_rejects_traversal_duplicate_and_bomb_shape(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.zip"
    _write_zip(traversal, (("../evil.yar", b"rule e { condition: true }"),))
    with pytest.raises(ValueError, match="yara_archive_member_path_invalid"):
        validate_rule_archive(traversal, YaraConfig())
    duplicate = tmp_path / "duplicate.zip"
    _write_zip(duplicate, (("a.yar", b"rule a { condition: true }"), ("A.YAR", b"rule b { condition: true }")))
    with pytest.raises(ValueError, match="yara_archive_duplicate_member"):
        validate_rule_archive(duplicate, YaraConfig())
    bomb = tmp_path / "bomb.zip"
    _write_zip(bomb, (("bomb.yar", b"A" * 100_000),))
    with pytest.raises(ValueError, match="yara_archive_compression_ratio_invalid"):
        validate_rule_archive(bomb, YaraConfig(maximum_compression_ratio=2.0))


def test_rule_load_result_enforces_readiness_counts_and_order() -> None:
    ready = YaraRuleLoadResult("fully_compiled", True, 2, 2, 0, 0.95, (), "")
    assert ready.ready is True
    with pytest.raises(ValueError, match="yara_load_counts_inconsistent"):
        YaraRuleLoadResult("fully_compiled", True, 2, 1, 0, 0.95, (), "")
    with pytest.raises(ValueError, match="yara_load_readiness_inconsistent"):
        YaraRuleLoadResult("integrity_failure", True, 1, 0, 1, 0.95, ("bad",), "failure")
    with pytest.raises(ValueError, match="yara_load_ready_counts_invalid"):
        YaraRuleLoadResult("fully_compiled", True, 2, 1, 1, 0.95, ("bad",), "")
    with pytest.raises(ValueError, match="yara_load_partial_acceptance_invalid"):
        YaraRuleLoadResult("partially_compiled_accepted", True, 2, 0, 2, 0.5, ("a", "b"), "")
    with pytest.raises(ValueError, match="yara_load_threshold_invalid"):
        YaraRuleLoadResult("custom_verified", True, 1, 1, 0, 0.1, (), "")


class _HostileText(str):
    def __str__(self) -> str:
        raise AssertionError("hook executed")


def test_public_contracts_reject_hostile_text_without_hooks() -> None:
    with pytest.raises(TypeError, match="yara_package_kind_invalid"):
        select_release_identity(_release_bytes(), _HostileText("extended"))

    class _ForeignYaraConfig(YaraConfig):
        pass

    with pytest.raises(TypeError, match="yara_config_owner_invalid"):
        _ForeignYaraConfig()
