from hashlib import sha256
from pathlib import Path
from types import ModuleType
import zipfile

import pytest

from Virus_Scan.tests.support.native_filesystem_alias import create_native_directory_alias
from Virus_Scan.yara.cache import cache_paths, load_compiled_cache, save_compiled_cache
from Virus_Scan.yara.cache_identity import build_cache_identity, cache_identity_from_payload
from Virus_Scan.yara.compilation import compile_rule_source
from Virus_Scan.yara.loader import YaraLoadAttempt, _load_source
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraArchiveAcquisition, YaraArchiveMember, YaraArchiveSnapshot, YaraReleaseIdentity
from Virus_Scan.yara.publication import disabled_package_status, load_attempt_status
from Virus_Scan.yara.source import custom_rule_source, official_rule_source


class _CompiledRules:
    def __init__(self, marker: str = "compiled") -> None:
        self.marker = marker

    def save(self, path: str) -> None:
        Path(path).write_bytes(self.marker.encode("utf-8"))


def _module() -> ModuleType:
    module = ModuleType("yara")
    module.__version__ = "4.5.2"

    def load(path: str) -> _CompiledRules:
        return _CompiledRules(Path(path).read_text(encoding="utf-8"))

    def compile_rules(**kwargs: object) -> _CompiledRules:
        filepaths = kwargs.get("filepaths")
        if type(filepaths) is not dict:
            raise RuntimeError("filepaths_required")
        for path in tuple(dict.values(filepaths)):
            if "BAD" in Path(path).read_text(encoding="utf-8"):
                raise RuntimeError("bad_rule")
        return _CompiledRules("compiled")

    module.load = load
    module.compile = compile_rules
    return module


def _verified_file(tmp_path: Path) -> tuple[Path, YaraConfig]:
    path = tmp_path / "rules.yar"
    path.write_text("rule Good { condition: true }", encoding="utf-8")
    digest = sha256(path.read_bytes()).hexdigest()
    return path, YaraConfig(custom_rule_expected_sha256=digest)


def _verified_zip(tmp_path: Path, *, threshold: float) -> tuple[Path, YaraConfig]:
    path = tmp_path / "rules.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.yar", "rule A { condition: true }")
        archive.writestr("b.yar", "rule B { condition: true }")
        archive.writestr("bad.yar", "BAD")
    digest = sha256(path.read_bytes()).hexdigest()
    return path, YaraConfig(custom_rule_expected_sha256=digest, partial_compile_threshold=threshold)


def test_custom_zip_requires_zip_extension_at_source_boundary(tmp_path: Path) -> None:
    path = tmp_path / "rules.yar"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.yar", "rule A { condition: true }")
    digest = sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="yara_custom_source_extension_invalid"):
        custom_rule_source(path, YaraConfig(custom_rule_expected_sha256=digest), package_kind="custom")



def _official_source(tmp_path: Path, *, release_id: int, archive_asset_id: int):
    path = tmp_path / ("official-" + str(release_id) + ".zip")
    path.write_bytes(b"official-archive-bytes")
    archive_digest = sha256(path.read_bytes()).hexdigest()
    tag = "20260712"
    archive_name = "yara-forge-rules-extended.zip"
    manifest_name = "yara-forge-rules-sha256.txt"
    base = "https://github.com/YARAHQ/yara-forge/releases/download/" + tag + "/"
    release = YaraReleaseIdentity(
        release_id=release_id,
        release_tag=tag,
        package_kind="extended",
        archive_asset_id=archive_asset_id,
        archive_name=archive_name,
        archive_url=base + archive_name,
        manifest_asset_id=archive_asset_id + 1,
        manifest_name=manifest_name,
        manifest_url=base + manifest_name,
    )
    member = YaraArchiveMember("rules/a.yar", "a" * 64, 16, 32)
    snapshot = YaraArchiveSnapshot(
        release, path, archive_digest, archive_digest, "b" * 64, (member,),
    )
    acquisition = YaraArchiveAcquisition(snapshot, "github_release_api", "downloaded", True)
    return official_rule_source(acquisition)


def test_cache_identity_rejects_group_values_before_partitioning(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    source = custom_rule_source(path, config, package_kind="custom")
    with pytest.raises((TypeError, ValueError), match="yara_cache_group_count_invalid"):
        build_cache_identity(source, _module(), group_count=0)
    with pytest.raises((TypeError, ValueError), match="yara_cache_group_index_invalid"):
        build_cache_identity(source, _module(), group_index=1, group_count=1)


def test_cache_identity_binds_compiler_partition_and_member_digest(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    source = custom_rule_source(path, config, package_kind="custom")
    first_module = _module()
    first = build_cache_identity(source, first_module)
    second_module = _module()
    second_module.__version__ = "4.6.0"
    assert first.digest != build_cache_identity(source, second_module).digest
    assert first.digest == build_cache_identity(source, first_module).digest


def test_compiled_cache_requires_exact_identity_and_binary_digest(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    module = _module()
    source = custom_rule_source(path, config, package_kind="custom")
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    assert outcome.load_result.ready is True
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=tmp_path / "Yara") is True
    loaded = load_compiled_cache(identity, module, root=tmp_path / "Yara")
    assert loaded is not None
    assert loaded.load_result == outcome.load_result
    paths = cache_paths(identity, root=tmp_path / "Yara")
    paths.compiled.write_bytes(b"tampered")
    assert load_compiled_cache(identity, module, root=tmp_path / "Yara") is None
    assert not paths.compiled.exists()
    assert not paths.manifest.exists()


def test_compiled_cache_rejects_symlinked_manifest_without_following_target(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    module = _module()
    source = custom_rule_source(path, config, package_kind="custom")
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    root = tmp_path / "Yara"
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=root) is True
    paths = cache_paths(identity, root=root)
    outside = tmp_path / "outside-manifest"
    outside.mkdir()
    sentinel = outside / "sentinel.json"
    paths.manifest.replace(sentinel)
    create_native_directory_alias(paths.manifest, outside)
    assert load_compiled_cache(identity, module, root=root) is None
    assert sentinel.is_file()
    assert not paths.manifest.exists()
    assert not paths.compiled.exists()


def test_compiled_cache_rejects_symlinked_cache_directory(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    module = _module()
    source = custom_rule_source(path, config, package_kind="custom")
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    root = tmp_path / "Yara"
    root.mkdir()
    outside = tmp_path / "outside-cache"
    outside.mkdir()
    create_native_directory_alias(root / "yara.cache", outside)
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=root) is False
    assert load_compiled_cache(identity, module, root=root) is None
    assert tuple(outside.iterdir()) == ()


def test_compiled_cache_rejects_symlink_created_by_compiler_save(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    module = _module()
    source = custom_rule_source(path, config, package_kind="custom")
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    outside = tmp_path / "outside-compiled"
    outside.mkdir()
    sentinel = outside / "sentinel.yarc"
    sentinel.write_bytes(b"outside")

    class SymlinkCompiled:
        def save(self, target: str) -> None:
            create_native_directory_alias(Path(target), outside)

    assert save_compiled_cache(
        SymlinkCompiled(), identity, outcome.load_result, root=tmp_path / "Yara",
    ) is False
    assert sentinel.read_bytes() == b"outside"


def test_load_source_rejects_non_boolean_cache_policy(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    source = custom_rule_source(path, config, package_kind="custom")
    with pytest.raises(TypeError, match="yara_cache_write_policy_invalid"):
        _load_source(source, config, use_cache=1, yara_module=_module())


def test_partial_compile_acceptance_uses_configured_threshold(tmp_path: Path) -> None:
    path, config = _verified_zip(tmp_path, threshold=0.6)
    source = custom_rule_source(path, config, package_kind="custom")
    module = _module()
    first_bulk = {"value": True}

    def compile_rules(**kwargs: object) -> _CompiledRules:
        filepaths = kwargs.get("filepaths")
        if type(filepaths) is not dict:
            raise RuntimeError("filepaths_required")
        values = tuple(dict.values(filepaths))
        if len(values) > 1 and first_bulk["value"]:
            first_bulk["value"] = False
            raise RuntimeError("bulk_rejected")
        if any("BAD" in Path(item).read_text(encoding="utf-8") for item in values):
            raise RuntimeError("bad_rule")
        return _CompiledRules()

    module.compile = compile_rules
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    assert outcome.rules is not None
    assert outcome.load_result.state == "partially_compiled_accepted"
    assert outcome.load_result.compiled_members == 2
    assert outcome.load_result.failed_members == 1
    assert outcome.load_result.failure_samples == ("bad.yar",)
    assert not tuple(item for item in tmp_path.iterdir() if item.is_dir())


def test_partial_compile_below_threshold_is_unavailable(tmp_path: Path) -> None:
    path, config = _verified_zip(tmp_path, threshold=0.9)
    source = custom_rule_source(path, config, package_kind="custom")
    module = _module()
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    assert outcome.rules is None
    assert outcome.load_result.ready is False
    assert outcome.load_result.state == "partial_rejected"
    assert outcome.load_result.failure_samples == ("bad.yar",)
    assert not tuple(item for item in tmp_path.iterdir() if item.is_dir())


def test_unverified_custom_source_cannot_compile_or_enter_cache(tmp_path: Path) -> None:
    path = tmp_path / "rules.yar"
    path.write_text("rule Good { condition: true }", encoding="utf-8")
    source = custom_rule_source(path, YaraConfig(), package_kind="custom")
    with pytest.raises(TypeError, match="yara_cache_source_identity_invalid"):
        build_cache_identity(source, _module())


def test_official_cache_identity_binds_exact_release_and_asset_identity(tmp_path: Path) -> None:
    module = _module()
    first = build_cache_identity(_official_source(tmp_path, release_id=700, archive_asset_id=701), module)
    repeated = build_cache_identity(_official_source(tmp_path, release_id=700, archive_asset_id=701), module)
    changed_release = build_cache_identity(_official_source(tmp_path, release_id=800, archive_asset_id=701), module)
    changed_asset = build_cache_identity(_official_source(tmp_path, release_id=700, archive_asset_id=801), module)
    assert first == cache_identity_from_payload(first.payload())
    assert first.digest == repeated.digest
    assert first.digest != changed_release.digest
    assert first.digest != changed_asset.digest
    assert first.release_id == 700
    assert first.archive_asset_id == 701
    assert first.manifest_asset_id == 702


def test_load_attempt_reports_unverified_and_dependency_unavailable_states(tmp_path: Path) -> None:
    unverified_path = tmp_path / "unverified.yar"
    unverified_path.write_text("rule Unverified { condition: true }", encoding="utf-8")
    unverified_source = custom_rule_source(unverified_path, YaraConfig(), package_kind="custom")
    unverified = _load_source(
        unverified_source, YaraConfig(), use_cache=False, yara_module=_module(),
    )
    assert type(unverified) is YaraLoadAttempt
    assert unverified.rules is None
    assert unverified.identity is None
    assert unverified.load_result.state == "custom_unverified"
    assert unverified.load_result.failed_members == 1

    verified_path, verified_config = _verified_file(tmp_path)
    verified_source = custom_rule_source(verified_path, verified_config, package_kind="custom")
    unavailable = _load_source(
        verified_source, verified_config, use_cache=False, yara_module=None,
        dependency_error=RuntimeError("missing fixture dependency"),
    )
    assert unavailable.rules is None
    assert unavailable.identity is None
    assert unavailable.load_result.state == "dependency_unavailable"
    assert unavailable.load_result.failed_members == 1
    assert "missing fixture dependency" in unavailable.load_result.reason


def test_ready_load_publication_binds_cache_compiler_and_custom_integrity(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    source = custom_rule_source(path, config, package_kind="custom")
    loaded = _load_source(
        source, config, use_cache=False, yara_module=_module(),
    )
    status = load_attempt_status(loaded, disabled_reason="not_used")
    assert loaded.load_result.ready is True
    assert status["source_trust"] == "custom_verified"
    assert status["integrity_state"] == "explicit_expected_sha256_verified"
    assert status["archive_sha256_expected"] == sha256(path.read_bytes()).hexdigest()
    assert status["archive_sha256_computed"] == sha256(path.read_bytes()).hexdigest()
    assert status["cache_identity"] == loaded.identity.digest
    assert status["cache_schema_version"] == loaded.identity.cache_schema_version
    assert status["yara_engine_version"] == "4.5.2"
    assert status["platform_identity"] == loaded.identity.platform_identity
    assert status["compilation_state"] == "custom_verified"
    assert status["compiled_members"] == 1
    assert status["failed_members"] == 0
    assert status["unavailable_reason"] == ""


def test_yara_package_publication_keeps_one_stable_key_schema(tmp_path: Path) -> None:
    path, config = _verified_file(tmp_path)
    loaded = _load_source(
        custom_rule_source(path, config, package_kind="custom"), config, use_cache=False, yara_module=_module(),
    )
    disabled = disabled_package_status("disabled")
    ready = load_attempt_status(loaded, disabled_reason="not_used")

    assert disabled.keys() == ready.keys()
    assert disabled["compile_policy_version"] == ""
    assert disabled["group_cache_count"] == 0
    assert disabled["group_cache_identities"] == ()
