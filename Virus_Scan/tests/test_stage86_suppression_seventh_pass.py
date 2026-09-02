import json
from hashlib import sha256
from pathlib import Path
from types import ModuleType

from Virus_Scan.yara.cache import cache_paths, load_compiled_cache, save_compiled_cache
from Virus_Scan.storage import ScanCacheRepository, SQLiteLifecycleOwner
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.compilation import compile_rule_source
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.source import custom_rule_source


class _Rules:
    def save(self, path: str) -> None:
        Path(path).write_bytes(b"compiled")


def _cache(tmp_path: Path):
    source_path = tmp_path / "rules.yar"
    source_path.write_text("rule A { condition: true }", encoding="utf-8")
    config = YaraConfig(custom_rule_expected_sha256=sha256(source_path.read_bytes()).hexdigest())
    source = custom_rule_source(source_path, config, package_kind="custom")
    module = ModuleType("yara")
    module.__version__ = "4.5.2"
    module.compile = lambda **_kwargs: _Rules()
    module.load = lambda path: {"loaded": path}
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    root = tmp_path / "Yara"
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=root)
    return module, identity, root, cache_paths(identity, root=root)


def test_scan_cache_corrupt_sqlite_result_is_deleted_fail_closed(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path)
    repository = ScanCacheRepository(lifecycle)
    repository.configure(tmp_path, enabled=True)
    identity = disabled_scan_cache_identity()
    sha256 = "1" * 64
    try:
        assert repository.put_result(
            content_sha256=sha256,
            content_size=1,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
        ) is True
        lifecycle.connection("cache").execute(
            "UPDATE cache_semantic_results SET result_sha256=? WHERE content_sha256=?",
            ("0" * 64, sha256),
        )
        assert repository.get_result(
            content_sha256=sha256,
            execution_identity=identity,
            canonical_path=str(tmp_path / "payload.bin"),
            file_name="payload.bin",
            content_size=1,
        ) is None
        assert lifecycle.connection("cache").execute(
            "SELECT 1 FROM cache_semantic_results WHERE content_sha256=?", (sha256,)
        ).fetchone() is None
    finally:
        lifecycle.close()

def test_yara_cache_corrupt_manifest_is_removed_with_binary(tmp_path: Path) -> None:
    module, identity, root, paths = _cache(tmp_path)
    paths.manifest.write_text("{broken", encoding="utf-8")
    assert load_compiled_cache(identity, module, root=root) is None
    assert not paths.manifest.exists()
    assert not paths.compiled.exists()


def test_yara_cache_duplicate_manifest_key_is_rejected(tmp_path: Path) -> None:
    module, identity, root, paths = _cache(tmp_path)
    payload = paths.manifest.read_text(encoding="utf-8")
    paths.manifest.write_text(payload[:-1] + ',"identity_digest":"' + identity.digest + '"}', encoding="utf-8")
    assert load_compiled_cache(identity, module, root=root) is None
