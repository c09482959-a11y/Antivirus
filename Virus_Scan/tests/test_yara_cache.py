from hashlib import sha256
from pathlib import Path
from types import ModuleType

from Virus_Scan.yara.cache import load_compiled_cache, save_compiled_cache
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.compilation import compile_rule_source
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.source import custom_rule_source


class _Rules:
    def save(self, path: str) -> None:
        Path(path).write_bytes(b"compiled")


def _module() -> ModuleType:
    module = ModuleType("yara")
    module.__version__ = "4.5.2"
    module.compile = lambda **_kwargs: _Rules()
    module.load = lambda path: {"loaded": path}
    return module


def _source(path: Path):
    digest = sha256(path.read_bytes()).hexdigest()
    config = YaraConfig(custom_rule_expected_sha256=digest)
    return custom_rule_source(path, config, package_kind="custom"), config


def test_yara_cache_identity_changes_when_rules_change(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule A { condition: true }", encoding="utf-8")
    source, _config = _source(rules)
    first = build_cache_identity(source, _module()).digest
    rules.write_text("rule B { condition: true }", encoding="utf-8")
    source, _config = _source(rules)
    assert first != build_cache_identity(source, _module()).digest


def test_yara_cache_loader_requires_exact_compiled_identity(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule A { condition: true }", encoding="utf-8")
    source, config = _source(rules)
    module = _module()
    identity = build_cache_identity(source, module)
    outcome = compile_rule_source(source, config, identity, module)
    root = tmp_path / "Yara"
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=root) is True
    loaded = load_compiled_cache(identity, module, root=root)
    assert loaded is not None
    assert loaded.identity == identity
