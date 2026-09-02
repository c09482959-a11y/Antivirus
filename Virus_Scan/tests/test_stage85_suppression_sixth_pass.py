import ast
from hashlib import sha256
from pathlib import Path
from types import ModuleType

from Virus_Scan.yara.cache import cache_paths, save_compiled_cache
from Virus_Scan.yara.cache_identity import build_cache_identity
from Virus_Scan.yara.compilation import compile_rule_source
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.source import custom_rule_source
import Virus_Scan.reporting.result_schema as rs


class _Rules:
    def save(self, path: str) -> None:
        Path(path).write_bytes(b"compiled")


def _outcome(tmp_path: Path):
    source_path = tmp_path / "rules.yar"
    source_path.write_text("rule A { condition: true }", encoding="utf-8")
    config = YaraConfig(custom_rule_expected_sha256=sha256(source_path.read_bytes()).hexdigest())
    source = custom_rule_source(source_path, config, package_kind="custom")
    module = ModuleType("yara")
    module.__version__ = "4.5.2"
    module.compile = lambda **_kwargs: _Rules()
    identity = build_cache_identity(source, module)
    return identity, compile_rule_source(source, config, identity, module)


def test_compiled_cache_save_fails_closed_when_root_is_not_directory(tmp_path: Path) -> None:
    identity, outcome = _outcome(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.write_text("file", encoding="utf-8")
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=blocked) is False


def test_compiled_cache_save_is_durable_and_identity_indexed(tmp_path: Path) -> None:
    identity, outcome = _outcome(tmp_path)
    root = tmp_path / "Yara"
    assert save_compiled_cache(outcome.rules, identity, outcome.load_result, root=root) is True
    paths = cache_paths(identity, root=root)
    assert paths.compiled.read_bytes() == b"compiled"
    assert identity.digest in paths.manifest.read_text(encoding="utf-8")


def test_reporting_result_schema_has_no_static_output_cycle() -> None:
    source = Path(rs.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert "Virus_Scan.reporting.output" not in imports
