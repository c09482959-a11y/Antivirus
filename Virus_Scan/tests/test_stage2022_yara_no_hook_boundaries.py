import ast
from pathlib import Path

import pytest

from Virus_Scan.yara import download, download_io, match, phase_contracts, zip_scan
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.no_hook import yara_text


class HostileYaraValue:
    touched = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def __str__(self):
        type(self).touched.append("__str__")
        return "hostile"

    def __repr__(self):
        type(self).touched.append("__repr__")
        return "hostile"

    def __format__(self, spec):
        type(self).touched.append("__format__")
        return "hostile"

    def __bool__(self):
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __hash__(self):
        type(self).touched.append("__hash__")
        return 1

    def __eq__(self, other):
        type(self).touched.append("__eq__")
        return False

    def __lt__(self, other):
        type(self).touched.append("__lt__")
        return False

    def __float__(self):
        type(self).touched.append("__float__")
        return 99.0

    def __int__(self):
        type(self).touched.append("__int__")
        return 99

    def __fspath__(self):
        type(self).touched.append("__fspath__")
        return "hostile"

    def __bytes__(self):
        type(self).touched.append("__bytes__")
        return b"hostile"


class HostileYaraMapping:
    def get(self, key, default=None):
        HostileYaraValue.touched.append("mapping.get")
        return default

    def items(self):
        HostileYaraValue.touched.append("mapping.items")
        return ()

    def values(self):
        HostileYaraValue.touched.append("mapping.values")
        return ()

    def __bool__(self):
        HostileYaraValue.touched.append("mapping.__bool__")
        return True


def test_stage2022_yara_text_path_numeric_boundaries_reject_hostile_values_without_hooks():
    hostile = HostileYaraValue()
    HostileYaraValue.reset()

    assert yara_text(hostile) == ""
    with pytest.raises(TypeError, match="yara_acquisition_owner_invalid"):
        download.acquire_official_archive(hostile, YaraConfig(), "core")
    with pytest.raises(TypeError, match="yara_download_temp_contract_invalid"):
        download_io.unique_temp(hostile, "rules", ".tmp")
    with pytest.raises(TypeError, match="yara_download_state_read_contract_invalid"):
        download_io.load_json_state(hostile)
    assert phase_contracts.yara_rule_count_from_source(hostile) is None
    assert phase_contracts.yara_parallel_group_count(hostile) == 1
    assert zip_scan.yara_zip_worker_count(hostile) == 1

    assert HostileYaraValue.touched == []


def test_stage2022_yara_scan_errors_reject_hostile_paths_without_hooks():
    hostile = HostileYaraValue()
    HostileYaraValue.reset()

    with pytest.raises(FileNotFoundError):
        match.yara_scan(hostile, compiled_rules=None)
    with pytest.raises(FileNotFoundError):
        match.yara_scan_with_optional_zip(hostile, compiled_rules=None)

    assert HostileYaraValue.touched == []


def test_stage2022_yara_sources_have_no_repaired_formatting_or_raw_conversion_patterns():
    old_snippets = (
        'str(candidate or "")',
        'int(getattr(e, "code", 0) or 0)',
        'str(path or "")',
        'int(getattr(r, "status", 200) or 200)',
        'float(timeout or 45)',
        'str(method_body or',
        'Path(str(rule_path))',
        'src = str(source_path or "")',
        'int(member_count or 0)',
        '.items()',
    )
    offenders = {}
    for path in sorted(Path("Virus_Scan/yara").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        present = [snippet for snippet in old_snippets if snippet in source]
        if [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]:
            present.append("f-string")
        if present:
            offenders[str(path)] = present

    assert offenders == {}
