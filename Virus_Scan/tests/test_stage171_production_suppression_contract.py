from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _prod_files():
    return python_files_under("Virus_Scan")


def test_no_production_except_pass_suppression():
    offenders = []
    pattern = re.compile(r'except[^:\n]*:\s*(?:\n\s*)?pass\b')
    for path in _prod_files():
        text = read_python_file(path)
        if pattern.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_yara_compat_module_removed():
    assert not (ROOT / 'yara' / 'compat.py').exists()
    loader = (ROOT / 'yara' / 'loader.py').read_text(encoding='utf-8', errors='ignore')
    assert ('Loader' + 'Module') not in loader
