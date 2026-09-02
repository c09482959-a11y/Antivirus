from Virus_Scan.tests.support.static_inventory import read_python_file

import subprocess
import sys
from pathlib import Path



def test_stage505_main_import_remains_startup_safe_without_runtime_modules() -> None:
    code = """
import sys
import Virus_Scan.main
loaded_modules = vars(sys)['modules']
blocked = [name for name in loaded_modules if name.startswith((
    'Virus_Scan.runtime_main',
    'Virus_Scan.runtime.',
    'Virus_Scan.scheduler',
    'Virus_Scan.reporting',
    'Virus_Scan.yara',
    'Virus_Scan.detection',
    'Virus_Scan.models',
    'Virus_Scan.scanners',
))]
if blocked:
    raise SystemExit('runtime_import_contamination:' + ','.join(sorted(blocked)[:16]))
"""
    completed = subprocess.run([sys.executable, "-c", code], cwd=Path.cwd(), text=True, capture_output=True, timeout=20)
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_stage505_main_has_no_static_runtime_main_import() -> None:
    source = read_python_file(Path("Virus_Scan/main.py"))
    assert "from Virus_Scan import runtime_main" not in source
    assert "import Virus_Scan.runtime_main" not in source
    assert "_runtime_child_entrypoint" not in source
