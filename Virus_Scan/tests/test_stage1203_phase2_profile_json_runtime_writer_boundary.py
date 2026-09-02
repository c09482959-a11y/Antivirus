from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.tests.support.static_inventory import read_python_file


def test_profiles_use_sqlite_authority_without_json_writer_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/persistence.py"))
    api_source = inspect.getsource(profile_api)
    assert "Virus_Scan.core.jsonio" not in source
    assert "Virus_Scan.core.jsonio" not in api_source
    assert "atomic_json_save" not in source
    assert "write_profile_json" not in source
    assert "authoritative_model_state" in source
    assert "write_profile_json" not in profile_api.__all__


def test_superseded_profile_json_writer_and_lkg_owner_are_removed() -> None:
    assert not Path("Virus_Scan/runtime/profile_json_writer.py").exists()
    assert not Path("Virus_Scan/models/profiles/last_known_good.py").exists()


def test_model_related_sources_do_not_import_core_modules() -> None:
    root = Path(__file__).resolve().parents[1]
    checked = []
    for folder in (
        root / "models",
        root / "detection" / "scoring",
        root / "detection" / "models",
        root / "detection" / "profiles",
    ):
        if not folder.exists():
            continue
        for path in sorted(folder.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            checked.append(path)
            assert "from Virus_Scan.core" not in source, str(path.relative_to(root))
            assert "import Virus_Scan.core" not in source, str(path.relative_to(root))
    assert checked


def test_runtime_library_identity_duplicate_module_removed() -> None:
    root = Path(__file__).resolve().parents[1]
    assert not (root / "detection" / "tags" / "heuristics" / "runtime_library_identity.py").exists()
    policy = (root / "detection" / "tags" / "heuristics" / "runtime_library_policy.py").read_text(encoding="utf-8")
    assert "runtime_library_identity" not in policy
    assert "Virus_Scan.contracts.library_baseline" in policy
