from pathlib import Path

from Virus_Scan.core.paths import _umige_runtime_base_dir, _umige_runtime_temp_dir
from Virus_Scan.core.jsonio import _umige_unique_json_tmp_path


def test_runtime_temp_dir_is_script_root_temp_not_package_or_root_dump():
    base = Path(_umige_runtime_base_dir()).resolve()
    temp = Path(_umige_runtime_temp_dir()).resolve()
    assert temp == base / "Temp"
    assert temp.exists()
    assert temp.name == "Temp"
    assert "Batch" not in temp.parts or temp.parent.name == "Batch"


def test_atomic_json_tmp_paths_stay_under_runtime_temp_even_for_missing_target():
    temp = Path(_umige_runtime_temp_dir()).resolve()
    tmp_for_none = Path(_umige_unique_json_tmp_path(None)).resolve()
    tmp_for_path = Path(_umige_unique_json_tmp_path(temp.parent / "profiles" / "staged_benign_candidates.json")).resolve()
    assert temp == tmp_for_none.parent
    assert temp == tmp_for_path.parent
    assert tmp_for_none.name.startswith("umige.json.tmp.")
    assert "None.tmp" not in tmp_for_none.name
