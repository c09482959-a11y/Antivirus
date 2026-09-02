from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.core.jsonio import _umige_unique_json_tmp_path, atomic_json_save


def test_stage1473_atomic_json_temp_path_uses_destination_directory(tmp_path: Path) -> None:
    target = tmp_path / "profile.json"

    tmp_path_for_target = Path(_umige_unique_json_tmp_path(str(target)))

    assert tmp_path_for_target.parent == tmp_path
    assert tmp_path_for_target.name.startswith("profile.json.tmp.")


def test_stage1473_atomic_json_save_replaces_destination_from_same_volume(tmp_path: Path) -> None:
    target = tmp_path / "final_report.json"

    assert atomic_json_save(str(target), {"status": "first"}, backups=1) is True
    assert atomic_json_save(str(target), {"status": "second"}, backups=1) is True

    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "second"}
    assert json.loads((tmp_path / "final_report.json.bak1").read_text(encoding="utf-8")) == {"status": "first"}
