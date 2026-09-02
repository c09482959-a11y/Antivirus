from __future__ import annotations

from pathlib import Path

from Virus_Scan.routing.engine_detect import detect_target_engine_context, resolve_scan_engine_hint
from Virus_Scan.runtime.determinism import deterministic_scan_path_inventory, deterministic_json_digest
from Virus_Scan.scheduler.execution.target_collection import collect_target_files


def test_stage361_startup_engine_detection_ignores_generated_runtime_artifacts(tmp_path: Path) -> None:
    (tmp_path / "game").mkdir()
    (tmp_path / "Scan Logs").mkdir()
    (tmp_path / "Temp").mkdir()
    (tmp_path / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    before = detect_target_engine_context(tmp_path)
    before_hint = resolve_scan_engine_hint(tmp_path, "auto")

    # Generated scan outputs must not become engine evidence on replay/restart.
    (tmp_path / "Scan Logs" / "scan_results.json").write_text(
        '{"fake":"UnityPlayer.dll Data/Managed/Assembly-CSharp.dll globalgamemanagers"}',
        encoding="utf-8",
    )
    (tmp_path / "Scan Logs" / "UnityPlayer.dll").write_bytes(b"MZ" + b"unity" * 16)
    (tmp_path / "Temp" / "globalgamemanagers").write_bytes(b"unity" * 16)
    after = detect_target_engine_context(tmp_path)
    after_hint = resolve_scan_engine_hint(tmp_path, "auto")

    assert before_hint[0] == after_hint[0] == "renpy"
    assert deterministic_json_digest(before) == deterministic_json_digest(after)


def test_stage361_scheduler_collection_and_replay_inventory_share_artifact_policy(tmp_path: Path) -> None:
    (tmp_path / "B").mkdir()
    (tmp_path / "a").mkdir()
    (tmp_path / "Scan Logs").mkdir()
    (tmp_path / "Temp").mkdir()
    (tmp_path / "work_queue" / "pending").mkdir(parents=True)
    (tmp_path / "B" / "two.bin").write_bytes(b"2")
    (tmp_path / "a" / "one.bin").write_bytes(b"1")
    (tmp_path / "Scan Logs" / "scan_results.json").write_text("{}", encoding="utf-8")
    (tmp_path / "Temp" / "active.lock").write_text("locked", encoding="utf-8")
    (tmp_path / "work_queue" / "pending" / "job.json").write_text("{}", encoding="utf-8")

    collected = tuple(Path(path).relative_to(tmp_path).as_posix() for path in collect_target_files(str(tmp_path)))
    assert collected == deterministic_scan_path_inventory(tmp_path) == ("a/one.bin", "B/two.bin")


def test_stage361_file_list_collection_preserves_deterministic_unique_scan_targets(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "Scan Logs").mkdir()
    first = tmp_path / "a" / "one.bin"
    second = tmp_path / "a" / "two.bin"
    excluded = tmp_path / "Scan Logs" / "scan_results.json"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    excluded.write_text("{}", encoding="utf-8")
    manifest = tmp_path / "manifest.txt"
    manifest.write_text("\n".join([str(second), str(excluded), str(first), str(first)]), encoding="utf-8")

    collected = tuple(Path(path).name for path in collect_target_files(str(tmp_path), str(manifest)))
    assert collected == ("one.bin", "two.bin")


def test_stage449_host_temp_ancestor_is_not_scan_artifact_exclusion(tmp_path: Path) -> None:
    root = tmp_path / "Temp" / "Star_Knightess_Aura_v1.3.3-windows"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "data").mkdir(parents=True)
    (root / "Temp").mkdir()
    (root / "www" / "js" / "rpg_core.js").write_text("// rpgm", encoding="utf-8")
    (root / "www" / "data" / "System.json").write_text("{}", encoding="utf-8")
    (root / "Temp" / "active.lock").write_text("runtime artifact", encoding="utf-8")

    collected = tuple(Path(path).relative_to(root).as_posix() for path in collect_target_files(str(root)))

    assert collected == ("www/data/System.json", "www/js/rpg_core.js")
    assert deterministic_scan_path_inventory(root) == collected


def test_stage449_engine_detection_uses_files_under_host_temp_ancestor(tmp_path: Path) -> None:
    root = tmp_path / "Temp" / "Star_Knightess_Aura_v1.3.3-windows"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "data").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("// rpgm", encoding="utf-8")
    (root / "www" / "data" / "System.json").write_text("{}", encoding="utf-8")

    assert resolve_scan_engine_hint(root, "auto")[0] == "rpgm"
