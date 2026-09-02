from pathlib import Path


from Virus_Scan.core.paths import _umige_runtime_base_dir, _umige_runtime_temp_dir
from Virus_Scan.core.jsonio import _umige_json_lock_path
from Virus_Scan.core.paths import _umige_runtime_base_dir
from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.runtime.resource_paths import work_queue_dir
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs
from Virus_Scan.scheduler.runtime.writable_paths import create_process_queue_runtime_dirs
from Virus_Scan.storage import DatabasePaths

def test_jsonsave_lock_paths_are_under_runtime_temp():

    root = Path(_umige_runtime_base_dir()).resolve()
    temp = Path(_umige_runtime_temp_dir()).resolve()

    lock_for_none = Path(_umige_json_lock_path(None)).resolve()
    lock_for_profile = Path(_umige_json_lock_path(root / "profiles" / "x.json")).resolve()

    assert temp in lock_for_none.parents
    assert temp in lock_for_profile.parents
    assert lock_for_none.parent == temp
    assert lock_for_profile.parent == temp
    assert lock_for_none.name != "None.jsonsave.lock"


def test_atomic_json_save_refuses_missing_destination_instead_of_root_none(tmp_path):

    root = Path(_umige_runtime_base_dir()).resolve()
    for bad in (None, "", "None", "null"):
        try:
            atomic_json_save(bad, {"bad": True}, backups=0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"atomic_json_save accepted bad path {bad!r}")

    assert not (root / "None.jsonsave.lock").exists()
    assert not (root / "None.tmp").exists()


def test_sqlite_database_paths_refuse_stale_none_instead_of_root_write():
    root = Path(_umige_runtime_base_dir()).resolve()
    for bad in (None, "", "None", "null"):
        try:
            DatabasePaths.from_profiles_dir(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"database path accepted bad profiles root {bad!r}")
    assert not (root / "model_state.sqlite3").exists()


def test_scheduler_queue_runtime_dirs_stay_under_runtime_temp_work_queue():

    temp = Path(_umige_runtime_temp_dir()).resolve()
    queue_root = work_queue_dir().resolve()
    dirs = create_process_queue_runtime_dirs(
        runtime_temp_dir=lambda: temp,
        runtime_work_queue_dir=lambda: queue_root,
    )

    assert queue_root == temp / "work_queue"
    assert dirs.run_dir.parent == queue_root
    assert dirs.queue_dir == dirs.run_dir / "queue"
    for path in queue_job_dirs(dirs.queue_dir) + (dirs.queue_dir / "accumulators", dirs.queue_dir / "locks"):
        resolved = path.resolve()
        assert queue_root in resolved.parents
        assert temp in resolved.parents
