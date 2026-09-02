from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_identity import collect_existing_identities
from Virus_Scan.scheduler.queue.raw_queue_progress import file_has_recent_raw_owner_progress


def test_collect_existing_identities_uses_file_results(tmp_path):
    q = tmp_path
    for name in ("pending", "active", "done", "failed", "quarantine", "file_results"):
        (q / name).mkdir()
    (q / "file_results" / "abc.result.json").write_text('{"file":"/tmp/game.exe"}', encoding="utf-8")

    seen = collect_existing_identities(
        q,
        states=("file_results",),
        job_dirs=lambda qd: (qd / "pending", qd / "active", qd / "done", qd / "failed"),
        quarantine_dir=lambda qd: qd / "quarantine",
        file_results_dir=lambda qd: qd / "file_results",
        safe_listdir=lambda d: list(Path(d).iterdir()),
        is_job_json_name=lambda name: str(name).endswith(".json"),
        read_json=lambda p, default=None: {"file": "/tmp/game.exe"},
        job_identity=lambda job, name=None: "file:" + job["file"],
    )
    assert seen == {"file:/tmp/game.exe"}


def test_raw_owner_progress_reports_recent_accumulator(tmp_path):
    class Store:
        def __init__(self, queue_dir, file_id):
            self.path = tmp_path / "accum.json"
        def load(self):
            self.path.write_text("{}", encoding="utf-8")
            return {"file_id": "fid", "expected": 2, "completed": 1, "updated_at": 100.0}
        @staticmethod
        def is_complete(data):
            return False

    reported = []
    info = file_has_recent_raw_owner_progress(
        tmp_path,
        "sample.bin",
        quiet_sec=30,
        global_raw_file_id=lambda path: "fid",
        accumulator_store_cls=Store,
        queue_now=lambda: 110.0,
        raw_stage_progress_recent=lambda queue_dir, quiet_sec: False,
        report=lambda *args, **kwargs: reported.append((args, kwargs)),
    )
    assert info["has_accumulator"] is True
    assert info["recent"] is True
    assert info["age"] == 10.0
    assert reported == []
