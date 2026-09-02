from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file

from pathlib import Path



def test_phase11_only_evidence_owns_scheduler_checkpoint_writer():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    checkpoint_writers = sorted(
        path.relative_to(scheduler_root).as_posix()
        for path in scheduler_root.rglob("*checkpoint_writer.py")
    )
    assert checkpoint_writers == ["evidence/checkpoint_writer.py"]


def test_phase11_no_replay_checkpoint_writer_imports_remain():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    forbidden = "scheduler.replay.checkpoint_writer"
    for path in python_files_under("Virus_Scan"):
        if path == Path(__file__):
            continue
        text = read_python_file(path)
        if forbidden in text:
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []
