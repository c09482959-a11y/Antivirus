from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.determinism import deterministic_json_digest, snapshot_runtime_state
from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import (
    deterministic_lifecycle_epoch,
    deterministic_worker_process_name,
)


def test_stage362_inmemory_lifecycle_epoch_is_corpus_owned_not_clock_owned(tmp_path: Path) -> None:
    root_a = tmp_path / "Corpus"
    root_a.mkdir()
    first = root_a / "B.bin"
    second = root_a / "a.bin"
    first.write_bytes(b"b")
    second.write_bytes(b"a")

    ordered_one = [str(first), str(second)]
    ordered_two = [str(second), str(first)]

    epoch_one = deterministic_lifecycle_epoch(root_a, ordered_one)
    epoch_two = deterministic_lifecycle_epoch(root_a, ordered_two)

    assert isinstance(epoch_one, int)
    assert epoch_one == epoch_two
    assert 0 <= epoch_one <= 0x7FFFFFFF


def test_stage362_worker_respawn_names_are_replay_stable_and_sequenced() -> None:
    first = deterministic_worker_process_name(prefix="umige-inmem-r", epoch=0x1234, sequence=1)
    second = deterministic_worker_process_name(prefix="umige-inmem-r", epoch=0x1234, sequence=2)

    assert first == "umige-inmem-r00001234-00001"
    assert second == "umige-inmem-r00001234-00002"
    assert first != second


def test_stage362_runtime_snapshot_digest_ignores_volatile_lifecycle_ordering() -> None:
    left = snapshot_runtime_state(
        queue_state={"workers": ["umige-inmem-r00001234-00002", "umige-inmem-r00001234-00001"]},
        replay_state={"records": {"B.bin": {"verdict": "Clean"}, "a.bin": {"verdict": "Low"}}},
        scheduler_decisions=[
            {"job": "B.bin", "duration": 1.5, "worker_pid": 12345},
            {"job": "a.bin", "duration": 0.1, "worker_pid": 12346},
        ],
    )
    right = snapshot_runtime_state(
        queue_state={"workers": ["umige-inmem-r00001234-00001", "umige-inmem-r00001234-00002"]},
        replay_state={"records": {"a.bin": {"verdict": "Low"}, "B.bin": {"verdict": "Clean"}}},
        scheduler_decisions=[
            {"job": "a.bin", "duration": 99.0, "worker_pid": 99999},
            {"job": "B.bin", "duration": 88.0, "worker_pid": 99998},
        ],
    )

    assert deterministic_json_digest(left.as_stable_payload()) == deterministic_json_digest(right.as_stable_payload())
