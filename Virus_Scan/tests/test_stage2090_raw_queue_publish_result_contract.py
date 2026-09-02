from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.ownership.raw_queue_publish import (
    RawQueuePublishDependencies,
    RawQueuePublishResult,
    publish_raw_stage_job,
)
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


def _deps(tmp_path: Path, *, guard: bool = True, live_count: int = 0, live_cap: int = 900, release: bool = True):
    events: list[tuple[str, object]] = []
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    accum = tmp_path / "accum"
    locks = tmp_path / "locks"
    for path in (pending, active, done, failed, accum, locks):
        path.mkdir(parents=True, exist_ok=True)

    def write_json_durable(tmp: Path, final: Path, payload, **_kwargs) -> bool:
        tmp.write_text("{}", encoding="utf-8")
        tmp.replace(final)
        events.append(("payload", payload))
        return True

    return RawQueuePublishDependencies(
        global_raw_dirs=lambda _queue_dir: (pending, active, done, failed, accum, locks),
        global_raw_file_id=lambda file_text: "fid" if file_text else "empty",
        raw_queue_live_count=lambda _queue_dir: live_count,
        runtime_value=lambda name, default: live_cap if name == "RAW_LIVE_HARD_CAP" else default,
        runtime_int=lambda _name, default: default,
        umige_retry_max=lambda _file: 1,
        job_identity=lambda job, _source_name=None: f"raw:{job['file_id']}",
        acquire_identity_lock_decision=lambda _queue_dir, ident: IdentityLockAcquireDecision(True, tmp_path / "identity.lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda lock: events.append(("release", lock)) or IdentityLockReleaseDecision(release, "process_queue_identity_lock_released" if release else "process_queue_identity_lock_release_failed"),
        enqueue_guard=lambda *_args, **_kwargs: guard,
        write_json_durable=write_json_durable,
        identity_index_invalidate=lambda _queue_dir: events.append(("invalidate", "index")),
        hybrid_queue_state_delta=lambda _queue_dir, **delta: events.append(("delta", delta)),
        safe_unlink=lambda path, **_kwargs: events.append(("unlink", Path(path).name)),
        record_suppressed=lambda where, _exc: events.append(("suppressed", where)),
    ), events


def test_stage2090_publish_raw_stage_job_success_returns_replayable_result(tmp_path: Path) -> None:
    deps, events = _deps(tmp_path)

    result = publish_raw_stage_job(tmp_path, {"file": "game.bin", "file_id": "game", "seq": 4, "collector": "raw"}, deps)

    assert type(result) is RawQueuePublishResult
    assert result.published is True
    assert result.reason == "raw_publish_published"
    assert result.pending_name == "raw_game_000004_a00_raw.json"
    assert result.file_id == "game"
    assert result.seq == 4
    assert result.attempt == 0
    assert result.collector == "raw"
    assert result.release_failed is False
    assert (tmp_path / "pending" / result.pending_name).exists()
    assert ("release", tmp_path / "identity.lock") in events


def test_stage2090_publish_raw_stage_job_guard_rejection_is_typed_failure(tmp_path: Path) -> None:
    deps, events = _deps(tmp_path, guard=False)

    result = publish_raw_stage_job(tmp_path, {"file": "game.bin", "file_id": "game", "seq": 4}, deps)

    assert type(result) is RawQueuePublishResult
    assert result.published is False
    assert result.reason == "raw_publish_enqueue_guard_rejected"
    assert result.file_id == "game"
    assert result.seq == 4
    assert not list((tmp_path / "pending").glob("*.json"))
    assert ("suppressed", "raw_publish_enqueue_guard_rejected") in events
    assert ("release", tmp_path / "identity.lock") in events


def test_stage2090_publish_raw_stage_job_live_cap_exhaustion_is_typed_failure(tmp_path: Path) -> None:
    deps, events = _deps(tmp_path, live_count=5, live_cap=5)

    result = publish_raw_stage_job(tmp_path, {"file": "game.bin", "file_id": "game", "seq": 4}, deps)

    assert type(result) is RawQueuePublishResult
    assert result.published is False
    assert result.reason == "raw_publish_live_cap_exhausted"
    assert not list((tmp_path / "pending").glob("*.json"))
    assert ("suppressed", "raw_publish_live_cap_exhausted") in events


def test_stage2090_release_failure_remains_in_typed_publish_result(tmp_path: Path) -> None:
    deps, events = _deps(tmp_path, release=False)

    result = publish_raw_stage_job(tmp_path, {"file": "game.bin", "file_id": "game", "seq": 4}, deps)

    assert result.published is True
    assert result.release_failed is True
    assert ("suppressed", "raw_publish_identity_lock_release_failed") in events
