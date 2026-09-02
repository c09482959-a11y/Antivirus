from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace, read_json_file
from Virus_Scan.scheduler.execution.raw_work_executor import execute_raw_callable
from Virus_Scan.detection.scoring.stress.scoring_framework import IterationScoreProfile, ScorePenalty, SCORE_FIELDS


def test_stage77_queue_json_replace_uses_unique_temps_under_concurrency(tmp_path):
    target = tmp_path / "shared_queue_state.json"

    def write_one(i: int) -> bool:
        return bool(_queue_write_json_replace(
            target,
            {"iteration": i, "payload": [i, str(i)]},
            verify=True,
            log_context="stage77_concurrent_replace",
        ))

    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(write_one, range(200)))

    assert all(results)
    payload = read_json_file(target, default=None)
    assert isinstance(payload, dict)
    assert "iteration" in payload
    assert isinstance(payload.get("payload"), list)


def test_stage77_raw_executor_preserves_error_envelope_without_raising():
    env = execute_raw_callable("sample.bin", "raw", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert not env.ok
    assert "RuntimeError" in str(env.error)
    assert env.file == "sample.bin"
    assert env.collector == "raw"


def test_stage77_scoring_profile_rejects_unknown_score_field():
    profile = IterationScoreProfile()
    assert all(field in profile.as_record_fields()["scores"] for field in SCORE_FIELDS)
    try:
        profile.penalize(ScorePenalty(
            field="not_a_real_score",
            penalty=1,
            subsystem="test",
            reason="invalid field",
            trigger="stage77",
        ))
    except KeyError:
        pass
    else:
        raise AssertionError("unknown score field was silently accepted")
