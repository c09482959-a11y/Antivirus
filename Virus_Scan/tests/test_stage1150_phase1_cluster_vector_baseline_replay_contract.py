from __future__ import annotations

import inspect

from Virus_Scan.models import clustering


def test_stage1150_online_vector_update_is_replay_deterministic_for_equivalent_inputs() -> None:
    baseline = {
        "count": 1,
        "mean": [2.0, 4.0],
        "m2": [0.0, 0.0],
        "variance": [0.0, 0.0],
        "feature_names": ["a", "b"],
        "updated": 1.0,
    }
    vector = [4.0, "bad"]

    first = clustering.online_vector_update(baseline, vector, ["a", "b"])
    second = clustering.online_vector_update(baseline, vector, ["a", "b"])

    assert first == second
    assert first["updated"] == 2.0
    assert first["updated_source"] == "deterministic_update_count"
    assert first["mean"] == (3.0, 2.0)
    assert first["variance"] == (2.0, 8.0)


def test_stage1150_online_vector_update_does_not_publish_wall_clock_time() -> None:
    source = inspect.getsource(clustering.online_vector_update)

    assert "time.time" not in source
    assert "_cluster_now" not in source
    assert "deterministic_update_count" in source
