from Virus_Scan.tests.support.static_inventory import read_python_file

from copy import deepcopy
from pathlib import Path

from Virus_Scan.models import retention



def test_stage1340_retention_owner_does_not_import_live_clock_for_model_metadata():
    source = read_python_file(Path("Virus_Scan/models/retention.py"))

    assert "import time" not in source
    assert "time.time()" not in source


def test_stage1340_extension_retention_marker_is_derived_from_model_state():
    baseline = {
        "files": 7,
        "timeline_baseline": {
            "sample_count": 3,
            "last_updated": 42.0,
            "event_counts": {"z": 1},
            "transition_counts": {},
            "behavior_counts": {},
            "behavior_transition_counts": {},
        },
        "vector_baseline": {"count": 5, "vectors": [[1.0]], "samples": ["drop-me"]},
        "learning_gate": {"accepted": 2, "rejected": 1},
    }

    first = retention.prune_extension_baseline_for_retention(deepcopy(baseline))
    second = retention.prune_extension_baseline_for_retention(deepcopy(baseline))

    assert first["retention"]["last_pruned"] == 42.0
    assert second["retention"]["last_pruned"] == 42.0
    assert first == second


def test_stage1340_staged_candidate_prune_marker_is_derived_from_retained_candidates():
    store = {
        "candidates": {
            f"candidate-{i}": {
                "clean_observations": 1,
                "last_seen": float(i),
                "first_seen": float(i) - 1.0,
                "promoted": False,
            }
            for i in range(retention.MAX_STAGED_BENIGN_CANDIDATES + 2)
        }
    }

    returned = retention.prune_staged_benign_store(deepcopy(store))
    retained_last_seen = max(
        float(candidate["last_seen"])
        for candidate in returned["candidates"].values()
    )

    assert returned["retention"]["staged_candidates_pruned_at"] == retained_last_seen
    assert retained_last_seen == float(retention.MAX_STAGED_BENIGN_CANDIDATES + 1)
