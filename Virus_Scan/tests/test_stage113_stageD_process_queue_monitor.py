from Virus_Scan.scheduler.queue import feed_marker as marker

import inspect

from Virus_Scan.scheduler.execution import process_queue_runner as rq
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload


def testrun_process_queue_has_no_dynamic_globals_or_locals_checks():
    src = inspect.getsource(rq.run_process_queue)
    assert "globals()" not in src
    assert "locals()" not in src


def test_stage113_worker_output_payload_rejects_invalid_parent_without_artifact(tmp_path):
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    output_path = blocked_parent / "out.json"

    assert write_worker_output_payload(
        output_path,
        {"x": 1},
    ) is False
    assert not output_path.exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["blocked-parent"]


def test_stage113_worker_output_payload_publishes_canonical_payload(tmp_path):
    output_path = tmp_path / "out.json"

    assert write_worker_output_payload(
        output_path,
        {"x": 1},
    ) is True
    assert output_path.read_text(encoding="utf-8") == '{"x":1}'
    assert sorted(path.name for path in tmp_path.iterdir()) == ["out.json"]


def test_stage113_feed_complete_marker_failure_is_canonical_ingress(tmp_path):

    queue_parent = tmp_path / "not_a_directory"
    queue_parent.write_text("occupied", encoding="utf-8")

    assert marker.mark_process_queue_feed_complete(queue_parent) is False
