from pathlib import Path

from Virus_Scan.scheduler.workers.metadata import (
    WorkerMetadataAnnotation,
    attach_worker_metadata,
    build_worker_metadata_annotation,
)


def test_worker_metadata_is_worker_owned_and_immutable():
    annotation = build_worker_metadata_annotation(
        scheduler_mode="process-queue-child",
        worker_id="w7",
        worker_pid="123",
    )

    assert isinstance(annotation, WorkerMetadataAnnotation)
    assert annotation.as_dict() == {
        "scheduler_mode": "process-queue-child",
        "worker_id": "w7",
        "worker_pid": 123,
    }


def test_worker_metadata_annotation_preserves_non_mapping_results():
    assert attach_worker_metadata("not-a-worker-result", scheduler_mode="x", worker_id="w") == "not-a-worker-result"


def test_worker_modules_do_not_import_evidence_metadata_boundary():
    workers_dir = Path(__file__).resolve().parents[1] / "scheduler" / "workers"
    offenders = []
    for path in workers_dir.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "scheduler.evidence.worker_metadata" in text:
            offenders.append(path.name)
    assert offenders == []
