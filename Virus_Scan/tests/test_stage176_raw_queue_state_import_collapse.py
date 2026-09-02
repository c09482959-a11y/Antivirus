from pathlib import Path
from Virus_Scan.scheduler.api import contracts


def test_stage176_raw_queue_state_import_surface_removed():
    assert not Path(__file__).resolve().parents[1].joinpath("scheduler/raw_queue.py").exists()


def test_stage176_raw_queue_keeps_explicit_queue_contracts_available_from_api_contracts():
    assert contracts.RAW_QUEUE_RECOVERABLE_EXCEPTIONS
    assert contracts.RawRangeReadError.__name__ == "RawRangeReadError"
    assert contracts.QueueIdentityScanError.__name__ == "QueueIdentityScanError"
