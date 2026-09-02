from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_claiming_uses_queue_authority_for_active_return():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert "def _queue_return_active_claim_to_pending" not in source
    assert "return_active_claim_to_pending as _queue_return_active_claim_to_pending" in source


def test_queue_authority_owns_active_to_pending_return():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/authority.py"))
    assert "def return_active_claim_to_pending" in source
    assert "queue active claim return-to-pending returned false" in source
