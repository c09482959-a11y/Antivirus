import json
from pathlib import Path

from Virus_Scan.scheduler.queue.claim_meta import read_claim_meta, remove_claim_meta


def test_read_claim_meta_absent_returns_empty(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir()
    events = []
    result = read_claim_meta(
        claim,
        claim_meta_path=lambda p: Path(str(p) + ".claim"),
        now=lambda: 10.0,
        report=lambda *a, **kw: events.append((a, kw)),
    )
    assert result == {}
    assert events == []


def test_read_claim_meta_corrupt_reports_and_quarantines(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir()
    meta = Path(str(claim) + ".claim")
    meta.write_text("{not-json", encoding="utf-8")
    events = []
    result = read_claim_meta(
        claim,
        claim_meta_path=lambda p: Path(str(p) + ".claim"),
        now=lambda: 20.0,
        report=lambda where, exc, **kw: events.append((where, type(exc).__name__, kw)),
    )
    assert result["queue_info"]["claim_meta_corrupt"] is True
    assert result["queue_info"]["progress_marker"] == "claim_meta_corrupt_recovery"
    assert not meta.exists()
    assert list(claim.parent.glob("job.json.claim.corrupt.*"))
    assert any(e[0] == "queue_claim_meta_corrupt" for e in events)


def test_remove_claim_meta_reports_failure(tmp_path):
    events = []
    result = remove_claim_meta(
        tmp_path / "job.json",
        claim_meta_path=lambda p: Path(str(p) + ".claim"),
        safe_unlink=lambda p, **kw: (_ for _ in ()).throw(OSError("locked")),
        report=lambda where, exc: events.append((where, str(exc))),
    )
    assert result is False
    assert events == [("queue_claim_meta_cleanup_failed", "locked")]
