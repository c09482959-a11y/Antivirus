from Virus_Scan.scheduler.queue.identity import invalidate_identity_index


def test_stage645_queue_identity_invalidation_deletes_queue_index_entries(tmp_path) -> None:
    index_dir = tmp_path / "identity_index"
    index_dir.mkdir()
    entry = index_dir / "entry.json"
    entry.write_text('{"time": 0, "ids": ["sample"]}', encoding="utf-8")

    assert invalidate_identity_index(tmp_path) is True

    assert not entry.exists()
