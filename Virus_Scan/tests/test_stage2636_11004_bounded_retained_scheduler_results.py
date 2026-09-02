from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.contracts.retained_scan_result import (
    RETAINED_RESULT_COMPRESSION,
    RETAINED_RESULT_CONTRACT_FIELD,
    RETAINED_RESULT_PUBLICATION_FIELD,
    RETAINED_RESULT_REPLAY_FIELD,
    RETAINED_RESULT_SCHEMA,
    build_retained_scan_result,
    retained_parent_replay_payload,
    retained_publication_record,
    validate_retained_scan_result,
)
from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.models.replay.learning import parent_replay_result_learning
from Virus_Scan.models.replay.payload import result_learning_payload
from Virus_Scan.orchestration.direct_audit_projection import project_direct_audit_record
from Virus_Scan.publication.json_finalization.compact_record import compact_result_record
from Virus_Scan.publication.json_finalization.stream_identity import record_with_stream_identity
from Virus_Scan.publication.json_finalization.stream_record import (
    drop_volatile_result_fields,
)
from Virus_Scan.publication.json_finalization.streaming import finalize_scan_results
from Virus_Scan.runtime.api import deterministic_mode_enabled
from Virus_Scan.orchestration.lifecycle import report_results
from Virus_Scan.scheduler.api.final_json import (
    attach_scheduler_final_json_fields,
    enrich_scheduler_final_json_results,
)
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.scheduler.orchestration.result_retention import (
    SchedulerResultRetentionContext,
    build_scheduler_result_retainer,
)
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe as make_queue_json_safe


def _full_result(path: Path) -> dict[str, object]:
    return {
        "file": str(path),
        "classification": "malicious",
        "class": "malicious",
        "verdict": "malicious",
        "score": 75.0,
        "tags": ["file_seen"],
        "effective_stage": "binary",
        "previous_stage": "unknown",
        "scan_integrity": {
            "allow_learning": True,
            "file_failed": False,
            "had_degraded_stage": False,
            "ok": True,
            "failure_count": 0,
        },
        "learn_eligible": True,
        "fast_path": False,
        "container_engine": "other",
        "artifact_engine": "other",
        "declared_extension": ".bin",
        "sniffed_type": "data",
        "effective_analysis_engine": "other",
        "baseline_key": "other::other::.bin::data",
        "extension_baseline": "other/.bin",
        "contextual_baseline": "other::other::.bin",
        "fingerprint_evidence": ["sniffed_type:data"],
        "engine_context": {
            "engine": "other",
            "baseline_key": "other::other::.bin::data",
        },
    }


def _retained_fixture(tmp_path: Path) -> tuple[str, dict[str, object], dict[str, object]]:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"bounded-retention-fixture")
    raw = _full_result(sample)
    retained = build_scheduler_result_retainer(
        scheduler_mode="serial",
        requested_engine="auto",
        yara_enabled=True,
    )(str(sample), raw)
    assert type(retained) is dict
    return str(sample), raw, retained


def test_stage2636_11004_retained_contract_round_trip_is_integrity_bound(tmp_path: Path) -> None:
    _path, _raw, retained = _retained_fixture(tmp_path)

    validated = validate_retained_scan_result(retained)

    assert retained[RETAINED_RESULT_CONTRACT_FIELD]["schema_version"] == RETAINED_RESULT_SCHEMA
    assert validated.publication == retained_publication_record(retained)
    assert validated.replay_payload == retained_parent_replay_payload(retained)
    assert validated.replay_payload == make_json_safe(validated.replay_payload)


def _tamper_base64_payload(value: str) -> str:
    index = max(0, len(value) // 2)
    replacement = "A" if value[index] != "A" else "B"
    return value[:index] + replacement + value[index + 1:]


def test_stage2636_11004_retained_contract_rejects_public_replay_and_metadata_tampering(tmp_path: Path) -> None:
    _path, _raw, retained = _retained_fixture(tmp_path)

    public_tamper = json.loads(json.dumps(retained))
    public_tamper[RETAINED_RESULT_PUBLICATION_FIELD] = _tamper_base64_payload(
        public_tamper[RETAINED_RESULT_PUBLICATION_FIELD]
    )
    with pytest.raises(ValueError, match="publication_compressed_digest_mismatch"):
        validate_retained_scan_result(public_tamper)

    replay_tamper = json.loads(json.dumps(retained))
    replay_tamper[RETAINED_RESULT_REPLAY_FIELD] = _tamper_base64_payload(
        replay_tamper[RETAINED_RESULT_REPLAY_FIELD]
    )
    with pytest.raises(ValueError, match="replay_compressed_digest_mismatch"):
        validate_retained_scan_result(replay_tamper)

    metadata_tamper = json.loads(json.dumps(retained))
    metadata_tamper[RETAINED_RESULT_CONTRACT_FIELD]["publication_bytes"] += 1
    with pytest.raises(ValueError, match="publication_size_mismatch"):
        validate_retained_scan_result(metadata_tamper)




def test_stage2636_11018_retained_contract_is_compressed_and_has_no_v1_reader() -> None:
    publication = {"payload": "repeatable-retained-result-" * 4_000}
    retained = build_retained_scan_result(publication, {"score": 75.0})
    contract = retained[RETAINED_RESULT_CONTRACT_FIELD]

    assert frozenset(retained) == frozenset({
        RETAINED_RESULT_CONTRACT_FIELD,
        RETAINED_RESULT_PUBLICATION_FIELD,
        RETAINED_RESULT_REPLAY_FIELD,
    })
    assert contract["schema_version"] == RETAINED_RESULT_SCHEMA
    assert contract["compression"] == RETAINED_RESULT_COMPRESSION
    assert type(retained[RETAINED_RESULT_PUBLICATION_FIELD]) is str
    assert type(retained[RETAINED_RESULT_REPLAY_FIELD]) is str
    assert contract["publication_compressed_bytes"] < contract["publication_bytes"]
    assert len(json.dumps(retained, separators=(",", ":"))) < contract["publication_bytes"]
    assert retained_publication_record(retained) == publication

    legacy = json.loads(json.dumps(retained))
    legacy[RETAINED_RESULT_CONTRACT_FIELD]["schema_version"] = "scheduler_retained_result_v1"
    with pytest.raises(ValueError, match="retained_result_contract_schema_invalid"):
        validate_retained_scan_result(legacy)


def test_stage2636_11004_retained_contract_enforces_publication_and_replay_bounds() -> None:
    with pytest.raises(ValueError, match="publication_bytes_exceeded"):
        build_retained_scan_result({"payload": "x" * 1_048_576}, None)
    with pytest.raises(ValueError, match="replay_bytes_exceeded"):
        build_retained_scan_result({"ok": True}, {"payload": "x" * 262_144})


def test_stage2636_11004_final_json_strips_private_retention_fields_without_recompaction(tmp_path: Path) -> None:
    path, _raw, retained = _retained_fixture(tmp_path)
    output = tmp_path / "results.json"
    expected = retained_publication_record(retained)

    assert finalize_scan_results(str(output), {path: retained}) is True

    published = json.loads(output.read_text(encoding="utf-8"))[path]
    assert published == expected
    assert RETAINED_RESULT_CONTRACT_FIELD not in published
    assert RETAINED_RESULT_PUBLICATION_FIELD not in published
    assert RETAINED_RESULT_REPLAY_FIELD not in published


def test_stage2636_11004_checkpoint_cache_preserves_validated_private_replay_payload(tmp_path: Path) -> None:
    path, _raw, retained = _retained_fixture(tmp_path)
    cache = PartialCheckpointCache()

    assert cache.observe_terminal(path, retained, make_queue_json_safe) is True
    delta = cache.pending_delta()
    checkpoint_record = delta.items[0][1]

    assert validate_retained_scan_result(checkpoint_record).replay_payload is not None
    assert checkpoint_record[RETAINED_RESULT_CONTRACT_FIELD]["schema_version"] == RETAINED_RESULT_SCHEMA


def test_stage2636_11004_retainer_matches_single_canonical_compaction_pipeline(tmp_path: Path) -> None:
    path, raw, retained = _retained_fixture(tmp_path)
    context = SchedulerResultRetentionContext(
        scheduler_mode="serial",
        requested_engine="auto",
        yara_enabled=True,
    )
    output_path, audited = project_direct_audit_record(path, raw, context.direct_audit_context())
    scheduled = attach_scheduler_final_json_fields(audited)
    identified = record_with_stream_identity(scheduled, output_path)
    final_input = drop_volatile_result_fields(identified) if deterministic_mode_enabled() else identified
    expected = make_json_safe(compact_result_record(final_input))

    assert retained_publication_record(retained) == expected
    assert retained_parent_replay_payload(retained) == make_json_safe(result_learning_payload(raw))


def test_stage2636_11004_parent_replay_consumes_private_payload_without_mutating_retained_record() -> None:
    retained = build_retained_scan_result(
        {"classification": "malicious", "score": 75.0},
        {
            "file_path": "/tmp/stage2636_11004_replay.tmp",
            "integrity": {"allow_learning": False},
            "verdict": "malicious",
            "passive_fast_asset": False,
        },
    )
    before = json.dumps(retained, sort_keys=True, separators=(",", ":"))

    summary = parent_replay_result_learning(retained)

    assert summary["checked"] == 1
    assert json.dumps(retained, sort_keys=True, separators=(",", ":")) == before
    validate_retained_scan_result(retained)


def test_stage2636_11004_bounded_terminal_failure_uses_existing_finalization_path() -> None:
    failure = {
        "classification": "error",
        "class": "error",
        "error": "worker_error_unavailable",
        "scan_duration_seconds": 0.01,
    }
    retained = build_scheduler_result_retainer(
        scheduler_mode="serial",
        requested_engine="auto",
        yara_enabled=False,
    )("sample.bin", failure)

    assert retained is failure
    assert RETAINED_RESULT_CONTRACT_FIELD not in retained


def test_stage2636_11018_internal_enrichment_preserves_compressed_retention(tmp_path: Path) -> None:
    path, _raw, retained = _retained_fixture(tmp_path)

    enriched = enrich_scheduler_final_json_results({path: retained})
    internal = enriched[path]

    assert type(internal) is dict
    assert frozenset(internal) == frozenset({
        RETAINED_RESULT_CONTRACT_FIELD,
        RETAINED_RESULT_PUBLICATION_FIELD,
        RETAINED_RESULT_REPLAY_FIELD,
    })
    assert retained_publication_record(internal) == retained_publication_record(retained)
    assert validate_retained_scan_result(internal).replay_payload is not None


def test_stage2636_11018_cli_report_streams_retained_record_without_private_publication(
    tmp_path: Path,
) -> None:
    path, _raw, retained = _retained_fixture(tmp_path)
    output = tmp_path / "streamed-results.json"
    runtime = SimpleNamespace(parent_cli=False, scan_started_at=0.0)
    args = SimpleNamespace(
        output=str(output),
        scheduler="serial",
        engine="auto",
        dir=str(tmp_path),
    )

    max_score, _elapsed = report_results(
        runtime,
        args,
        {path: retained},
        yara_ok=True,
    )

    published = json.loads(output.read_text(encoding="utf-8"))[Path(path).as_posix()]
    assert max_score == 75.0
    assert published == retained_publication_record(retained)
    assert RETAINED_RESULT_CONTRACT_FIELD not in published
    assert RETAINED_RESULT_PUBLICATION_FIELD not in published
    assert RETAINED_RESULT_REPLAY_FIELD not in published


def test_stage2636_11020_retained_publication_preserves_cache_lineage(tmp_path: Path) -> None:
    sample = tmp_path / "cached.bin"
    sample.write_bytes(b"cached-lineage")
    raw = _full_result(sample)
    raw["cache_hit"] = True
    raw["cache_source"] = "pre_scan_sha256"

    retained = build_scheduler_result_retainer(
        scheduler_mode="process",
        requested_engine="auto",
        yara_enabled=False,
    )(str(sample), raw)
    publication = retained_publication_record(retained)

    assert publication["cache_hit"] is True
    assert publication["cache_source"] == "pre_scan_sha256"
