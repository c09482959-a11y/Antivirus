"""Stage2217 scheduler raw queue wrapper/domain-adapter proofs."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.scheduler_json_durable import RawQueueJsonDependencies
from Virus_Scan.scheduler.queue.raw_queue_accumulator import RawAccumulatorDependencies
from Virus_Scan.scheduler.queue import raw_accumulator_store as raw_store
from Virus_Scan.scheduler.ownership import raw_queue_publish_boundary as raw_boundary


class HostileValue:
    def __str__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("raw queue boundary called __str__")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("raw queue boundary called __repr__")

    def __bool__(self) -> bool:  # pragma: no cover - must never be reached
        raise AssertionError("raw queue boundary called __bool__")

    def __iter__(self):  # pragma: no cover - must never be reached
        raise AssertionError("raw queue boundary called __iter__")


def test_stage2217_raw_publish_field_adapters_bind_replayable_reason_codes_without_value_hooks() -> None:
    hostile = HostileValue()

    assert raw_boundary.raw_publish_text(
        None,
        missing_reason="raw_publish_custom_missing",
        unsupported_reason="raw_publish_custom_rejected",
    ) == ("", "raw_publish_custom_missing")
    assert raw_boundary.raw_publish_text(
        hostile,
        missing_reason="raw_publish_custom_missing",
        unsupported_reason="raw_publish_custom_rejected",
    ) == ("", "raw_publish_custom_rejected")

    assert raw_boundary.raw_publish_file_text({"file": hostile}) == (
        "",
        "raw_publish_file_rejected",
    )
    assert raw_boundary.raw_publish_file_text({}) == ("", "raw_publish_file_missing")
    assert raw_boundary.raw_publish_generated_file_id(hostile) == (
        "",
        "raw_publish_generated_file_id_rejected",
    )
    assert raw_boundary.raw_publish_generated_file_id(None) == (
        "",
        "raw_publish_generated_file_id_missing",
    )
    assert raw_boundary.raw_publish_existing_file_id({"file_id": hostile}) == (
        "",
        "raw_publish_file_id_rejected",
    )
    assert raw_boundary.raw_publish_existing_file_id({}) == ("", "raw_publish_file_id_missing")


def test_stage2217_raw_publish_numeric_adapters_bind_raw_queue_defaults_and_reason_codes() -> None:
    hostile = HostileValue()

    assert raw_boundary.raw_publish_sequence({"seq": True}) == (0, "raw_publish_seq_parse_failed")
    assert raw_boundary.raw_publish_sequence({"seq": -1}) == (0, "raw_publish_seq_parse_failed")
    assert raw_boundary.raw_publish_sequence({"seq": 7}) == (7, "")
    assert raw_boundary.raw_publish_sequence({}) == (0, "")

    assert raw_boundary.raw_publish_live_hard_cap(hostile) == (900, "raw_publish_live_cap_rejected")
    assert raw_boundary.raw_publish_live_hard_cap(float("inf")) == (
        900,
        "raw_publish_live_cap_non_finite",
    )
    assert raw_boundary.raw_publish_live_hard_cap(11) == (11, "")


def test_stage2217_raw_accumulator_store_adapters_inject_queue_owned_dependencies(tmp_path: Path) -> None:
    json_deps = raw_store.raw_json_dependencies()
    assert isinstance(json_deps, RawQueueJsonDependencies)
    assert json_deps.recoverable_exceptions == RAW_QUEUE_RECOVERABLE_EXCEPTIONS

    raw_deps = raw_store.raw_accumulator_dependencies()
    assert isinstance(raw_deps, RawAccumulatorDependencies)
    assert raw_deps.global_raw_dirs is raw_store.global_raw_dirs
    assert raw_deps.write_json_durable is raw_store.write_raw_json_durable
    assert raw_deps.recoverable_exceptions == RAW_QUEUE_RECOVERABLE_EXCEPTIONS

    store = raw_store.RawAccumulatorStore(tmp_path, "stage2217")
    assert isinstance(store.deps, RawAccumulatorDependencies)
    assert store.deps.global_raw_dirs is raw_store.global_raw_dirs
    assert store.file_id == "stage2217"

    normalized = raw_store.RawAccumulatorStore.normalize_counts(
        {"expected": 1, "completed": 1, "failed": 0, "tags": [], "errors": []}
    )
    assert normalized["expected"] == 1
    assert raw_store.RawAccumulatorStore.is_complete(normalized) is True


def test_stage2217_raw_accumulator_json_adapter_uses_canonical_durability_owner(tmp_path: Path) -> None:
    events: list[tuple[str, object]] = []

    def make_json_safe(payload: object) -> object:
        events.append(("make_json_safe", payload))
        return payload

    def validate_persistent_record_semantics(payload: object, *, context: object) -> None:
        events.append(("validate", context))

    def verify_persistent_json_file(path: object, *, expected: object, context: object, require_match: bool) -> None:
        events.append(("verify", context))

    def runtime_value(*_args: object, **_kwargs: object) -> object:
        events.append(("runtime_value", "unexpected"))
        return None

    def record_suppressed(where: str, exc: BaseException) -> None:
        events.append(("suppressed", where))

    deps = RawQueueJsonDependencies(
        make_json_safe=make_json_safe,
        validate_persistent_record_semantics=validate_persistent_record_semantics,
        verify_persistent_json_file=verify_persistent_json_file,
        runtime_value=runtime_value,
        record_suppressed=record_suppressed,
    )

    assert raw_store.write_raw_json_durable(
        tmp_path / "record.tmp",
        tmp_path / "record.json",
        {"ok": True},
        log_context="stage2217_raw_json_adapter",
        deps=deps,
    ) is True
    assert ("make_json_safe", {"ok": True}) in events
    assert ("validate", "stage2217_raw_json_adapter") in events
    assert any(name == "verify" for name, _value in events)
    assert (tmp_path / "record.json").is_file()


def test_stage2217_raw_queue_adapter_source_boundaries_are_retained_domain_adapters() -> None:
    raw_publish_source = Path(raw_boundary.__file__).read_text(encoding="utf-8")
    raw_accum_source = Path(raw_store.__file__).read_text(encoding="utf-8")

    for reason in (
        "raw_publish_file_missing",
        "raw_publish_file_rejected",
        "raw_publish_generated_file_id_missing",
        "raw_publish_generated_file_id_rejected",
        "raw_publish_file_id_missing",
        "raw_publish_file_id_rejected",
        "raw_publish_seq_parse_failed",
        "raw_publish_seq_non_finite",
        "raw_publish_live_cap_rejected",
        "raw_publish_live_cap_non_finite",
    ):
        assert reason in raw_publish_source

    publish_tree = ast.parse(raw_publish_source)
    publish_functions = {
        node.name
        for node in publish_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    assert {
        "raw_publish_text",
        "raw_publish_file_text",
        "raw_publish_generated_file_id",
        "raw_publish_existing_file_id",
        "raw_publish_sequence",
        "raw_publish_live_hard_cap",
    } <= publish_functions

    accum_tree = ast.parse(raw_accum_source)
    accum_functions = {
        node.name
        for node in accum_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    assert {"raw_json_dependencies", "write_raw_json_durable", "global_raw_dirs", "raw_accumulator_dependencies"} <= accum_functions
    assert "class RawAccumulatorStore(_CanonicalRawAccumulatorStore):" in raw_accum_source
    assert "class GlobalRawAccumLock(_CanonicalGlobalRawAccumLock):" in raw_accum_source
