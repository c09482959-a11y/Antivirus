from __future__ import annotations

from pathlib import Path

from Virus_Scan.core import jsonio, paths
from Virus_Scan.stress import corpus_builder
from Virus_Scan.utils import tagging


ROOT = Path(__file__).resolve().parents[2]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_stage2083_static_contract_source_repairs_are_present() -> None:
    paths_logging = _source("Virus_Scan/core/init_parts/paths_logging_init.py")
    core_jsonio = _source("Virus_Scan/core/jsonio.py")
    core_paths = _source("Virus_Scan/core/paths.py")
    lifecycle = _source("Virus_Scan/orchestration/lifecycle.py")
    result_schema = _source("Virus_Scan/reporting/result_schema.py")
    scan_cache_result_writer = _source("Virus_Scan/storage/scan_cache_result_writer/scan_cache_result_writer.py")
    reporting_text = _source("Virus_Scan/reporting/evidence_line_text.py")
    utils_tagging = _source("Virus_Scan/utils/tagging.py")
    fast_assets = _source("Virus_Scan/utils/fast_assets.py")
    stress_corpus = _source("Virus_Scan/stress/corpus_builder.py")
    yara_download = _source("Virus_Scan/yara/download.py")
    yara_download_io = _source("Virus_Scan/yara/download_io.py")
    yara_match = _source("Virus_Scan/yara/match.py")
    yara_zip = _source("Virus_Scan/yara/zip_scan.py")

    assert "dict.get(vars(signal), name)" not in paths_logging
    assert "signal_values = vars(signal)" in paths_logging
    assert "return signal_values[name] if name in signal_values else None" in paths_logging
    assert "info: dict[str, object]" in core_jsonio
    assert "def load_scan_cache" not in core_jsonio
    assert "def flush_scan_cache" not in core_jsonio
    assert "dict.get(vars(compiled), 'original_argv0')" not in core_paths
    assert "vars(compiled_state).get('original_argv0')" in core_paths
    assert "for entity in entities:" in core_paths
    assert "parts = set(_path_parts_lower(path_text, as_set=True))" in core_paths
    assert "cli_args.load_scan_cache()" not in lifecycle
    assert "from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle" in lifecycle
    assert "scan_cache_repository().configure(" in lifecycle
    assert "runtime.owner.refresh(run_top_level_init())" in lifecycle
    assert "new_state: Mapping[str, Any] | None" in _source("Virus_Scan/runtime/ownership.py")
    assert "if normalized is None:" not in result_schema
    assert "if normalized is None:" in scan_cache_result_writer
    assert "_MAPPING_PROXY_TYPE: type" in reporting_text
    assert "from typing import Iterator, Mapping, TYPE_CHECKING" in utils_tagging
    assert "def _iter_tag_values(tags: object) -> Iterator[object] | None:" in utils_tagging
    assert "result_tags.extend" in fast_assets
    assert "for item in items:" in stress_corpus
    assert "raise ValueError(\"yara_download_response_missing\")" in yara_download_io
    assert "except (*SCAN_CONTENT_ERRORS, ValueError) as e:" in yara_match
    assert "pending: _queue.Queue[str]" in yara_zip


def test_stage2083_queue_failure_info_accepts_json_safe_non_string_values() -> None:
    info = jsonio._jsonio_queue_failure_info(
        "queue_stage",
        worker_pid=1234,
        attempt=2,
        extra={"nested": {"answer": 42}, "sequence": ["a", 1]},
    )

    assert info["stage"] == "queue_stage"
    assert info["worker_pid"] == 1234
    assert info["attempt"] == 2
    assert info["nested"] == {"answer": 42}
    assert info["sequence"] == ["a", 1]


def test_stage2083_path_runtime_library_parts_are_materialized_as_set() -> None:
    text = "tom rothamel renpy.arguments.bootstrap renpy.import_all path_to_gamedir"

    assert paths.is_known_python_runtime_library_path("game/renpy/bootstrap.py", text) is True


def test_stage2083_iterator_and_sequence_static_repairs_preserve_behavior() -> None:
    assert tagging.canonical_raw_tag_list([" Stage_Hit:Bad Thing ", "encoded powershell"]) == [
        "stage_hit:bad_thing",
        "encoded_powershell",
    ]
    assert tagging.ordered_unique_tags(["A", "a", "A"]) == ["A", "a"]
    assert corpus_builder._stress_text_sequence([".png", "jpg", ""]) == ("png", "jpg")
