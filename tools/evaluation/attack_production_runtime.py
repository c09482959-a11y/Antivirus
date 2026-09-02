"""Raw-file runtime support for the single ATT&CK corpus evaluator."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path, PosixPath, WindowsPath
import shutil
import subprocess
import sys
from time import monotonic_ns, sleep

from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_PARTITIONS,
    AttackEvaluationCorpusManifest,
    AttackEvaluationSample,
)
from Virus_Scan.detection.attack.integrity import file_integrity
from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.publication.api import verify_report_manifest
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.storage.cache_repository import ScanCacheRepository
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleOwner
from Virus_Scan.yara.config import YaraConfig, config_toml, load_config
from Virus_Scan.yara.control_files import ensure_generated_controls

_PATH_TYPES = (PosixPath, WindowsPath)
YARA_RUNTIME_MODES = ("disabled", "core", "extended")
SAMPLE_ORDERS = ("ascending", "descending")
ALL_PARTITIONS = "all_partitions"
_YARA_SOURCE_FILENAMES = {
    "core": "yara-forge-rules-core.zip",
    "extended": "yara-forge-rules-extended.zip",
}


def _completed_scan_log_generation(run_root: Path) -> Path:
    scan_logs_root = (run_root / "Scan Logs").absolute()
    latest_path = scan_logs_root / "latest.json"
    if path_contains_filesystem_alias(latest_path) or not latest_path.is_file():
        raise RuntimeError("attack_production_scan_log_latest_missing")
    if latest_path.stat().st_size > 65_536:
        raise RuntimeError("attack_production_scan_log_latest_oversized")
    try:
        payload = json.loads(latest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("attack_production_scan_log_latest_invalid") from exc
    if type(payload) is not dict or payload.get("completion_state") != "complete":
        raise RuntimeError("attack_production_scan_log_latest_invalid")
    scan_id = payload.get("scan_id")
    run_path_value = payload.get("run_path")
    manifest_sha256 = payload.get("manifest_file_sha256")
    if (
        type(scan_id) is not str or not scan_id
        or type(run_path_value) is not str or not run_path_value
        or type(manifest_sha256) is not str or len(manifest_sha256) != 64
    ):
        raise RuntimeError("attack_production_scan_log_latest_invalid")
    generation = Path(run_path_value).absolute()
    runs_root = (scan_logs_root / "runs").absolute()
    try:
        relative = generation.relative_to(runs_root)
    except ValueError as exc:
        raise RuntimeError("attack_production_scan_log_generation_invalid") from exc
    if (
        len(relative.parts) != 1
        or relative.name != scan_id
        or path_contains_filesystem_alias(generation)
        or not generation.is_dir()
    ):
        raise RuntimeError("attack_production_scan_log_generation_invalid")
    manifest = verify_report_manifest(generation)
    manifest_path = generation / "report_manifest.json"
    if manifest.scan_id != scan_id or file_integrity(manifest_path)[1] != manifest_sha256:
        raise RuntimeError("attack_production_scan_log_manifest_mismatch")
    return generation


@dataclass(frozen=True, slots=True)
class AttackProductionResourceMetrics:
    elapsed_ns: int
    peak_process_tree_rss_bytes: int
    peak_process_tree_descriptor_count: int
    peak_run_root_bytes: int
    output_bytes: int
    yara_metric_line_count: int
    yara_engine_call_count: int
    yara_unique_scan_pass_count: int
    yara_latency_min_ns: int
    yara_latency_median_ns: int
    yara_latency_p95_ns: int
    yara_latency_p99_ns: int
    yara_latency_max_ns: int
    yara_total_match_count: int
    yara_retained_match_count: int
    yara_duplicate_match_count: int
    yara_truncated_match_count: int
    yara_status_counts: tuple[tuple[str, int], ...]
    scan_cache_hit_count: int = 0
    scan_cache_miss_count: int = 0
    scan_cache_database_bytes: int = 0
    scan_cache_wal_bytes: int = 0
    scan_cache_content_row_count: int = 0
    scan_cache_alias_row_count: int = 0
    scan_cache_fast_fingerprint_row_count: int = 0
    scan_cache_execution_identity_row_count: int = 0
    scan_cache_semantic_result_row_count: int = 0
    scan_cache_parse_result_row_count: int = 0
    scan_cache_static_operation_row_count: int = 0
    scan_cache_scanner_observation_row_count: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "elapsed_ns", "peak_process_tree_rss_bytes",
            "peak_process_tree_descriptor_count", "peak_run_root_bytes",
            "output_bytes", "yara_metric_line_count", "yara_engine_call_count",
            "yara_unique_scan_pass_count", "yara_latency_min_ns",
            "yara_latency_median_ns", "yara_latency_p95_ns",
            "yara_latency_p99_ns", "yara_latency_max_ns",
            "yara_total_match_count", "yara_retained_match_count",
            "yara_duplicate_match_count", "yara_truncated_match_count",
            "scan_cache_hit_count", "scan_cache_miss_count",
            "scan_cache_database_bytes", "scan_cache_wal_bytes",
            "scan_cache_content_row_count", "scan_cache_alias_row_count",
            "scan_cache_fast_fingerprint_row_count",
            "scan_cache_execution_identity_row_count",
            "scan_cache_semantic_result_row_count",
            "scan_cache_parse_result_row_count",
            "scan_cache_static_operation_row_count",
            "scan_cache_scanner_observation_row_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise TypeError("attack_production_resource_metric_invalid:" + field_name)
        if type(self.yara_status_counts) is not tuple:
            raise TypeError("attack_production_yara_status_counts_invalid")
        previous = ""
        for item in self.yara_status_counts:
            if (
                type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str or not item[0]
                or type(item[1]) is not int or item[1] < 1
                or item[0] <= previous
            ):
                raise TypeError("attack_production_yara_status_counts_invalid")
            previous = item[0]
        if not (
            self.yara_latency_min_ns <= self.yara_latency_median_ns
            <= self.yara_latency_p95_ns <= self.yara_latency_p99_ns
            <= self.yara_latency_max_ns
        ):
            raise ValueError("attack_production_yara_latency_order_invalid")
        if self.yara_engine_call_count > self.yara_metric_line_count:
            raise ValueError("attack_production_yara_metric_count_invalid")
        if self.yara_unique_scan_pass_count > self.yara_engine_call_count:
            raise ValueError("attack_production_yara_scan_pass_count_invalid")

    def to_record(self) -> dict[str, object]:
        return {
            "elapsed_ns": self.elapsed_ns,
            "output_bytes": self.output_bytes,
            "peak_process_tree_descriptor_count": self.peak_process_tree_descriptor_count,
            "peak_process_tree_rss_bytes": self.peak_process_tree_rss_bytes,
            "peak_run_root_bytes": self.peak_run_root_bytes,
            "scan_cache_alias_row_count": self.scan_cache_alias_row_count,
            "scan_cache_content_row_count": self.scan_cache_content_row_count,
            "scan_cache_database_bytes": self.scan_cache_database_bytes,
            "scan_cache_execution_identity_row_count": self.scan_cache_execution_identity_row_count,
            "scan_cache_fast_fingerprint_row_count": self.scan_cache_fast_fingerprint_row_count,
            "scan_cache_hit_count": self.scan_cache_hit_count,
            "scan_cache_miss_count": self.scan_cache_miss_count,
            "scan_cache_parse_result_row_count": self.scan_cache_parse_result_row_count,
            "scan_cache_scanner_observation_row_count": self.scan_cache_scanner_observation_row_count,
            "scan_cache_semantic_result_row_count": self.scan_cache_semantic_result_row_count,
            "scan_cache_static_operation_row_count": self.scan_cache_static_operation_row_count,
            "scan_cache_wal_bytes": self.scan_cache_wal_bytes,
            "yara_duplicate_match_count": self.yara_duplicate_match_count,
            "yara_engine_call_count": self.yara_engine_call_count,
            "yara_latency_max_ns": self.yara_latency_max_ns,
            "yara_latency_median_ns": self.yara_latency_median_ns,
            "yara_latency_min_ns": self.yara_latency_min_ns,
            "yara_latency_p95_ns": self.yara_latency_p95_ns,
            "yara_latency_p99_ns": self.yara_latency_p99_ns,
            "yara_metric_line_count": self.yara_metric_line_count,
            "yara_retained_match_count": self.yara_retained_match_count,
            "yara_status_counts": self.yara_status_counts,
            "yara_total_match_count": self.yara_total_match_count,
            "yara_truncated_match_count": self.yara_truncated_match_count,
            "yara_unique_scan_pass_count": self.yara_unique_scan_pass_count,
        }


def empty_production_resource_metrics() -> AttackProductionResourceMetrics:
    return AttackProductionResourceMetrics(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (),
    )


@dataclass(frozen=True, slots=True)
class AttackProductionRuntimeOutput:
    """Filesystem evidence emitted by one isolated canonical runtime execution."""

    selected_samples: tuple[AttackEvaluationSample, ...]
    run_root: Path
    output_path: Path
    stdout_path: Path
    stderr_path: Path
    bundle_git_blob_sha1: str
    bundle_sha256: str
    returncode: int
    command: tuple[str, ...]
    yara_mode: str
    yara_source_path: str
    yara_source_sha256: str
    resource_metrics: AttackProductionResourceMetrics
    state_root: Path = Path()
    scan_cache_enabled: bool = False
    hash_seed: int = 0
    sample_order: str = "ascending"

    def __post_init__(self) -> None:
        if type(self.scan_cache_enabled) is not bool:
            raise TypeError("attack_production_scan_cache_enabled_invalid")
        if type(self.hash_seed) is not int or type(self.hash_seed) is bool:
            raise TypeError("attack_production_hash_seed_invalid")
        if self.hash_seed < 0 or self.hash_seed > 4_294_967_295:
            raise ValueError("attack_production_hash_seed_invalid")
        if type(self.sample_order) is not str or self.sample_order not in SAMPLE_ORDERS:
            raise ValueError("attack_production_sample_order_invalid")
        if type(self.state_root) not in _PATH_TYPES:
            raise TypeError("attack_production_state_root_invalid")


def select_production_samples(
    corpus: AttackEvaluationCorpusManifest,
    *,
    partition: str,
    limit: int,
) -> tuple[AttackEvaluationSample, ...]:
    if type(corpus) is not AttackEvaluationCorpusManifest:
        raise TypeError("attack_production_corpus_invalid")
    if (
        type(partition) is not str
        or partition not in (*ATTACK_EVALUATION_PARTITIONS, ALL_PARTITIONS)
    ):
        raise ValueError("attack_production_partition_invalid")
    bounded = exact_bounded_nonnegative_int(limit, "attack_production_limit_invalid", maximum=10_000)
    if bounded < 1:
        raise ValueError("attack_production_limit_invalid")
    matching = (
        corpus.samples
        if partition == ALL_PARTITIONS
        else tuple(sample for sample in corpus.samples if sample.partition == partition)
    )
    malware = tuple(sorted(
        (sample for sample in matching if sample.malware_class == "malware"),
        key=lambda sample: sample.sample_id,
    ))
    controls = tuple(sorted(
        (sample for sample in matching if sample.malware_class == "control"),
        key=lambda sample: sample.sample_id,
    ))
    malware_count = min(len(malware), (bounded + 1) // 2)
    control_count = min(len(controls), bounded // 2)
    selected = tuple(sorted(
        malware[:malware_count] + controls[:control_count],
        key=lambda sample: sample.sample_id,
    ))
    if len(selected) != bounded:
        raise ValueError("attack_production_partition_capacity_invalid")
    return selected


def _isolated_environment(repository_root: Path, state_root: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("UMIGE_") and key != "PYTEST_CURRENT_TEST"
    }
    current = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = (
        str(repository_root)
        if not current
        else os.pathsep.join((str(repository_root), current))
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["UMIGE_BASE_DIR"] = str(state_root)
    return environment


def _runtime_environment(
    repository_root: Path,
    state_root: Path,
    *,
    scheduler: str,
    yara_mode: str,
    hash_seed: int,
) -> dict[str, str]:
    """Return the isolated runtime environment with explicit diagnostic policy."""
    if type(scheduler) is not str or scheduler not in {"serial", "process"}:
        raise ValueError("attack_production_scheduler_invalid")
    mode = _validated_yara_mode(yara_mode)
    seed = exact_bounded_nonnegative_int(
        hash_seed, "attack_production_hash_seed_invalid", maximum=4_294_967_295,
    )
    environment = _isolated_environment(repository_root, state_root)
    environment["PYTHONHASHSEED"] = str(seed)
    if scheduler == "process" and mode != "disabled":
        environment["UMIGE_YARA_SCAN_METRIC_LOGGING"] = "1"
    return environment


def _prepare_run_root(
    run_root: Path,
    *,
    state_root: Path,
    reuse_state: bool,
) -> tuple[Path, Path]:
    if type(run_root) not in _PATH_TYPES:
        raise TypeError("attack_production_run_root_invalid")
    if run_root.exists():
        raise ValueError("attack_production_run_root_not_clean")
    if type(state_root) not in _PATH_TYPES:
        raise TypeError("attack_production_state_root_invalid")
    if type(reuse_state) is not bool:
        raise TypeError("attack_production_reuse_state_invalid")
    if path_contains_filesystem_alias(run_root.parent):
        raise ValueError("attack_production_run_root_invalid")
    if state_root.exists():
        if not reuse_state:
            raise ValueError("attack_production_state_root_not_clean")
        if path_contains_filesystem_alias(state_root) or not state_root.is_dir():
            raise ValueError("attack_production_state_root_invalid")
    elif reuse_state:
        raise ValueError("attack_production_state_root_unavailable")
    elif path_contains_filesystem_alias(state_root.parent):
        raise ValueError("attack_production_state_root_invalid")
    run_root.mkdir(parents=True)
    cache_root = state_root / "Mitre"
    cache_root.mkdir(parents=True, exist_ok=True)
    return state_root, cache_root


def _prepare_bundle(bundle_path: Path, cache_root: Path) -> tuple[str, str, Path]:
    if type(bundle_path) not in _PATH_TYPES:
        raise TypeError("attack_production_bundle_path_invalid")
    if path_contains_filesystem_alias(bundle_path) or not bundle_path.is_file():
        raise ValueError("attack_production_bundle_file_invalid")
    git_blob_sha1, local_sha256, size = file_integrity(bundle_path)
    if size < 1:
        raise ValueError("attack_production_bundle_file_invalid")
    target = cache_root / ("enterprise-attack-v" + git_blob_sha1 + ".json")
    shutil.copyfile(bundle_path, target)
    copied_git, copied_sha, copied_size = file_integrity(target)
    if (copied_git, copied_sha, copied_size) != (git_blob_sha1, local_sha256, size):
        raise ValueError("attack_production_bundle_copy_mismatch")
    return git_blob_sha1, local_sha256, target


def _scan_root(samples: tuple[AttackEvaluationSample, ...]) -> Path:
    common = Path(os.path.commonpath(tuple(sample.artifact_path for sample in samples)))
    return common.parent if common.is_file() else common


def _validated_yara_mode(value: object) -> str:
    if type(value) is not str or value not in YARA_RUNTIME_MODES:
        raise ValueError("attack_production_yara_mode_invalid")
    return value


def _validated_sample_order(value: object) -> str:
    if type(value) is not str or value not in SAMPLE_ORDERS:
        raise ValueError("attack_production_sample_order_invalid")
    return value


def _ordered_samples(
    samples: tuple[AttackEvaluationSample, ...],
    *,
    sample_order: str,
) -> tuple[AttackEvaluationSample, ...]:
    order = _validated_sample_order(sample_order)
    ordered = tuple(sorted(samples, key=lambda sample: sample.sample_id))
    return ordered if order == "ascending" else tuple(reversed(ordered))


def _resolve_yara_source(
    repository_root: Path,
    *,
    yara_mode: str,
    yara_source_path: Path | None,
) -> tuple[Path | None, str]:
    mode = _validated_yara_mode(yara_mode)
    if mode == "disabled":
        if yara_source_path is not None:
            raise ValueError("attack_production_yara_source_while_disabled")
        return None, ""
    if yara_source_path is None:
        source = repository_root / "Yara" / _YARA_SOURCE_FILENAMES[mode]
    else:
        if type(yara_source_path) not in _PATH_TYPES:
            raise TypeError("attack_production_yara_source_invalid")
        source = yara_source_path
    candidate = source.expanduser().absolute()
    if path_contains_filesystem_alias(candidate) or not candidate.is_file():
        raise ValueError("attack_production_yara_source_invalid")
    resolved = candidate.resolve()
    if resolved.suffix.lower() not in (".zip", ".yar", ".yara"):
        raise ValueError("attack_production_yara_source_invalid")
    _git_blob_sha1, source_sha256, size = file_integrity(resolved)
    if size < 1:
        raise ValueError("attack_production_yara_source_invalid")
    return resolved, source_sha256


def _prepare_yara_controls(
    state_root: Path,
    *,
    yara_mode: str,
    source_sha256: str,
) -> Path | None:
    mode = _validated_yara_mode(yara_mode)
    if mode == "disabled":
        if source_sha256 != "":
            raise ValueError("attack_production_yara_digest_while_disabled")
        return None
    if type(source_sha256) is not str or len(source_sha256) != 64:
        raise ValueError("attack_production_yara_source_sha256_invalid")
    root = state_root / "Yara"
    controls = ensure_generated_controls(root)
    config = YaraConfig(
        enabled=True,
        full_enabled=mode == "extended",
        light_enabled=mode == "core",
        allow_full_download=False,
        allow_light_download=False,
        full_expected_sha256=source_sha256 if mode == "extended" else "",
        light_expected_sha256=source_sha256 if mode == "core" else "",
    )
    controls["config"].write_text(config_toml(config), encoding="utf-8", newline="\n")
    if load_config(controls["config"]) != config:
        raise RuntimeError("attack_production_yara_config_roundtrip_failed")
    return controls["config"]


def _yara_command_arguments(
    *,
    yara_mode: str,
    yara_source_path: Path | None,
    yara_config_path: Path | None,
) -> tuple[str, ...]:
    mode = _validated_yara_mode(yara_mode)
    if mode == "disabled":
        if yara_source_path is not None or yara_config_path is not None:
            raise ValueError("attack_production_yara_disabled_identity_present")
        return (
            "--deep-scan-mode", "thorough",
            "--no-yara", "--no-yaralight",
        )
    if type(yara_source_path) not in _PATH_TYPES or type(yara_config_path) not in _PATH_TYPES:
        raise TypeError("attack_production_yara_runtime_identity_invalid")
    shared = (
        "--yara-config", str(yara_config_path),
        "--yara-no-download", "--yaralight-no-download",
        "--yara-status",
    )
    if mode == "core":
        return (
            "--deep-scan-mode", "fast",
            "--yaralight", str(yara_source_path),
            *shared,
        )
    return (
        "--deep-scan-mode", "thorough",
        "--yara", str(yara_source_path),
        "--no-yaralight",
        *shared,
    )


def _production_command(
    *,
    samples: tuple[AttackEvaluationSample, ...],
    scheduler: str,
    run_root: Path,
    cache_root: Path,
    output_path: Path,
    yara_mode: str,
    yara_source_path: Path | None,
    yara_config_path: Path | None,
    scan_cache_enabled: bool,
) -> tuple[str, ...]:
    if type(scan_cache_enabled) is not bool:
        raise TypeError("attack_production_scan_cache_enabled_invalid")
    cache_arguments = () if scan_cache_enabled else ("--no-scan-cache",)
    return (
        sys.executable, "-m", "Virus_Scan.runtime_main",
        "--dir", str(_scan_root(samples)),
        "--file-list", str(run_root / "selected_paths.txt"),
        "--scheduler", scheduler,
        "--workers", "1" if scheduler == "serial" else "2",
        *_yara_command_arguments(
            yara_mode=yara_mode,
            yara_source_path=yara_source_path,
            yara_config_path=yara_config_path,
        ),
        "--no-stage-parallel",
        "--mitre-no-download",
        "--mitre-config", str(cache_root / "mitre_config.toml"),
        "--scan-log-root", str(run_root / "Scan Logs"),
        *cache_arguments,
        "--no-freeze-baseline",
        "--partial-output-every", "0", "--progress-every", "0",
        "--per-file-timeout", "60",
    )


def _percentile(values: tuple[int, ...], fraction: float) -> int:
    if not values:
        return 0
    ordered = tuple(sorted(values))
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def _process_parent_map() -> dict[int, int]:
    root = Path("/proc")
    if not root.is_dir():
        return {}
    result: dict[int, int] = {}
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text(encoding="utf-8", errors="strict")
            tail = text[text.rfind(")") + 2:].split()
            result[int(entry.name)] = int(tail[1])
        except (OSError, ValueError, IndexError):
            continue
    return result


def _process_tree(root_pid: int) -> tuple[int, ...]:
    parents = _process_parent_map()
    selected = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return tuple(sorted(selected))


def _process_tree_resources(root_pid: int) -> tuple[int, int]:
    rss_bytes = 0
    descriptors = 0
    for pid in _process_tree(root_pid):
        proc = Path("/proc") / str(pid)
        try:
            for line in (proc / "status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    rss_bytes += int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
        try:
            descriptors += sum(1 for _entry in (proc / "fd").iterdir())
        except OSError:
            pass
    return rss_bytes, descriptors


def _directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if path_contains_filesystem_alias(entry):
                    continue
                if entry.is_dir():
                    pending.append(entry)
                elif entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                continue
    return total


def _run_runtime_command(
    command: tuple[str, ...],
    *,
    repository_root: Path,
    environment: dict[str, str],
    stdout_handle: object,
    stderr_handle: object,
    timeout_seconds: int,
    run_root: Path,
) -> tuple[int, int, int, int, int]:
    started = monotonic_ns()
    process = subprocess.Popen(
        command,
        cwd=repository_root,
        env=environment,
        stdout=stdout_handle,
        stderr=stderr_handle,
        text=True,
    )
    peak_rss = 0
    peak_descriptors = 0
    peak_disk = 0
    while process.poll() is None:
        elapsed = monotonic_ns() - started
        if elapsed > timeout_seconds * 1_000_000_000:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        rss, descriptors = _process_tree_resources(process.pid)
        peak_rss = max(peak_rss, rss)
        peak_descriptors = max(peak_descriptors, descriptors)
        peak_disk = max(peak_disk, _directory_size(run_root))
        sleep(0.5)
    rss, descriptors = _process_tree_resources(process.pid)
    peak_rss = max(peak_rss, rss)
    peak_descriptors = max(peak_descriptors, descriptors)
    peak_disk = max(peak_disk, _directory_size(run_root))
    return process.returncode, monotonic_ns() - started, peak_rss, peak_descriptors, peak_disk


def _parse_yara_scan_metrics(log_path: Path) -> dict[str, object]:
    marker = "[YARA_SCAN_METRIC] "
    records: list[dict[str, object]] = []
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8", errors="strict").splitlines():
            position = line.find(marker)
            if position < 0:
                continue
            value = json.loads(line[position + len(marker):])
            if type(value) is not dict:
                raise ValueError("attack_production_yara_metric_record_invalid")
            records.append(value)
    invoked = tuple(record for record in records if record.get("engine_match_invoked") is True)
    latencies = tuple(
        int(record["elapsed_ns"])
        for record in invoked
        if type(record.get("elapsed_ns")) is int and type(record.get("elapsed_ns")) is not bool
    )
    statuses: dict[str, int] = {}
    for record in records:
        status = record.get("status")
        if type(status) is str:
            statuses[status] = statuses.get(status, 0) + 1
    scan_passes = {
        record["scan_pass_id"] for record in invoked
        if type(record.get("scan_pass_id")) is str
    }
    def _sum(field: str) -> int:
        return sum(
            int(record[field]) for record in records
            if type(record.get(field)) is int and type(record.get(field)) is not bool
        )
    ordered = tuple(sorted(latencies))
    return {
        "metric_line_count": len(records),
        "engine_call_count": len(invoked),
        "unique_scan_pass_count": len(scan_passes),
        "latency_min_ns": ordered[0] if ordered else 0,
        "latency_median_ns": ordered[(len(ordered) - 1) // 2] if ordered else 0,
        "latency_p95_ns": _percentile(ordered, 0.95),
        "latency_p99_ns": _percentile(ordered, 0.99),
        "latency_max_ns": ordered[-1] if ordered else 0,
        "total_match_count": _sum("total_match_count"),
        "retained_match_count": _sum("retained_match_count"),
        "duplicate_match_count": _sum("duplicate_match_count"),
        "truncated_match_count": _sum("truncated_match_count"),
        "status_counts": tuple(sorted(statuses.items())),
    }



def _scan_cache_metrics(
    *,
    output_path: Path,
    state_root: Path,
    scan_cache_enabled: bool,
) -> dict[str, int]:
    empty = {
        "hit_count": 0,
        "miss_count": 0,
        "database_bytes": 0,
        "wal_bytes": 0,
        "content_row_count": 0,
        "alias_row_count": 0,
        "fast_fingerprint_row_count": 0,
        "execution_identity_row_count": 0,
        "semantic_result_row_count": 0,
        "parse_result_row_count": 0,
        "static_operation_row_count": 0,
        "scanner_observation_row_count": 0,
    }
    if not scan_cache_enabled:
        return empty
    if path_contains_filesystem_alias(output_path) or not output_path.is_file():
        raise ValueError("attack_production_output_file_invalid")
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    if type(payload) is not dict:
        raise ValueError("attack_production_output_invalid")
    hit_count = 0
    for record in payload.values():
        if type(record) is not dict:
            raise ValueError("attack_production_output_record_invalid")
        hit_count += dict.get(record, "cache_hit") is True
    lifecycle = SQLiteLifecycleOwner()
    repository = ScanCacheRepository(lifecycle)
    try:
        repository.configure_reader(state_root / "profiles")
        statistics = repository.stats()
    finally:
        lifecycle.close()

    def exact_metric(name: str) -> int:
        value = statistics.get(name)
        if type(value) is not int or value < 0:
            raise ValueError("attack_production_scan_cache_metric_invalid:" + name)
        return value

    return {
        "hit_count": hit_count,
        "miss_count": len(payload) - hit_count,
        "database_bytes": exact_metric("database_bytes"),
        "wal_bytes": exact_metric("wal_bytes"),
        "content_row_count": exact_metric("contents"),
        "alias_row_count": exact_metric("aliases"),
        "fast_fingerprint_row_count": exact_metric("fast_fingerprints"),
        "execution_identity_row_count": exact_metric("execution_identities"),
        "semantic_result_row_count": exact_metric("results"),
        "parse_result_row_count": exact_metric("parse_results"),
        "static_operation_row_count": exact_metric("static_analyses"),
        "scanner_observation_row_count": exact_metric("scanner_observations"),
    }


def run_production_runtime(
    *,
    repository_root: Path,
    corpus: AttackEvaluationCorpusManifest,
    partition: str,
    limit: int,
    run_root: Path,
    bundle_path: Path,
    scheduler: str,
    timeout_seconds: int,
    scan_cache_enabled: bool = False,
    state_root: Path | None = None,
    reuse_state: bool = False,
    hash_seed: int = 0,
    sample_order: str = "ascending",
    yara_mode: str = "disabled",
    yara_source_path: Path | None = None,
) -> AttackProductionRuntimeOutput:
    if (
        type(repository_root) not in _PATH_TYPES
        or path_contains_filesystem_alias(repository_root)
        or not repository_root.is_dir()
    ):
        raise ValueError("attack_production_repository_root_invalid")
    if type(scheduler) is not str or scheduler not in {"serial", "process"}:
        raise ValueError("attack_production_scheduler_invalid")
    if type(scan_cache_enabled) is not bool:
        raise TypeError("attack_production_scan_cache_enabled_invalid")
    if state_root is not None and type(state_root) not in _PATH_TYPES:
        raise TypeError("attack_production_state_root_invalid")
    if type(reuse_state) is not bool:
        raise TypeError("attack_production_reuse_state_invalid")
    seed = exact_bounded_nonnegative_int(
        hash_seed, "attack_production_hash_seed_invalid", maximum=4_294_967_295,
    )
    order = _validated_sample_order(sample_order)
    mode = _validated_yara_mode(yara_mode)
    timeout = exact_bounded_nonnegative_int(
        timeout_seconds, "attack_production_timeout_invalid", maximum=86_400,
    )
    if timeout < 1:
        raise ValueError("attack_production_timeout_invalid")
    selected = select_production_samples(corpus, partition=partition, limit=limit)
    samples = _ordered_samples(selected, sample_order=order)
    effective_state_root = run_root / "state" if state_root is None else state_root
    effective_state_root, cache_root = _prepare_run_root(
        run_root,
        state_root=effective_state_root,
        reuse_state=reuse_state,
    )
    bundle_git, bundle_sha, _cached_bundle = _prepare_bundle(bundle_path, cache_root)
    source_path, source_sha256 = _resolve_yara_source(
        repository_root,
        yara_mode=mode,
        yara_source_path=yara_source_path,
    )
    yara_config_path = _prepare_yara_controls(
        effective_state_root,
        yara_mode=mode,
        source_sha256=source_sha256,
    )
    file_list = run_root / "selected_paths.txt"
    file_list.write_text(
        "".join(sample.artifact_path + "\n" for sample in samples),
        encoding="utf-8",
    )
    output_path = run_root / "scan_results.json"
    stdout_path = run_root / "stdout.log"
    stderr_path = run_root / "stderr.log"
    command = _production_command(
        samples=samples,
        scheduler=scheduler,
        run_root=run_root,
        cache_root=cache_root,
        output_path=output_path,
        yara_mode=mode,
        yara_source_path=source_path,
        yara_config_path=yara_config_path,
        scan_cache_enabled=scan_cache_enabled,
    )
    (run_root / "runtime_command.json").write_text(
        json.dumps(command, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w", encoding="utf-8",
    ) as stderr_handle:
        returncode, elapsed_ns, peak_rss, peak_descriptors, peak_disk = _run_runtime_command(
            command,
            repository_root=repository_root,
            environment=_runtime_environment(
                repository_root,
                effective_state_root,
                scheduler=scheduler,
                yara_mode=mode,
                hash_seed=seed,
            ),
            stdout_handle=stdout_handle,
            stderr_handle=stderr_handle,
            timeout_seconds=timeout,
            run_root=run_root,
        )
    generation = _completed_scan_log_generation(run_root)
    output_path = generation / "scan_results.json"
    scanlog_path = generation / "scanlog"
    yara_metrics = _parse_yara_scan_metrics(
        stderr_path if scheduler == "process" else scanlog_path,
    )
    cache_metrics = _scan_cache_metrics(
        output_path=output_path,
        state_root=effective_state_root,
        scan_cache_enabled=scan_cache_enabled,
    )
    resource_metrics = AttackProductionResourceMetrics(
        elapsed_ns=elapsed_ns,
        peak_process_tree_rss_bytes=peak_rss,
        peak_process_tree_descriptor_count=peak_descriptors,
        peak_run_root_bytes=peak_disk,
        output_bytes=output_path.stat().st_size if output_path.is_file() else 0,
        yara_metric_line_count=int(yara_metrics["metric_line_count"]),
        yara_engine_call_count=int(yara_metrics["engine_call_count"]),
        yara_unique_scan_pass_count=int(yara_metrics["unique_scan_pass_count"]),
        yara_latency_min_ns=int(yara_metrics["latency_min_ns"]),
        yara_latency_median_ns=int(yara_metrics["latency_median_ns"]),
        yara_latency_p95_ns=int(yara_metrics["latency_p95_ns"]),
        yara_latency_p99_ns=int(yara_metrics["latency_p99_ns"]),
        yara_latency_max_ns=int(yara_metrics["latency_max_ns"]),
        yara_total_match_count=int(yara_metrics["total_match_count"]),
        yara_retained_match_count=int(yara_metrics["retained_match_count"]),
        yara_duplicate_match_count=int(yara_metrics["duplicate_match_count"]),
        yara_truncated_match_count=int(yara_metrics["truncated_match_count"]),
        yara_status_counts=tuple(yara_metrics["status_counts"]),
        scan_cache_hit_count=int(cache_metrics["hit_count"]),
        scan_cache_miss_count=int(cache_metrics["miss_count"]),
        scan_cache_database_bytes=int(cache_metrics["database_bytes"]),
        scan_cache_wal_bytes=int(cache_metrics["wal_bytes"]),
        scan_cache_content_row_count=int(cache_metrics["content_row_count"]),
        scan_cache_alias_row_count=int(cache_metrics["alias_row_count"]),
        scan_cache_fast_fingerprint_row_count=int(cache_metrics["fast_fingerprint_row_count"]),
        scan_cache_execution_identity_row_count=int(cache_metrics["execution_identity_row_count"]),
        scan_cache_semantic_result_row_count=int(cache_metrics["semantic_result_row_count"]),
        scan_cache_parse_result_row_count=int(cache_metrics["parse_result_row_count"]),
        scan_cache_static_operation_row_count=int(cache_metrics["static_operation_row_count"]),
        scan_cache_scanner_observation_row_count=int(cache_metrics["scanner_observation_row_count"]),
    )
    return AttackProductionRuntimeOutput(
        selected_samples=samples,
        run_root=run_root,
        output_path=output_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        bundle_git_blob_sha1=bundle_git,
        bundle_sha256=bundle_sha,
        returncode=returncode,
        command=command,
        yara_mode=mode,
        yara_source_path="" if source_path is None else str(source_path),
        yara_source_sha256=source_sha256,
        resource_metrics=resource_metrics,
        state_root=effective_state_root,
        scan_cache_enabled=scan_cache_enabled,
        hash_seed=seed,
        sample_order=order,
    )


__all__ = (
    "ALL_PARTITIONS",
    "AttackProductionResourceMetrics",
    "AttackProductionRuntimeOutput",
    "SAMPLE_ORDERS",
    "YARA_RUNTIME_MODES",
    "empty_production_resource_metrics",
    "run_production_runtime",
    "select_production_samples",
)
