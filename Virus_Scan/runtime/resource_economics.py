"""Runtime resource economics for extraction and workload admission.

This module owns the cost model used by Stage 19.  It is intentionally
side-effect free: callers compute costs and compare them to explicit budgets;
scanner code receives limits through explicitly owned RuntimeConfig snapshots.
"""
from __future__ import annotations
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_sequence_items,
    no_hook_text,
)

from dataclasses import dataclass, field
from pathlib import Path, PosixPath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Iterable
import os


_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


def _economics_field(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return "resource_economics_field"


def _economics_reason(field_name: object, suffix: str) -> str:
    return _economics_field(field_name) + "_" + str.__str__(suffix)


def _pressure_count_reason(invalid_count: int) -> str:
    return "invalid pressure value count: " + int.__str__(invalid_count)


def _economics_nonnegative_int(value: object, field_name: str) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        reason=_economics_reason(field_name, "rejected"),
        non_finite_reason=_economics_reason(field_name, "non_finite"),
        allow_exact_text=True,
    )
    if reason:
        raise ValueError(reason)
    return parsed


def _economics_positive_int(value: object, field_name: str) -> int:
    parsed = _economics_nonnegative_int(value, field_name)
    if parsed < 1:
        raise ValueError(_economics_reason(field_name, "below_minimum"))
    return parsed


def _economics_float(
    value: object,
    field_name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    parsed, reason = no_hook_finite_float(
        value,
        minimum=minimum,
        maximum=maximum,
        reason=_economics_reason(field_name, "rejected"),
        non_finite_reason=_economics_reason(field_name, "non_finite"),
        allow_exact_text=True,
    )
    if reason:
        raise ValueError(reason)
    return parsed


def _economics_path_text(value: object) -> str:
    if type(value) is str or isinstance(value, str):
        return str.__str__(value)
    if type(value) is Path:
        return Path.as_posix(value)
    if type(value) is PosixPath:
        return PosixPath.as_posix(value)
    if type(value) is WindowsPath:
        return WindowsPath.as_posix(value)
    if type(value) is PurePosixPath:
        return PurePosixPath.as_posix(value)
    if type(value) is PureWindowsPath:
        return PureWindowsPath.as_posix(value)
    raise TypeError("resource_economics_path_rejected")


def _economics_sequence(value: object, field_name: str) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) not in (tuple, list, set, frozenset):
        raise TypeError(_economics_reason(field_name, "sequence_rejected"))
    return no_hook_sequence_items(value)



@dataclass(frozen=True)
class ResourceEconomicsConfig:
    """Hard economic budgets for archive and expensive workload growth."""

    max_archive_fanout_score: int = 1500
    max_archive_expansion_ratio: float = 80.0
    max_pending_expansion_bytes: int = 256 * 1024 * 1024
    max_workload_cost: int = 4000
    max_queue_cost_window: int = 20000

    def __post_init__(self) -> None:
        if type(self) is not ResourceEconomicsConfig:
            exception_message = "resource economics config owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(
            self,
            "max_archive_fanout_score",
            _economics_positive_int(self.max_archive_fanout_score, "max_archive_fanout_score"),
        )
        object.__setattr__(
            self,
            "max_archive_expansion_ratio",
            _economics_float(
                self.max_archive_expansion_ratio,
                "max_archive_expansion_ratio",
                minimum=1.0,
            ),
        )
        object.__setattr__(
            self,
            "max_pending_expansion_bytes",
            _economics_positive_int(self.max_pending_expansion_bytes, "max_pending_expansion_bytes"),
        )
        object.__setattr__(
            self,
            "max_workload_cost",
            _economics_positive_int(self.max_workload_cost, "max_workload_cost"),
        )
        object.__setattr__(
            self,
            "max_queue_cost_window",
            _economics_positive_int(self.max_queue_cost_window, "max_queue_cost_window"),
        )

    @classmethod
    def from_env(cls) -> "ResourceEconomicsConfig":
        return cls(
            max_archive_fanout_score=int_env("UMIGE_MAX_ARCHIVE_FANOUT_SCORE", cls.max_archive_fanout_score, 1),
            max_archive_expansion_ratio=float_env("UMIGE_MAX_ARCHIVE_EXPANSION_RATIO", cls.max_archive_expansion_ratio, 1.0),
            max_pending_expansion_bytes=int_env("UMIGE_MAX_PENDING_EXPANSION_BYTES", cls.max_pending_expansion_bytes, 1024),
            max_workload_cost=int_env("UMIGE_MAX_WORKLOAD_COST", cls.max_workload_cost, 1),
            max_queue_cost_window=int_env("UMIGE_MAX_QUEUE_COST_WINDOW", cls.max_queue_cost_window, 1),
        )

    def env_mapping(self) -> dict[str, str]:
        return {
            "UMIGE_MAX_ARCHIVE_FANOUT_SCORE": int.__str__(self.max_archive_fanout_score),
            "UMIGE_MAX_ARCHIVE_EXPANSION_RATIO": float.__str__(self.max_archive_expansion_ratio),
            "UMIGE_MAX_PENDING_EXPANSION_BYTES": int.__str__(self.max_pending_expansion_bytes),
            "UMIGE_MAX_WORKLOAD_COST": int.__str__(self.max_workload_cost),
            "UMIGE_MAX_QUEUE_COST_WINDOW": int.__str__(self.max_queue_cost_window),
        }



@dataclass
class ExtractionEconomics:
    """Cumulative extraction cost ledger for one archive tree."""

    config: ResourceEconomicsConfig = field(default_factory=ResourceEconomicsConfig.from_env)
    compressed_bytes: int = 0
    extracted_bytes: int = 0
    members: int = 0
    nested_archives: int = 0

    def __post_init__(self) -> None:
        if type(self) is not ExtractionEconomics:
            exception_message = "extraction economics owner rejected"
            raise TypeError(exception_message)
        if type(self.config) is not ResourceEconomicsConfig:
            exception_message = "resource_economics_config_rejected"
            raise TypeError(exception_message)
        self.compressed_bytes = _economics_nonnegative_int(self.compressed_bytes, "compressed_bytes")
        self.extracted_bytes = _economics_nonnegative_int(self.extracted_bytes, "extracted_bytes")
        self.members = _economics_nonnegative_int(self.members, "members")
        self.nested_archives = _economics_nonnegative_int(self.nested_archives, "nested_archives")

    def observe_member(self, *, compressed_size: int = 0, extracted_size: int = 0, is_archive: bool = False) -> None:
        compressed = _economics_nonnegative_int(compressed_size, "compressed_size")
        extracted = _economics_nonnegative_int(extracted_size, "extracted_size")
        if type(is_archive) is not bool:
            raise ValueError("is_archive_rejected")
        compressed_total = self.compressed_bytes + compressed
        extracted_total = self.extracted_bytes + extracted
        member_total = self.members + 1
        nested_total = self.nested_archives + (1 if is_archive else 0)
        self._enforce_values(
            compressed_bytes=compressed_total,
            extracted_bytes=extracted_total,
            members=member_total,
            nested_archives=nested_total,
        )
        self.compressed_bytes = compressed_total
        self.extracted_bytes = extracted_total
        self.members = member_total
        self.nested_archives = nested_total

    @property
    def expansion_ratio(self) -> float:
        return float(self.extracted_bytes) / float(max(1, self.compressed_bytes))

    @property
    def fanout_score(self) -> int:
        return self.members + (self.nested_archives * 20) + (self.extracted_bytes // (1024 * 1024))

    def enforce(self) -> None:
        self._enforce_values(
            compressed_bytes=self.compressed_bytes,
            extracted_bytes=self.extracted_bytes,
            members=self.members,
            nested_archives=self.nested_archives,
        )

    def _enforce_values(
        self,
        *,
        compressed_bytes: int,
        extracted_bytes: int,
        members: int,
        nested_archives: int,
    ) -> None:
        if extracted_bytes > self.config.max_pending_expansion_bytes:
            raise RuntimeError("archive_pending_expansion_byte_budget")
        expansion_ratio = float(extracted_bytes) / float(max(1, compressed_bytes))
        if expansion_ratio > self.config.max_archive_expansion_ratio:
            raise RuntimeError("archive_cumulative_expansion_ratio")
        fanout_score = members + (nested_archives * 20) + (extracted_bytes // (1024 * 1024))
        if fanout_score > self.config.max_archive_fanout_score:
            raise RuntimeError("archive_fanout_score_limit")


def extension_cost(path: str | os.PathLike[str]) -> int:
    ext = PurePosixPath(_economics_path_text(path)).suffix.lower()
    if ext in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".rpa"}:
        return 250
    if ext in {".dll", ".exe"}:
        return 180
    if ext in {".ps1", ".vbs", ".jse", ".bat", ".cmd", ".js", ".py", ".rpy", ".rpyc"}:
        return 70
    if ext in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".ogg", ".mp3", ".wav", ".mp4", ".webm"}:
        return 10
    return 25


def file_cost(path: str | os.PathLike[str]) -> int:
    path_text = _economics_path_text(path)
    try:
        size = Path(path_text).stat().st_size
    except RECOVERABLE_RUNTIME_ERRORS:
        size = 0
    return extension_cost(path_text) + min(1000, size // (1024 * 1024))


def queue_cost(paths: Iterable[str | os.PathLike[str]]) -> int:
    safe_paths = _economics_sequence(paths, "queue_paths")
    return sum(file_cost(_economics_path_text(path)) for path in safe_paths)


@dataclass(frozen=True)
class WorkComplexitySignal:
    """Threat-neutral workload complexity signal.

    Scheduler/economics may price these computational properties.  Detection
    threat tags must not be used directly as cost/admission signals.
    """
    kind: str
    weight: int = 0

    def __post_init__(self) -> None:
        if type(self) is not WorkComplexitySignal:
            exception_message = "work complexity signal owner rejected"
            raise TypeError(exception_message)
        kind, reason = no_hook_text(
            self.kind,
            missing_reason="work_complexity_kind_missing",
            unsupported_reason="work_complexity_kind_rejected",
        )
        if reason or kind == "":
            raise ValueError(reason or "work_complexity_kind_blank")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "weight",
            _economics_nonnegative_int(self.weight, "work_complexity_weight"),
        )

@dataclass(frozen=True)
class ArchiveComplexityScore:
    """Archive complexity estimate used before allowing deeper recursion."""
    members: int = 0
    compressed_bytes: int = 0
    extracted_bytes: int = 0
    nested_archives: int = 0
    corrupt_members: int = 0
    compression_kinds: int = 1

    def __post_init__(self) -> None:
        if type(self) is not ArchiveComplexityScore:
            exception_message = "archive complexity score owner rejected"
            raise TypeError(exception_message)
        for field_name in (
            "members",
            "compressed_bytes",
            "extracted_bytes",
            "nested_archives",
            "corrupt_members",
        ):
            object.__setattr__(
                self,
                field_name,
                _economics_nonnegative_int(
                    no_hook_exact_owner_field(self, ArchiveComplexityScore, field_name), field_name
                ),
            )
        object.__setattr__(
            self,
            "compression_kinds",
            _economics_positive_int(self.compression_kinds, "compression_kinds"),
        )

    @property
    def expansion_ratio(self) -> float:
        return float(self.extracted_bytes) / float(max(1, self.compressed_bytes))

    @property
    def score(self) -> int:
        density = self.members * 2
        nesting = self.nested_archives * 40
        corruption = self.corrupt_members * 35
        compression = max(0, self.compression_kinds - 1) * 25
        size = self.extracted_bytes // (1024 * 1024)
        ratio = int(min(1000, self.expansion_ratio * 5))
        return density + nesting + corruption + compression + size + ratio


def archive_complexity_score(*, members: int = 0, compressed_bytes: int = 0, extracted_bytes: int = 0,
                             nested_archives: int = 0, corrupt_members: int = 0,
                             compression_kinds: int = 1) -> ArchiveComplexityScore:
    return ArchiveComplexityScore(members, compressed_bytes, extracted_bytes, nested_archives, corrupt_members, compression_kinds)


def adaptive_reprice_cost(path: str | os.PathLike[str], *, discovered_members: int = 0,
                          discovered_bytes: int = 0,
                          complexity_signals: Iterable[WorkComplexitySignal | str] | None = None) -> int:
    """Predictive cost plus feedback from discovered runtime complexity."""
    cost = file_cost(path)
    members = _economics_nonnegative_int(discovered_members, "discovered_members")
    discovered = _economics_nonnegative_int(discovered_bytes, "discovered_bytes")
    cost += min(2000, members * 3)
    cost += min(2000, discovered // (1024 * 1024))
    for sig in _economics_sequence(complexity_signals, "complexity_signals"):
        if type(sig) is WorkComplexitySignal:
            cost += sig.weight
        else:
            name, reason = no_hook_text(
                sig,
                missing_reason="complexity_signal_missing",
                unsupported_reason="complexity_signal_rejected",
            )
            if reason:
                raise ValueError(reason)
            name = name.lower()
            if name in {"managed_runtime", "decompiler_required"}:
                cost += 250
            elif name in {"container_expansion", "nested_archive"}:
                cost += 300
            elif name in {"large_decode_surface", "high_entropy_surface"}:
                cost += 175
    return min(ResourceEconomicsConfig.from_env().max_workload_cost, max(1, cost))


def confidence_inertia(previous: float, current: float, *, max_step: float = 18.0, floor: float = 0.0, ceiling: float = 100.0) -> float:
    """Bound late evidence score swings while preserving direction."""
    prev = _economics_float(previous, "previous_confidence")
    curr = _economics_float(current, "current_confidence")
    step = _economics_float(max_step, "confidence_max_step", minimum=0.0)
    lower = _economics_float(floor, "confidence_floor")
    upper = _economics_float(ceiling, "confidence_ceiling")
    if lower > upper:
        raise ValueError("confidence_bounds_reversed")
    if curr > prev + step:
        curr = prev + step
    elif curr < prev - step:
        curr = prev - step
    return max(lower, min(upper, curr))

@dataclass(frozen=True)
class RepricingInertiaConfig:
    """Smoothing guard for adaptive workload repricing."""
    max_step: int = 350
    smoothing: float = 0.35

    def __post_init__(self) -> None:
        if type(self) is not RepricingInertiaConfig:
            exception_message = "repricing inertia config owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "max_step", _economics_positive_int(self.max_step, "repricing_max_step"))
        object.__setattr__(
            self,
            "smoothing",
            _economics_float(self.smoothing, "repricing_smoothing", minimum=0.0, maximum=1.0),
        )

    @classmethod
    def from_env(cls) -> "RepricingInertiaConfig":
        return cls(
            max_step=int_env("UMIGE_REPRICING_MAX_STEP", cls.max_step, 1),
            smoothing=float_env("UMIGE_REPRICING_SMOOTHING", cls.smoothing, 0.01, 1.0),
        )


def apply_repricing_inertia(previous_cost: float | None, proposed_cost: float, *, config: RepricingInertiaConfig | None = None) -> int:
    """Prevent cost oscillation when hidden workload complexity is discovered late."""
    config = config or RepricingInertiaConfig.from_env()
    if type(config) is not RepricingInertiaConfig:
        raise TypeError("repricing_config_rejected")
    proposed = _economics_float(proposed_cost, "proposed_cost", minimum=0.0)
    previous = proposed if previous_cost is None else _economics_float(previous_cost, "previous_cost", minimum=0.0)
    blended = previous + ((proposed - previous) * config.smoothing)
    if blended > previous + config.max_step:
        blended = previous + config.max_step
    elif blended < previous - config.max_step:
        blended = previous - config.max_step
    return max(1, int(round(blended)))


@dataclass(frozen=True)
class ArchiveEcosystemScore:
    """Pre-extraction risk/economics score for pathological archive ecosystems."""
    metadata_density: float = 0.0
    lineage_depth: int = 0
    fanout_irregularity: float = 0.0
    corruption_entropy: float = 0.0
    decompression_unpredictability: float = 0.0

    def __post_init__(self) -> None:
        if type(self) is not ArchiveEcosystemScore:
            exception_message = "archive ecosystem score owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(
            self,
            "metadata_density",
            _economics_float(self.metadata_density, "metadata_density", minimum=0.0),
        )
        object.__setattr__(
            self,
            "lineage_depth",
            _economics_nonnegative_int(self.lineage_depth, "lineage_depth"),
        )
        object.__setattr__(
            self,
            "fanout_irregularity",
            _economics_float(self.fanout_irregularity, "fanout_irregularity", minimum=0.0),
        )
        object.__setattr__(
            self,
            "corruption_entropy",
            _economics_float(self.corruption_entropy, "corruption_entropy", minimum=0.0),
        )
        object.__setattr__(
            self,
            "decompression_unpredictability",
            _economics_float(
                self.decompression_unpredictability,
                "decompression_unpredictability",
                minimum=0.0,
            ),
        )

    @property
    def score(self) -> int:
        return int(
            min(5000.0,
                (self.metadata_density * 120.0) +
                (self.lineage_depth * 80.0) +
                (self.fanout_irregularity * 180.0) +
                (self.corruption_entropy * 220.0) +
                (self.decompression_unpredictability * 160.0)
            )
        )


def archive_ecosystem_score(*, members: int = 0, compressed_bytes: int = 0, extracted_bytes: int = 0,
                            depth: int = 0, nested_archives: int = 0, corrupt_members: int = 0,
                            distinct_extensions: int = 1) -> ArchiveEcosystemScore:
    members = _economics_nonnegative_int(members, "ecosystem_members")
    compressed_bytes = _economics_nonnegative_int(compressed_bytes, "ecosystem_compressed_bytes")
    extracted_bytes = _economics_nonnegative_int(extracted_bytes, "ecosystem_extracted_bytes")
    depth = _economics_nonnegative_int(depth, "ecosystem_depth")
    nested_archives = _economics_nonnegative_int(nested_archives, "ecosystem_nested_archives")
    corrupt_members = _economics_nonnegative_int(corrupt_members, "ecosystem_corrupt_members")
    distinct_extensions = _economics_positive_int(distinct_extensions, "ecosystem_distinct_extensions")
    density = members / max(1.0, compressed_bytes / 1024.0)
    fanout = (nested_archives * 2.0 + distinct_extensions) / max(1.0, members ** 0.5 if members else 1.0)
    corruption = corrupt_members / max(1.0, members)
    ratio = extracted_bytes / max(1.0, compressed_bytes)
    unpredictability = min(20.0, ratio) / 20.0
    return ArchiveEcosystemScore(
        metadata_density=min(10.0, density),
        lineage_depth=depth,
        fanout_irregularity=min(10.0, fanout),
        corruption_entropy=min(1.0, corruption),
        decompression_unpredictability=min(1.0, unpredictability),
    )


def cross_domain_pressure_budget(*pressures: float, budget: float = 1.0) -> tuple[bool, float]:
    """Shared pressure guard so telemetry/replay/scheduler cannot destabilize one another."""
    total = 0.0
    invalid_count = 0
    for pressure in pressures:
        try:
            total += _economics_float(pressure, "cross_domain_pressure", minimum=0.0)
        except ValueError:
            invalid_count += 1
    if invalid_count:
        raise ValueError(_pressure_count_reason(invalid_count))
    limit = _economics_float(budget, "cross_domain_pressure_budget", minimum=0.0)
    return total <= limit, total


__all__ = (
    "ArchiveComplexityScore",
    "ArchiveEcosystemScore",
    "ExtractionEconomics",
    "RepricingInertiaConfig",
    "ResourceEconomicsConfig",
    "WorkComplexitySignal",
    "adaptive_reprice_cost",
    "apply_repricing_inertia",
    "archive_complexity_score",
    "archive_ecosystem_score",
    "confidence_inertia",
    "cross_domain_pressure_budget",
    "extension_cost",
    "file_cost",
    "queue_cost",
)
