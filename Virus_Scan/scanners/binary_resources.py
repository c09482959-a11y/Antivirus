"""Binary scanner resource and strict-fast public aggregation surface."""

from __future__ import annotations

from Virus_Scan.scanners.binary_bits import _umige_bits_to_bytes
from Virus_Scan.scanners.binary_raw_escalation import _umige_raw_should_escalate_after_triage_inmemory
from Virus_Scan.scanners.binary_resource_metrics import (
    _umige_cpu_percent_sample,
    _umige_dynamic_cost_multiplier,
    _umige_process_rss_mb,
)
from Virus_Scan.scanners.binary_stage_tasks import _append_micro_binary_stage_tasks
from Virus_Scan.scanners.binary_strict_fast import (
    _strict_fast_entropy,
    _strict_fast_file_is_boring_text,
)

__all__ = (
    "_append_micro_binary_stage_tasks",
    "_strict_fast_entropy",
    "_strict_fast_file_is_boring_text",
    "_umige_bits_to_bytes",
    "_umige_cpu_percent_sample",
    "_umige_dynamic_cost_multiplier",
    "_umige_process_rss_mb",
    "_umige_raw_should_escalate_after_triage_inmemory",
)
