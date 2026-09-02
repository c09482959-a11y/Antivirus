"""Scheduler-owned stage-cost estimation and observation records."""
from __future__ import annotations
import math
import os
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import get_init_value, publish_init_value
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
    scheduler_text,
)
from Virus_Scan.scheduler.runtime.stage_cost_observation import (
    observe_runtime_execution_cost as _observe_runtime_execution_cost,
    pressure_from_observation as _pressure_from_observation,
)
_IMAGE_EXTENSIONS = frozenset({'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tif', '.tiff'})
_ARCHIVE_EXTENSIONS = frozenset({'.zip', '.rar', '.7z', '.rpa', '.rgssad', '.rgss3a', '.pak'})
_BINARY_EXTENSIONS = frozenset({'.dll', '.exe'})
_HEAVY_EXTENSIONS = _IMAGE_EXTENSIONS | _ARCHIVE_EXTENSIONS | _BINARY_EXTENSIONS | frozenset({'.unity3d', '.assets', '.bundle'})
_DYNAMIC_STAGE_COST_KEY = '_UMIGE_DYNAMIC_STAGE_COST'
def _extension_for_cost(path: object) -> object:
    path_text, path_reason = scheduler_path_text(path)
    if path_reason or path_text == '':
        return '', path_reason or 'scheduler_stage_cost_path_missing'
    try:
        extension = get_scan_extension(path_text)
        extension_text, extension_reason = scheduler_text(
            extension,
            unsupported_reason='scheduler_stage_cost_extension_rejected',
        )
        if extension_reason:
            return '', extension_reason
        return extension_text.lower(), ''
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        return '', scheduler_error_detail(exc, max_length=240)
def _base_stage_weight(ext: object) -> object:
    if ext in _IMAGE_EXTENSIONS:
        return 'image', 3
    if ext in _ARCHIVE_EXTENSIONS:
        return 'archive', 4
    if ext in _BINARY_EXTENSIONS:
        return 'binary', 3
    if ext in _HEAVY_EXTENSIONS:
        return 'heavy', 2
    return 'light', 1
def _size_weight_delta(size: object) -> object:
    if size > 64 * 1024 * 1024:
        return 4
    if size > 16 * 1024 * 1024:
        return 2
    if size > 4 * 1024 * 1024:
        return 1
    return 0
def estimate_stage_file_cost(path: object) -> object:
    """Return a deterministic scheduler-owned pre-dispatch file cost snapshot."""
    ext, extension_error = _extension_for_cost(path)
    path_text, path_reason = scheduler_path_text(path)
    if path_reason or path_text == '':
        size, size_error = 0, path_reason or 'scheduler_stage_cost_path_missing'
    else:
        try:
            size, size_error = scheduler_int(
                os.path.getsize(path_text),
                default=0,
                minimum=0,
                reason='scheduler_stage_cost_size_rejected',
            )
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            size, size_error = 0, scheduler_error_detail(exc, max_length=240)
    if extension_error or size_error:
        stage, base_weight = ('unknown', 4) if ext == '' else _base_stage_weight(ext)
    else:
        stage, base_weight = _base_stage_weight(ext)
    metric, weight_error = scheduler_float(
        base_weight + _size_weight_delta(size),
        default=4.0,
        minimum=1.0,
        reason='scheduler_stage_cost_weight_rejected',
    )
    if weight_error:
        try:
            record_suppressed_failure(
                'stage_file_cost_weight_normalize_failed',
                ValueError(weight_error),
                domain='scheduler',
            )
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
        weight = 4
    else:
        weight = int(math.ceil(metric))
    result = {
        'weight': max(1, weight),
        'stage': stage,
        'size': size,
        'heavy': weight >= 3,
    }
    errors = tuple(
        error
        for error in (extension_error, size_error, weight_error)
        if error
    )
    if errors:
        result['cost_evidence'] = {
            'scheduler_stage_cost_degraded': True,
            'reasons': errors,
            'final_json_must_record': True,
            'checkpoint_must_record': True,
            'replay_must_record': True,
        }
    return result
def record_stage_cost_observation(path: object=None, cost: object=None, duration_sec: object=0.0, rss_mb: object=0.0, *, stalled: object=False, retried: object=False) -> object:
    """Record scheduler-only EWMA stage pressure without altering scan decisions."""
    observed = None
    try:
        cost_items = no_hook_mapping_items(cost)
        c = dict(cost_items) if cost_items is not None else estimate_stage_file_cost(path)
        stage, stage_reason = scheduler_text(
            dict.get(c, 'stage'),
            replacement_text='unknown',
            unsupported_reason='scheduler_stage_cost_stage_rejected',
        )
        if stage_reason:
            record_suppressed_failure(
                'stage_cost_stage_rejected',
                ValueError(stage_reason),
                domain='scheduler',
            )
        stage = stage.lower()
        ext, extension_error = _extension_for_cost(path)
        if extension_error:
            record_suppressed_failure(
                'stage_cost_extension_unavailable',
                ValueError(extension_error),
                domain='scheduler',
            )
        pressure = _pressure_from_observation(duration_sec, rss_mb, stalled=stalled, retried=retried)
        _observe_runtime_execution_cost(duration_sec, rss_mb, stalled=stalled, retried=retried)
        state_items = no_hook_mapping_items(get_init_value(_DYNAMIC_STAGE_COST_KEY, {}))
        if state_items is None:
            record_suppressed_failure(
                'stage_cost_state_rejected',
                ValueError('scheduler_stage_cost_state_rejected'),
                domain='scheduler',
            )
            state = {}
        else:
            state = dict(state_items)
        for key in (stage + ':' + ext, stage + ':'):
            prev, prev_reason = scheduler_float(
                dict.get(state, key),
                default=1.0,
                minimum=0.75,
                maximum=3.0,
                reason='scheduler_stage_cost_previous_rejected',
            )
            if prev_reason:
                record_suppressed_failure(
                    'stage_cost_previous_rejected',
                    ValueError(prev_reason),
                    domain='scheduler',
                )
            state[key] = max(0.75, min(3.0, 0.2 * pressure + 0.8 * prev))
        publish_init_value(_DYNAMIC_STAGE_COST_KEY, state)
        observed = dict.get(state, stage + ':' + ext)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure(
                'stage_cost_observation_failed',
                exc,
                domain='scheduler',
            )
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return observed
__all__ = ('estimate_stage_file_cost', 'record_stage_cost_observation')
