"""Canonical raw queue identity ownership helpers."""

from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS, QueueIdentityScanError
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.queue.identity_index import get_index_entry as _queue_identity_owned_get, invalidate_queue as _queue_identity_owned_invalidate, set_index_entry as _queue_identity_owned_set
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_identity_index_cache_key as _queue_identity_index_cache_key
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.identity_issue_reporting import record_identity_helper_issue
from Virus_Scan.scheduler.queue.raw_queue_identity_decisions import queue_identity_index_get_failure_decision, queue_identity_mapping_decision
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names

_QUEUE_IDENTITY_INDEX_TTL_DEFAULT = 2.0
_QUEUE_IDENTITY_INDEX_TTL_MINIMUM = 0.25
_QUEUE_IDENTITY_DEFAULT_STATES = ("pending", "active", "done", "failed")
_QUEUE_IDENTITY_FILE_RESULTS_STATE = "file_results"

def _queue_identity_index_ttl_sec(*, float_env_func: object=float_env, report_issue: object=None) -> object:
    ttl = _QUEUE_IDENTITY_INDEX_TTL_DEFAULT
    try:
        ttl = float_env_func("UMIGE_QUEUE_IDENTITY_INDEX_TTL_SEC", ttl, _QUEUE_IDENTITY_INDEX_TTL_MINIMUM, None)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        if report_issue is not None:
            report_issue("queue_identity_index_ttl_policy_unavailable", exc)
        else:
            record_identity_helper_issue(
                "queue_identity_index_ttl_policy_unavailable",
                exc,
                recorder=record_scheduler_suppressed,
            )
    return ttl

def _owned_mapping_from_value(value: object) -> object:
    return queue_identity_mapping_decision(value).as_mapping_or_none()

def _add_identity(found: object, identity: object) -> object:
    if type(identity) is str and identity != "":
        found.add(identity)

def _listdir_exact_names(directory: object, safe_listdir: object) -> object:
    names = []
    for candidate in queue_listdir_names(safe_listdir(directory), context=directory):
        text, reason = no_hook_text(candidate, missing_reason="queue_identity_name_missing", unsupported_reason="queue_identity_name_rejected")
        if reason != "" or text == "":
            text, reason = scheduler_path_text(candidate)
        if reason == "" and text != "":
            names.append(text)
    return tuple(names)

def _queue_identity_index_get(queue_dir: object, states: object) -> object:
    try:
        key = _queue_identity_index_cache_key(queue_dir, states)
        return _queue_identity_owned_get(key, _queue_identity_index_ttl_sec())
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        record_identity_helper_issue(
            "queue_identity_index_get_failed",
            exc,
            recorder=record_scheduler_suppressed,
        )
        return queue_identity_index_get_failure_decision(queue_dir, states, exc).as_value()

def _queue_identity_index_invalidate(queue_dir: object=None) -> object:
    try:
        _queue_identity_owned_invalidate(queue_dir)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        record_identity_helper_issue(
            "queue_identity_index_invalidate_failed",
            exc,
            recorder=record_scheduler_suppressed,
        )

def _queue_identity_index_set(queue_dir: object, states: object, identities: object) -> object:
    try:
        key = _queue_identity_index_cache_key(queue_dir, states)
        _queue_identity_owned_set(key, identities)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        record_identity_helper_issue(
            "queue_identity_index_set_failed",
            exc,
            recorder=record_scheduler_suppressed,
        )

def collect_existing_identities(
    queue_dir: object, states: object=("pending", "active", "done", "failed", "quarantine"), *, strict: object=False,
    job_dirs: object, quarantine_dir: object, file_results_dir: object, safe_listdir: object, is_job_json_name: object, read_json: object, job_identity: object,
    identity_index_get: object=_queue_identity_index_get, identity_index_set: object=_queue_identity_index_set, log_error: object=None, report: object=None,
) -> object:
    """Collect queue identities already present before enqueueing new work."""
    if states is None:
        states_t = _QUEUE_IDENTITY_DEFAULT_STATES
    else:
        state_names = []
        for state in no_hook_sequence_items(states):
            text, reason = no_hook_text(
                state,
                missing_reason="queue_identity_state_missing",
                unsupported_reason="queue_identity_state_rejected",
            )
            if reason == "" and text != "":
                state_names.append(text)
        states_t = tuple(state_names)
    cached = identity_index_get(queue_dir, states_t)
    if cached is not None:
        return cached
    found = set()
    try:
        pending, active, done, failed = job_dirs(queue_dir)
        state_dirs = {
            "pending": pending,
            "active": active,
            "done": done,
            "failed": failed,
            "quarantine": quarantine_dir(queue_dir),
        }
        for state in states_t:
            if state == _QUEUE_IDENTITY_FILE_RESULTS_STATE:
                d = file_results_dir(queue_dir)
                for name in _listdir_exact_names(d, safe_listdir):
                    if not name.endswith(".result.json"):
                        continue
                    rec = read_json(d / name, default={})
                    rec_mapping = _owned_mapping_from_value(rec)
                    f = None if rec_mapping is None else dict.get(rec_mapping, "file")
                    if type(f) is str and f != "":
                        _add_identity(found, job_identity({"file": f}, name))
                continue
            d = dict.get(state_dirs, state)
            if d is None:
                continue
            for name in _listdir_exact_names(d, safe_listdir):
                if is_job_json_name(name) is not True:
                    continue
                job = _owned_mapping_from_value(read_json(d / name, default={}))
                if job is not None:
                    _add_identity(found, job_identity(job, name))
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        if log_error is not None:
            try:
                log_error("queue existing-identity scan failed: " + scheduler_exception_text(exc))
            except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as log_exc:
                if report is not None:
                    report("queue_existing_identity_log_failed", log_exc, fatal=False)
        if report is not None:
            report("queue_existing_identity_scan_failed", exc, fatal=True)
        if strict:
            raise QueueIdentityScanError(scheduler_exception_text(exc)) from exc
    try:
        identity_index_set(queue_dir, states_t, found)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        if report is not None:
            report("queue_identity_index_set_failed", exc, fatal=False)
    return found

def existing_identities(
    queue_dir: object, *, states: object=("pending", "active", "done", "failed", "quarantine"), strict: object=False,
    job_dirs: object, quarantine_dir: object, file_results_dir: object, safe_listdir: object, is_job_json_name: object, read_json: object, job_identity: object,
    identity_index_get: object, identity_index_set: object, log_error: object, report: object, raw_report: object,
) -> object:
    """Collect queue identities already present before new job admission."""
    def identity_report(where: object, exc: object, **kwargs: object) -> object:
        report(where, exc, **kwargs)
        if type(where) is str and where == "queue_existing_identity_scan_failed":
            raw_report("queue_existing_identity_scan_failed", exc)

    return collect_existing_identities(
        queue_dir,
        states=states,
        strict=strict,
        job_dirs=job_dirs,
        quarantine_dir=quarantine_dir,
        file_results_dir=file_results_dir,
        safe_listdir=safe_listdir,
        is_job_json_name=is_job_json_name,
        read_json=read_json,
        job_identity=job_identity,
        identity_index_get=identity_index_get,
        identity_index_set=identity_index_set,
        log_error=log_error,
        report=identity_report,
    )
