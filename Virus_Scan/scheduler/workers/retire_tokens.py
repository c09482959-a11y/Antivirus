"""Worker retire-token lifecycle ownership."""
from __future__ import annotations

import os
import time

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import flush_open_writable_file, record_suppressed_failure
from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_atomic_replace as _queue_atomic_replace,
    queue_retire_dir as _queue_retire_dir,
    queue_safe_unlink as _queue_safe_unlink,
    safe_queue_listdir as _safe_queue_listdir,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int
from Virus_Scan.scheduler.workers.retire_tokens_evidence import (
    retire_token_consume_decision,
    retire_token_name_decision,
    retire_token_request_decision,
)


def _record_retire_rejection(where: object, value: object, reason: object) -> object:
    try:
        record_suppressed_failure(
            where,
            RuntimeError(reason),
            domain='scheduler',
            context={
                'scheduler_retire_token_rejected': True,
                'reason': reason,
                'evidence': unsupported_scheduler_value_evidence(value, field_name=where),
            },
        )
    except RECOVERABLE_RUNTIME_ERRORS as report_exc:
        _ = report_exc



def request_queue_worker_retire(queue_dir: object, count: object=1) -> object:
    """Ask idle queue-child workers to exit without killing active scans.

    Worker authority owns retire-token creation because the token changes worker
    lifecycle authority without executing scans or mutating queue claims.
    """
    made = 0
    count, count_reason = worker_int(
        count,
        replacement=0,
        reason="queue_worker_retire_count_rejected",
        minimum=0,
    )
    if count_reason:
        _record_retire_rejection('queue_worker_retire_count_rejected', count, count_reason)
    request_decision = retire_token_request_decision(count, reason='')
    if not request_decision.accepted:
        return request_decision.requested
    count = request_decision.requested
    try:
        d = _queue_retire_dir(queue_dir)
        for i in range(count):
            name = 'retire_%s_%06d.token' % (time.time_ns() if hasattr(time, 'time_ns') else int(time.time() * 1000000000), i)
            tmp = d / (name + '.tmp')
            final = d / name
            sync_ok = True
            with tmp.open('w', encoding='utf-8') as fh:
                fh.write(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
                try:
                    fh.flush()
                    flush_open_writable_file(fh.fileno())
                except RECOVERABLE_RUNTIME_ERRORS as exc:
                    sync_ok = False
                    try:
                        record_suppressed_failure('queue_retire_token_sync_failed', exc, domain='runtime')
                    except RECOVERABLE_RUNTIME_ERRORS as report_exc:
                        _ = report_exc
            if not sync_ok:
                try:
                    _queue_safe_unlink(tmp, log_context='queue_retire_token_sync_failed')
                except RECOVERABLE_RUNTIME_ERRORS as unlink_exc:
                    record_suppressed_failure('queue_retire_token_cleanup_failed', unlink_exc, domain='scheduler')
                continue
            if not _queue_atomic_replace(tmp, final, log_context='queue_tmp_to_final'):
                try:
                    _queue_safe_unlink(tmp, log_context='queue_retire_token_replace_failed')
                except RECOVERABLE_RUNTIME_ERRORS as unlink_exc:
                    record_suppressed_failure('queue_retire_token_replace_cleanup_failed', unlink_exc, domain='scheduler')
                continue
            made += 1
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return made


def consume_queue_worker_retire(queue_dir: object) -> object:
    """Return True when this idle child consumed a worker-authority retire token."""
    try:
        d = _queue_retire_dir(queue_dir)
        token_names_list = []
        for listed_name in queue_listdir_names(_safe_queue_listdir(d), context=d):
            decision = retire_token_name_decision(listed_name)
            if not decision.accepted:
                _record_retire_rejection('queue_retire_token_name_rejected', listed_name, decision.reason)
            token_names_list.append(decision.name)
        token_names = tuple(token_names_list)
        for name in sorted(token_name for token_name in token_names if token_name):
            p = d / name
            try:
                _queue_safe_unlink(p, log_context='queue_unlink')
                return retire_token_consume_decision(consumed=True, reason='queue_retire_token_consumed').consumed
            except FileNotFoundError:
                continue
            except RECOVERABLE_RUNTIME_ERRORS as unlink_exc:
                record_suppressed_failure('queue_retire_token_consume_unlink_failed', unlink_exc, domain='scheduler')
                continue
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return retire_token_consume_decision(consumed=False, reason='queue_retire_token_unavailable').consumed
