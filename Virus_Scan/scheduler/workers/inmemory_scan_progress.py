from dataclasses import dataclass
from typing import Callable, Optional, Tuple, Type

from Virus_Scan.runtime.api import record_suppressed_failure

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text

_SCAN_PROGRESS_EMIT_FAILED = bool(0)
_SCAN_PROGRESS_FALLBACK_EXCEPTIONS = (OSError, RuntimeError, TypeError, ValueError, KeyError)


def _exception_type_tuple(value: object) -> tuple[type[BaseException], ...]:
    out = [
        item
        for item in no_hook_sequence_items(value)
        if type(item) is type and issubclass(item, BaseException)
    ]
    return tuple(out) or (OSError, RuntimeError, TypeError, ValueError)

@dataclass(frozen=True)
class InMemoryScanProgressFailureEvidence:
    stage: str
    reason: str
    callback_error_type: str
    recorder_failed: bool = False

    def as_context(self) -> dict[str, object]:
        return {
            "inmemory_scan_progress_failed": True,
            "stage": self.stage,
            "reason": self.reason,
            "callback_error_type": self.callback_error_type,
            "recorder_failed": self.recorder_failed,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }


def _record_scan_progress_fallback(evidence: InMemoryScanProgressFailureEvidence, exc: BaseException) -> None:
    try:
        record_suppressed_failure(
            "inmemory_scan_progress_callback_failed",
            exc,
            domain="scheduler",
            context=evidence.as_context(),
        )
    except _SCAN_PROGRESS_FALLBACK_EXCEPTIONS:
        return


def _progress_callback_failure(
    *,
    stage_text: str,
    exc: BaseException,
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    evidence = InMemoryScanProgressFailureEvidence(
        stage=stage_text,
        reason="progress_callback_failed",
        callback_error_type=type(exc).__name__,
    )
    try:
        recorded = record_suppressed("suppressed_exception", exc)
    except _exception_type_tuple(recoverable_exceptions) as recorder_exc:
        fallback = InMemoryScanProgressFailureEvidence(
            stage=stage_text,
            reason="progress_callback_failure_recorder_failed",
            callback_error_type=type(exc).__name__,
            recorder_failed=True,
        )
        _record_scan_progress_fallback(fallback, recorder_exc)
        return _SCAN_PROGRESS_EMIT_FAILED
    if recorded is False:
        fallback = InMemoryScanProgressFailureEvidence(
            stage=stage_text,
            reason="progress_callback_failure_recorder_returned_false",
            callback_error_type=type(exc).__name__,
            recorder_failed=True,
        )
        _record_scan_progress_fallback(fallback, exc)
    else:
        _record_scan_progress_fallback(evidence, exc)
    return _SCAN_PROGRESS_EMIT_FAILED


@dataclass(frozen=True)
class InMemoryScanProgressEmitter:
    """Worker-owned immutable progress emitter for one in-memory file scan."""

    progress_callback: Optional[Callable[[str, int, int], object]]
    cancel_error_type: Type[BaseException]
    recoverable_exceptions: Tuple[Type[BaseException], ...]
    record_suppressed: Callable[[str, BaseException], object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "recoverable_exceptions", _exception_type_tuple(self.recoverable_exceptions))

    def __call__(self, stage: object = "scan", inc: object = 1, bytes_delta: object = 0) -> bool:
        stage_text, stage_reason = scheduler_text(stage, replacement_text="scan")
        if stage_reason != "" or stage_text == "":
            stage_text = "scan"
        increment, increment_reason = scheduler_int(inc, default=1, minimum=1, reason="scan_progress_increment_rejected")
        if increment_reason != "":
            increment = 1
        byte_count, byte_reason = scheduler_int(bytes_delta, default=0, minimum=0, reason="scan_progress_bytes_rejected")
        if byte_reason != "":
            byte_count = 0
        try:
            if callable(self.progress_callback):
                ok = self.progress_callback(stage_text, increment, byte_count)
                if ok is False:
                    raise self.cancel_error_type("cancelled_at_stage:" + stage_text)
        except self.cancel_error_type:
            raise
        except _exception_type_tuple(self.recoverable_exceptions) as exc:
            return _progress_callback_failure(
                stage_text=stage_text,
                exc=exc,
                record_suppressed=self.record_suppressed,
                recoverable_exceptions=self.recoverable_exceptions,
            )
        return True
