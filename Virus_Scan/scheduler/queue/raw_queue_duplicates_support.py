"""Support helpers for raw queue duplicate live-claim guard."""
from __future__ import annotations

from pathlib import Path
from Virus_Scan.scheduler.queue.raw_queue_duplicate_evidence import (
    raw_queue_duplicate_name_text,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import (
    raw_queue_report_path_extra as _report_path,
)

_DUPLICATE_LIVE_GUARD_BLOCKED = False


def _collect_duplicate_live_guard_matches(
    *,
    queue_dir: object,
    current: Path,
    ident: str,
    safe_listdir: object,
    is_job_json_name: object,
    read_json: object,
    merge_claim_meta: object,
    job_dirs: object,
    job_identity: object,
    report: object,
    list_queue_names: object,
    job_mapping: object,
) -> list[tuple[str, Path, object]] | None:
    pending, active, done, failed = job_dirs(queue_dir)
    matches: list[tuple[str, Path, object]] = []
    for state, d in (("done", done), ("active", active), ("pending", pending), ("failed", failed)):
        names = []
        for raw_name in list_queue_names(safe_listdir, d):
            name = raw_queue_duplicate_name_text(raw_name).text
            if name == "":
                continue
            names.append(name)
        for name in sorted(names):
            if not is_job_json_name(name):
                continue
            p = d / name
            try:
                same_claim = p.resolve() == current
            except (OSError, RuntimeError, ValueError) as exc:
                report(
                    "queue_duplicate_live_guard_resolve_failed",
                    exc,
                    fatal=True,
                    extra=_report_path({"identity": ident, "state": state}, "path", p),
                )
                return None
            if same_claim:
                continue
            other_raw = read_json(p, default=None)
            other_decision = job_mapping(other_raw)
            other = other_decision.mapping
            if not other_decision.accepted or not other:
                report(
                    "queue_duplicate_live_guard_read_failed",
                    ValueError("queue job was not a JSON object"),
                    fatal=True,
                    extra=_report_path({"identity": ident, "state": state}, "path", p),
                )
                return None
            if state == "active":
                merged_decision = job_mapping(merge_claim_meta(p, other))
                other = merged_decision.mapping
                if not merged_decision.accepted or not other:
                    report(
                        "queue_duplicate_live_guard_read_failed",
                        ValueError(merged_decision.reason),
                        fatal=True,
                        extra=_report_path({"identity": ident, "state": state}, "path", p),
                    )
                    return None
            if job_identity(other, name) == ident:
                matches.append((state, p, other))
    return matches


def _quarantine_duplicate_live_guard_matches(
    *,
    claim_path: object,
    ident: str,
    current_job: object,
    matches: list[tuple[str, Path, object]],
    quarantine_job: object,
    report: object,
) -> bool:
    for state, _p, _other in matches:
        if state in ("done", "active"):
            quarantined = quarantine_job(
                claim_path,
                reason="duplicate_claim_blocked_by_%s" % state,
                job=current_job,
                identity=ident,
            )
            if quarantined is not True:
                report(
                    "queue_duplicate_live_guard_quarantine_current_failed",
                    RuntimeError("duplicate claim quarantine failed"),
                    fatal=True,
                    extra={"identity": ident, "state": state},
                )
            return _DUPLICATE_LIVE_GUARD_BLOCKED
    for state, p, other in matches:
        quarantined = quarantine_job(p, reason="duplicate_removed_by_active_claim", job=other, identity=ident)
        if quarantined is not True:
            report(
                "queue_duplicate_live_guard_quarantine_stale_failed",
                RuntimeError("stale duplicate quarantine failed"),
                fatal=True,
                extra=_report_path({"identity": ident, "state": state}, "path", p),
            )
            return _DUPLICATE_LIVE_GUARD_BLOCKED
    return True


__all__ = (
    "_collect_duplicate_live_guard_matches",
    "_quarantine_duplicate_live_guard_matches",
    "_report_path",
)
