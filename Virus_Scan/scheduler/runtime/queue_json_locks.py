"""Path-scoped lock ownership for scheduler queue JSON atomic replacement."""
from __future__ import annotations

from pathlib import Path
import os
from threading import RLock


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.runtime.queue_filesystem_common import queue_filesystem_path_text
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS

class QueueJsonReplaceLockOwner:
    def __init__(self) -> None:
        self._owner_lock = RLock()
        self._path_locks: dict[str, RLock] = {}
        self._path_refs: dict[str, int] = {}

    def acquire_for(self, path: object) -> object:
        filesystem_path, reason = queue_filesystem_path_text(path)
        if reason:
            key = "unsupported_scheduler_queue_json_path:" + no_hook_type_name(path)
        else:
            try:
                key = os.path.normcase(str(Path(filesystem_path).resolve()))
            except QUEUE_JSON_EXCEPTIONS:
                key = "unavailable_scheduler_queue_json_path"
        with self._owner_lock:
            lock = self._path_locks.get(key)
            if lock is None:
                lock = RLock()
                self._path_locks[key] = lock
                self._path_refs[key] = 0
            self._path_refs[key] = int(self._path_refs.get(key, 0) or 0) + 1
        lock.acquire()
        return key, lock

    def release_for(self, token: object) -> None:
        key, lock = token
        try:
            lock.release()
        finally:
            with self._owner_lock:
                refs = int(self._path_refs.get(key, 1) or 1) - 1
                if refs <= 0 and self._path_locks.get(key) is lock:
                    self._path_locks.pop(key, None)
                    self._path_refs.pop(key, None)
                else:
                    self._path_refs[key] = refs

QUEUE_JSON_REPLACE_LOCK_OWNER = QueueJsonReplaceLockOwner()
_QUEUE_JSON_REPLACE_LOCK_OWNER = QUEUE_JSON_REPLACE_LOCK_OWNER
