"""Canonical scheduler runtime startup-default ownership.

Owns immutable startup decisions for scheduler execution without queue/replay mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_int,
    scheduler_text,
)


@dataclass(frozen=True, slots=True)
class SchedulerStartupSnapshot:
    scheduler_mode: str
    process_requested: bool
    requested_workers: int | None = None
    metadata: Mapping[str, object] = field(default_factory=immutable_mapping)

    def __post_init__(self) -> object:
        scheduler_mode, scheduler_reason = scheduler_text(
            self.scheduler_mode,
            replacement_text="auto",
            unsupported_reason="scheduler_startup_mode_rejected",
        )
        process_requested, process_reason = scheduler_bool(
            self.process_requested,
            default=False,
            reason="scheduler_startup_process_flag_rejected",
        )
        if scheduler_reason or process_reason:
            raise ValueError(scheduler_reason or process_reason)
        if self.requested_workers is not None:
            requested_workers, workers_reason = scheduler_int(
                self.requested_workers,
                default=0,
                minimum=0,
                reason="scheduler_startup_worker_count_rejected",
            )
            if workers_reason:
                raise ValueError(workers_reason)
            object.__setattr__(self, "requested_workers", requested_workers)
        object.__setattr__(self, "scheduler_mode", scheduler_mode)
        object.__setattr__(self, "process_requested", process_requested)
        object.__setattr__(self, "metadata", immutable_mapping(self.metadata))


def make_startup_snapshot(*, scheduler_mode: str, process_requested: bool, requested_workers: int | None = None, metadata: Mapping[str, object] | None = None) -> SchedulerStartupSnapshot:
    return SchedulerStartupSnapshot(
        scheduler_mode,
        process_requested,
        requested_workers,
        immutable_mapping(metadata),
    )


# Scheduler startup default publication belongs to runtime startup ownership.
import threading
from threading import RLock

from Virus_Scan.detection.api.public_contracts import STRICT_FAST_PREFILTER_TAG_MAP
from Virus_Scan.runtime.api import publish_init_values


def init_scheduler_defaults() -> object:
    STRICT_FAST_BENIGN_BYPASS_VERSION = 'strict_fast_benign_bypass_v2_after_prefilter'
    STRICT_FAST_BENIGN_MAX_BYTES = 16384
    STRICT_FAST_BENIGN_EXTENSIONS = {'.rpy', '.py', '.js', '.cs', '.txt', '.md', '.json', '.csv', '.ini', '.cfg', '.yaml', '.yml', '.xml'}
    STRICT_FAST_BENIGN_DENY_TOKENS = {'powershell', 'pwsh', 'cmd.exe', '/c ', 'wscript', 'cscript', 'mshta', 'rundll32', 'reg add', 'currentversion\\run', 'schtasks', 'at.exe', 'wmic', 'winmgmts', 'certutil', 'bitsadmin', 'curl ', 'wget ', 'invoke-webrequest', 'downloadstring', 'iex', 'encodedcommand', '-enc', 'frombase64string', 'base64', 'http://', 'https://', 'ftp://', 'socket', 'connect(', 'subprocess', 'os.system', 'eval(', 'exec(', 'pickle.loads', 'marshal.loads', 'virtualalloc', 'virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'lsass', 'mimikatz', 'amsi', 'etw', 'defender', 'vssadmin', 'shadowcopy', 'startup', 'appdata', '%temp%', 'temp\\', '.exe', '.dll', '.scr', '.ps1', '.bat', '.vbs', '.hta', '.js', 'javascript:', 'shell.application', 'login data', 'cookies.sqlite', 'local state', 'localstorage', 'document.cookie', 'readfilesync', 'discord.com/api/webhooks'}
    STRICT_FAST_BENIGN_BINARY_MAGIC = (b'MZ', b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'Rar!', b"7z\xbc\xaf'\x1c", b'\x1f\x8b', b'BZh', b'\xfd7zXZ', b'\xca\xfe\xba\xbe', b'\x7fELF')
    PICKLE_FAST_ESCALATION_MAX_BYTES = 256 * 1024
    PICKLE_FAST_B64_SAMPLE_MAX = 96 * 1024
    PICKLE_FAST_RENPY_EXTS = {'.rpa', '.rpyc', '.rpyb', '.rpy', '.rpym', '.rpymc'}
    PICKLE_FAST_DANGEROUS_TEXT = ('pickle.loads', 'pickle.load(', 'cPickle.loads'.lower(), 'cPickle.load('.lower(), '__reduce__', '__reduce_ex__', 'pickletools', 'persistent_load', 'find_class', 'stack_global', 'opcode: global', 'opcode: reduce', 'cos\nsystem', 'posix\nsystem', 'nt\nsystem', 'builtins\neval', 'builtins\nexec', 'subprocess.popen', 'subprocess.run', 'os.system', 'eval(', 'exec(', 'compile(', 'marshal.loads', 'base64.b64decode', 'zlib.decompress', 'gzip.decompress')
    PICKLE_FAST_EXEC_TEXT = ('subprocess', 'popen(', 'os.system', 'cmd.exe', 'powershell', 'createprocess', 'eval(', 'exec(', 'compile(', 'marshal.loads', 'urlopen', 'urlretrieve', 'requests.get', 'http://', 'https://', 'appdata', '%temp%', 'renpy.loader')
    UMIGE_SCAN_INTEGRITY = {}
    _UMIGE_CPU_SAMPLE_STATE = {'last': None}
    _UMIGE_EWMA_STATE = {}
    HYBRID_QUEUE_STATE_CACHE = {}
    HYBRID_QUEUE_STATE_LOCK = RLock()
    INMEMORY_SCHEDULER_VERSION = 2
    HB_RUNNING = 1 << 0
    HB_CANCEL_REQUEST = 1 << 1
    HB_POISONED = 1 << 2
    HB_STALLED = 1 << 3
    HB_FORCE_RETIRE = 1 << 4
    _UMIGE_PROGRESS_LOCAL = threading.local()
    _UMIGE_DYNAMIC_STAGE_COST = {}
    publish_init_values((
        ('STRICT_FAST_BENIGN_BYPASS_VERSION', STRICT_FAST_BENIGN_BYPASS_VERSION),
        ('STRICT_FAST_BENIGN_MAX_BYTES', STRICT_FAST_BENIGN_MAX_BYTES),
        ('STRICT_FAST_BENIGN_EXTENSIONS', STRICT_FAST_BENIGN_EXTENSIONS),
        ('STRICT_FAST_BENIGN_DENY_TOKENS', STRICT_FAST_BENIGN_DENY_TOKENS),
        ('STRICT_FAST_BENIGN_BINARY_MAGIC', STRICT_FAST_BENIGN_BINARY_MAGIC),
        ('PICKLE_FAST_ESCALATION_MAX_BYTES', PICKLE_FAST_ESCALATION_MAX_BYTES),
        ('PICKLE_FAST_B64_SAMPLE_MAX', PICKLE_FAST_B64_SAMPLE_MAX),
        ('PICKLE_FAST_RENPY_EXTS', PICKLE_FAST_RENPY_EXTS),
        ('PICKLE_FAST_DANGEROUS_TEXT', PICKLE_FAST_DANGEROUS_TEXT),
        ('PICKLE_FAST_EXEC_TEXT', PICKLE_FAST_EXEC_TEXT),
        ('STRICT_FAST_PREFILTER_TAG_MAP', STRICT_FAST_PREFILTER_TAG_MAP),
        ('UMIGE_SCAN_INTEGRITY', UMIGE_SCAN_INTEGRITY),
        ('_UMIGE_CPU_SAMPLE_STATE', _UMIGE_CPU_SAMPLE_STATE),
        ('_UMIGE_EWMA_STATE', _UMIGE_EWMA_STATE),
        ('HYBRID_QUEUE_STATE_CACHE', HYBRID_QUEUE_STATE_CACHE),
        ('HYBRID_QUEUE_STATE_LOCK', HYBRID_QUEUE_STATE_LOCK),
        ('INMEMORY_SCHEDULER_VERSION', INMEMORY_SCHEDULER_VERSION),
        ('HB_RUNNING', HB_RUNNING),
        ('HB_CANCEL_REQUEST', HB_CANCEL_REQUEST),
        ('HB_POISONED', HB_POISONED),
        ('HB_STALLED', HB_STALLED),
        ('HB_FORCE_RETIRE', HB_FORCE_RETIRE),
        ('_UMIGE_PROGRESS_LOCAL', _UMIGE_PROGRESS_LOCAL),
        ('_UMIGE_DYNAMIC_STAGE_COST', _UMIGE_DYNAMIC_STAGE_COST),
    ))
    return publish_init_values(())

__all__ = ("SchedulerStartupSnapshot", "init_scheduler_defaults", "make_startup_snapshot")
