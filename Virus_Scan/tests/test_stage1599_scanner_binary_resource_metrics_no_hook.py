"""Stage1599: binary resource telemetry rejects hookable pid inputs."""
from __future__ import annotations

from Virus_Scan.scanners.binary_resource_metrics import _umige_process_rss_mb


class HostilePid:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __int__")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __str__")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")


def test_stage1599_binary_process_rss_rejects_hookable_pid_without_hooks():
    HostilePid.touched = 0

    assert _umige_process_rss_mb(pid=HostilePid()) == -1.0

    assert HostilePid.touched == 0


def test_stage1599_binary_process_rss_preserves_invalid_exact_text_sentinel():
    assert _umige_process_rss_mb(pid="not-a-pid") == -1.0
